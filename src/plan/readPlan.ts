import {
  Redacted,
  Unknown,
  configAddress,
  isUnknown,
  type Action,
  type Attrs,
  type ResourceChange,
} from '../core/model.js';
import { knownConfiguration } from '../core/configuration.js';
import { LazyMap, evaluate, redact, type EvalScope } from '../hcl/eval.js';
import { parseHcl } from '../hcl/parser.js';

/** The parts of `terraform show -json <planfile>` Diffseal reads. */
export interface PlanJson {
  format_version?: string;
  terraform_version?: string;
  variables?: Record<string, { value: unknown }>;
  resource_changes?: PlanResourceChange[];
  prior_state?: { values?: { root_module?: StateModule } };
  configuration?: { root_module?: ConfigModule };
}

interface PlanResourceChange {
  address: string;
  module_address?: string;
  mode?: 'managed' | 'data';
  type: string;
  name: string;
  previous_address?: string;
  action_reason?: string;
  change: {
    actions: string[];
    before: unknown;
    after: unknown;
    after_unknown?: unknown;
    before_sensitive?: unknown;
    after_sensitive?: unknown;
    replace_paths?: Array<Array<string | number>>;
    importing?: unknown;
  };
}

interface StateModule {
  resources?: Array<{ address: string; mode: string; type: string; name: string; values?: Attrs; sensitive_values?: unknown }>;
  child_modules?: StateModule[];
}

interface ConfigModule {
  resources?: Array<{ address: string; provider_config_key?: string; expressions?: Record<string, unknown> }>;
  module_calls?: Record<string, { expressions?: Record<string, unknown>; module?: ConfigModule }>;
  outputs?: Record<string, { expression?: unknown }>;
}

interface ConfiguredExpressions {
  expressions: Record<string, unknown>;
  scope: EvalScope;
}

export function readPlan(input: unknown): ResourceChange[] {
  if (!input || typeof input !== 'object') {
    throw new Error('Plan JSON must be an object produced by `terraform show -json <planfile>`.');
  }
  const plan = input as PlanJson;
  if (!Array.isArray(plan.resource_changes) && !plan.prior_state) {
    throw new Error('Plan JSON has no resource_changes. Pass the output of `terraform show -json <planfile>`, not a state file.');
  }

  const providers = new Map<string, string>();
  const configuredPaths = new Map<string, string[]>();
  const configurations = new Map<string, ConfiguredExpressions>();
  const references = collectReferences(plan, providers, configuredPaths, configurations);
  const changes: ResourceChange[] = [];
  const seen = new Set<string>();

  for (const rc of plan.resource_changes ?? []) {
    const actions = rc.change.actions;
    const action = mapAction(actions, rc);
    const after = rc.change.after === null || rc.change.after === undefined
      ? null
      : (overlay(overlay(rc.change.after, rc.change.after_unknown, unknownMarker), rc.change.after_sensitive, redactMarker) as Attrs);
    const before = rc.change.before === null || rc.change.before === undefined
      ? null
      : (overlay(rc.change.before, rc.change.before_sensitive, redactMarker) as Attrs);
    const config = configurations.get(configAddress(rc.address));

    changes.push({
      address: rc.address,
      type: rc.type,
      name: rc.name,
      mode: rc.mode ?? 'managed',
      moduleAddress: rc.module_address,
      ...(providers.has(configAddress(rc.address)) ? { providerAddress: providers.get(configAddress(rc.address)) } : {}),
      action,
      before,
      after,
      replacePaths: rc.change.replace_paths?.map((p) => p.map(String)),
      replaceOrder: action === 'replace' ? (actions[0] === 'create' ? 'create-first' : 'delete-first') : undefined,
      actionReason: rc.action_reason,
      references: references.get(configAddress(rc.address)) ?? {},
      configuredPaths: configuredPaths.get(configAddress(rc.address)) ?? [],
      configuredAfter: overlay(configuredValues(after ?? {}, config?.expressions ?? {}, config?.scope ?? { root: () => undefined }),
        rc.change.after_sensitive, (value) => value === undefined ? undefined : redactMarker(value)) as Attrs,
      previousAddress: rc.previous_address,
      confidence: 'proven',
    });
    seen.add(rc.address);
  }

  // Data sources read during planning only appear in prior_state. Rules need them as context,
  // e.g. an aws_iam_role_policy whose policy is data.aws_iam_policy_document.x.json.
  for (const res of walkState(plan.prior_state?.values?.root_module)) {
    if (res.mode !== 'data' || seen.has(res.address)) continue;
    // State keeps sensitive values in clear and marks them in sensitive_values, like a plan's masks.
    const values = overlay(res.values ?? {}, res.sensitive_values, redactMarker) as Attrs;
    changes.push({
      address: res.address,
      type: res.type,
      name: res.name,
      mode: 'data',
      action: 'no-op',
      before: values,
      after: values,
      references: references.get(configAddress(res.address)) ?? {},
      confidence: 'proven',
    });
  }

  return changes;
}

/** Resolve configured expressions from literals or planned expression values, never computed-only fields. */
function configuredValues(value: unknown, expression: unknown, scope: EvalScope): unknown {
  if (!expression || typeof expression !== 'object') return undefined;
  if ('constant_value' in expression) return expression.constant_value ?? undefined;
  // Never let a provider-populated result erase a null, unknown or computed dependency.
  if ('references' in expression) {
    const inputs = expressionInputs(expression, scope);
    return inputs.length && inputs.every(knownConfiguration) ? value ?? undefined
      : value == null ? undefined : new Unknown('configuration depends on a null, unknown or computed value');
  }
  if (isUnknown(value) || value instanceof Redacted) return value;
  if (Array.isArray(expression)) return expression.map((expr, i) => configuredValues(Array.isArray(value) ? value[i] : undefined, expr, scope));
  return Object.fromEntries(Object.entries(expression).map(([key, expr]) => [key,
    configuredValues(value && typeof value === 'object' ? (value as Attrs)[key] : undefined, expr, scope),
  ]));
}

function expressionInputs(expression: object, scope: EvalScope): unknown[] {
  if (!('references' in expression) || !Array.isArray(expression.references)) return [];
  const refs = expression.references.filter((ref): ref is string => typeof ref === 'string');
  // Terraform includes both a traversal and its containing object. Only read the most specific
  // traversal, so a nullable sibling does not invalidate a known attribute.
  return refs.filter((ref) => !refs.some((other) => other.startsWith(`${ref}.`) || other.startsWith(`${ref}[`))).map((ref) => {
    const parsed = parseHcl(`value = ${ref}\n`);
    return parsed.diagnostics.length || !parsed.body.attributes[0] ? undefined : evaluate(parsed.body.attributes[0].expr, scope);
  });
}

/** Module arguments/outputs have no planned value of their own; carry their dependency evidence. */
function expressionEvidence(expression: unknown, scope: EvalScope): unknown {
  if (!expression || typeof expression !== 'object') return undefined;
  if ('constant_value' in expression) return expression.constant_value;
  const inputs = expressionInputs(expression, scope);
  if (!inputs.length) return undefined;
  return inputs.length === 1 ? inputs[0] : inputs.every(knownConfiguration) ? inputs : new Unknown('expression has a null or unknown dependency');
}

function mapAction(actions: string[], rc: PlanResourceChange): Action {
  if (rc.change.importing && !actions.includes('delete')) return actions.includes('update') ? 'update' : 'import';
  if (actions.includes('create') && actions.includes('delete')) return 'replace';
  if (actions.includes('delete')) return 'delete';
  if (actions.includes('create')) return 'create';
  if (actions.includes('update')) return 'update';
  if (actions.includes('read')) return 'read';
  if (actions.includes('forget')) return 'forget';
  if (rc.previous_address && rc.previous_address !== rc.address) return 'move';
  return 'no-op';
}

const unknownMarker = () => new Unknown('known after apply');
// Terraform's plan JSON holds sensitive values in clear; keep them for rules, hidden from every report.
const redactMarker = (value: unknown) => (value === undefined || value === null || isUnknown(value) ? (value ?? new Redacted()) : redact(value));

/**
 * Apply a Terraform mask (after_unknown / *_sensitive) to a value. A `true` leaf replaces the value
 * with the marker; masks may name keys absent from the value (unknown values are omitted from `after`).
 */
function overlay(value: unknown, mask: unknown, marker: (value: unknown) => unknown): unknown {
  if (mask === true) return marker(value);
  if (!mask || typeof mask !== 'object') return value;
  if (Array.isArray(mask)) {
    const arr = Array.isArray(value) ? [...value] : [];
    mask.forEach((m, i) => {
      if (m === false || m === undefined) return;
      arr[i] = overlay(arr[i], m, marker);
    });
    return arr;
  }
  const obj: Attrs = value && typeof value === 'object' && !Array.isArray(value) ? { ...(value as Attrs) } : {};
  for (const [k, m] of Object.entries(mask as Attrs)) {
    if (m === false) continue;
    obj[k] = overlay(obj[k], m, marker);
  }
  return obj;
}

function* walkState(mod: StateModule | undefined): Generator<NonNullable<StateModule['resources']>[number]> {
  if (!mod) return;
  for (const r of mod.resources ?? []) yield r;
  for (const child of mod.child_modules ?? []) yield* walkState(child);
}

/** configAddress -> attribute -> referenced resource addresses (module-qualified). */
function collectReferences(plan: PlanJson, providers: Map<string, string>, configuredPaths: Map<string, string[]>, configurations: Map<string, ConfiguredExpressions>): Map<string, Record<string, string[]>> {
  const out = new Map<string, Record<string, string[]>>();
  const visit = (mod: ConfigModule | undefined, prefix: string, inputs: Map<string, () => unknown>): EvalScope => {
    const children = new Map<string, EvalScope>();
    const roots = new Map<string, unknown>();
    const variables = new LazyMap(inputs, () => new Unknown('variable value unavailable'));
    const resources = new LazyMap(new Map((mod?.resources ?? []).map((res) => [res.address, () => {
      const changes = plan.resource_changes?.filter((rc) => configAddress(rc.address) === prefix + res.address) ?? [];
      if (changes.length !== 1) return new Unknown('resource instance value unavailable');
      const rc = changes[0];
      const after = overlay(overlay(rc.change.after, rc.change.after_unknown, unknownMarker), rc.change.after_sensitive, redactMarker);
      return configuredValues(after, res.expressions ?? {}, scope);
    }])));
    const root = (name: string): unknown => {
      if (name === 'var') return variables;
      if (name === 'module') return new LazyMap(new Map(Object.entries(mod?.module_calls ?? {}).map(([name, call]) => [name, () =>
        new LazyMap(new Map(Object.entries(call.module?.outputs ?? {}).map(([output, config]) => [output, () =>
          expressionEvidence(config.expression, children.get(name)!),
        ]))),
      ])));
      // Only a configured argument can attest another argument; computed resource fields cannot.
      const data = name === 'data';
      const byType = (type: string) => new LazyMap(new Map((mod?.resources ?? [])
        .filter((r) => r.address.startsWith(`${data ? 'data.' : ''}${type}.`))
        .map((r) => [r.address.split('.').at(-1)!, () => resources.getAttr(r.address)])));
      return data ? new LazyMap(new Map([...new Set((mod?.resources ?? []).filter((r) => r.address.startsWith('data.')).map((r) => r.address.split('.')[1]))]
        .map((type) => [type, () => byType(type)]))) : byType(name);
    };
    const scope: EvalScope = { root: (name) => {
      if (!roots.has(name)) roots.set(name, root(name));
      return roots.get(name);
    } };
    for (const [name, call] of Object.entries(mod?.module_calls ?? {})) {
      children.set(name, visit(call.module, `${prefix}module.${name}.`, new Map(Object.entries(call.expressions ?? {})
        .map(([arg, expr]) => [arg, () => expressionEvidence(expr, scope)]))));
    }
    if (!mod) return scope;
    for (const res of mod.resources ?? []) {
      if (res.provider_config_key) providers.set(prefix + res.address, res.provider_config_key);
      configurations.set(prefix + res.address, { expressions: res.expressions ?? {}, scope });
      const paths: string[] = [];
      const visitLiteral = (value: unknown, path: string) => {
        if (value == null) return;
        if (typeof value === 'object' && (Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype)) {
          for (const [key, nested] of Object.entries(value)) visitLiteral(nested, `${path}.${key}`);
        } else paths.push(path);
      };
      const visitExpression = (expr: unknown, path: string) => {
        if (!expr || typeof expr !== 'object') return;
        if ('constant_value' in expr) { visitLiteral(expr.constant_value, path); return; }
        if ('references' in expr) { paths.push(path); return; }
        for (const [key, value] of Object.entries(expr)) visitExpression(value, `${path}.${key}`);
      };
      for (const [attr, expr] of Object.entries(res.expressions ?? {})) visitExpression(expr, attr);
      configuredPaths.set(prefix + res.address, paths);
      const byAttr: Record<string, string[]> = {};
      for (const [attr, expr] of Object.entries(res.expressions ?? {})) {
        const refs = new Set<string>();
        collectRefs(expr, refs);
        const resolved = [...refs].map((r) => normalizeReference(r, prefix)).filter((r): r is string => Boolean(r));
        if (resolved.length) byAttr[attr] = [...new Set(resolved)];
      }
      out.set(prefix + res.address, byAttr);
    }
    return scope;
  };
  visit(plan.configuration?.root_module, '', new Map(Object.entries(plan.variables ?? {}).map(([name, v]) => [name, () => v.value])));
  return out;
}

function collectRefs(expr: unknown, into: Set<string>) {
  if (!expr || typeof expr !== 'object') return;
  if (Array.isArray(expr)) {
    for (const e of expr) collectRefs(e, into);
    return;
  }
  const o = expr as Record<string, unknown>;
  if (Array.isArray(o.references)) {
    for (const r of o.references) if (typeof r === 'string') into.add(r);
  }
  for (const [k, v] of Object.entries(o)) {
    if (k !== 'references') collectRefs(v, into);
  }
}

const NON_RESOURCE_ROOTS = new Set(['var', 'local', 'each', 'count', 'path', 'terraform', 'self']);

/** `aws_s3_bucket.b[0].id` within module prefix `module.m.` -> `module.m.aws_s3_bucket.b`. */
export function normalizeReference(ref: string, prefix = ''): string | undefined {
  const parts = configAddress(ref).split('.');
  if (NON_RESOURCE_ROOTS.has(parts[0])) return undefined;
  if (parts[0] === 'data') return parts.length >= 3 ? prefix + parts.slice(0, 3).join('.') : undefined;
  if (parts[0] === 'module') return parts.length >= 2 ? prefix + parts.slice(0, 2).join('.') : undefined;
  return parts.length >= 2 ? prefix + parts.slice(0, 2).join('.') : undefined;
}
