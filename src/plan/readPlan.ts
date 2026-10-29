import {
  Redacted,
  Unknown,
  configAddress,
  isUnknown,
  type Action,
  type Attrs,
  type ResourceChange,
} from '../core/model.js';
import { redact } from '../hcl/eval.js';

/** The parts of `terraform show -json <planfile>` Diffseal reads. */
export interface PlanJson {
  format_version?: string;
  terraform_version?: string;
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
  module_calls?: Record<string, { module?: ConfigModule }>;
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
  const configurations = new Map<string, Record<string, unknown>>();
  const references = collectReferences(plan.configuration?.root_module, providers, configuredPaths, configurations);
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
      configuredAfter: overlay(configuredValues(after ?? {}, configurations.get(configAddress(rc.address)) ?? {}), rc.change.after_sensitive, redactMarker) as Attrs,
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
function configuredValues(value: unknown, expression: unknown): unknown {
  if (!expression || typeof expression !== 'object') return undefined;
  if ('constant_value' in expression) return expression.constant_value;
  if ('references' in expression) return value;
  if (isUnknown(value) || value instanceof Redacted) return value;
  if (Array.isArray(expression)) return expression.map((expr, i) => configuredValues(Array.isArray(value) ? value[i] : undefined, expr));
  return Object.fromEntries(Object.entries(expression).map(([key, expr]) => [key,
    configuredValues(value && typeof value === 'object' ? (value as Attrs)[key] : undefined, expr),
  ]));
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
function collectReferences(root: ConfigModule | undefined, providers: Map<string, string>, configuredPaths: Map<string, string[]>, configurations: Map<string, Record<string, unknown>>): Map<string, Record<string, string[]>> {
  const out = new Map<string, Record<string, string[]>>();
  const visit = (mod: ConfigModule | undefined, prefix: string) => {
    if (!mod) return;
    for (const res of mod.resources ?? []) {
      if (res.provider_config_key) providers.set(prefix + res.address, res.provider_config_key);
      configurations.set(prefix + res.address, res.expressions ?? {});
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
    for (const [name, call] of Object.entries(mod.module_calls ?? {})) {
      visit(call.module, `${prefix}module.${name}.`);
    }
  };
  visit(root, '');
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
