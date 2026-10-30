import { Unknown, isRedacted, isUnknown, type Attrs } from '../core/model.js';
import { redact, stableKey } from '../hcl/eval.js';

/**
 * The value inside a sensitive whole (a `sensitive` env map, or container definitions built with
 * jsonencode from a sensitive value), and how to wrap each value read from it: which parts were
 * secret is no longer known, so every value stays sensitive. Names are not secret.
 */
function opened(v: unknown): { value: unknown; wrap: (x: unknown) => unknown } | undefined {
  if (!isRedacted(v)) return { value: v, wrap: (x) => x };
  const r = v.revealed;
  return r ? { value: r.value, wrap: (x) => (x === undefined || x === null ? x : redact(x)) } : undefined;
}

/** Environment variables a compute resource hands to its code: name -> value expression result. */
function environmentOf(type: string, attrs: Attrs | null | undefined): Record<string, unknown> | undefined {
  if (!attrs) return undefined;
  if (type === 'aws_lambda_function') {
    const env = first(attrs.environment);
    const o = opened(env?.variables);
    const vars = o?.value;
    if (!o || !vars || typeof vars !== 'object' || isUnknown(vars) || Array.isArray(vars)) return undefined;
    return Object.fromEntries(Object.entries(vars as Record<string, unknown>).map(([k, x]) => [k, o.wrap(x)]));
  }
  if (type === 'aws_ecs_task_definition') {
    const o = opened(attrs.container_definitions);
    if (!o) return undefined;
    let defs = o.value;
    if (typeof defs === 'string') {
      try {
        defs = JSON.parse(defs);
      } catch {
        return undefined;
      }
    }
    if (!Array.isArray(defs)) return undefined;
    const out: Record<string, unknown> = {};
    for (const c of defs as Attrs[]) {
      for (const e of (Array.isArray(c?.environment) ? c.environment : []) as Attrs[]) if (typeof e?.name === 'string') out[e.name] = o.wrap(e.value);
      // ECS puts the secret's value in the variable, not the valueFrom ARN. The value is unknown; its
      // identity follows the ARN, so pointing at another secret is still a change.
      for (const s of (Array.isArray(c?.secrets) ? c.secrets : []) as Attrs[]) {
        if (typeof s?.name === 'string') out[s.name] = new Unknown(`the value of secret ${stableKey(s.valueFrom)}`);
      }
    }
    return out;
  }
  return undefined;
}

function first(v: unknown): Attrs | undefined {
  if (Array.isArray(v)) return v[0] as Attrs | undefined;
  return v && typeof v === 'object' && !isUnknown(v) ? (v as Attrs) : undefined;
}

export interface EnvDiff {
  added: string[];
  removed: string[];
  changed: string[];
}

export function diffEnvironment(type: string, before: Attrs | null, after: Attrs | null): EnvDiff | undefined {
  const b = environmentOf(type, before);
  const a = environmentOf(type, after);
  if (!b && !a) return undefined;
  const bk = b ?? {};
  const ak = a ?? {};
  return {
    added: Object.keys(ak).filter((k) => !(k in bk)).sort(),
    removed: Object.keys(bk).filter((k) => !(k in ak)).sort(),
    changed: Object.keys(ak).filter((k) => k in bk && stableKey(ak[k]) !== stableKey(bk[k])).sort(),
  };
}

export function describeEnvDiff(d: EnvDiff): string {
  const parts: string[] = [];
  if (d.added.length) parts.push(`adds env ${d.added.join(', ')}`);
  if (d.removed.length) parts.push(`removes env ${d.removed.join(', ')}`);
  if (d.changed.length) parts.push(`changes env ${d.changed.join(', ')}`);
  return parts.join('; ');
}
