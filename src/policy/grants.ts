import { isUnknown } from '../core/model.js';
import { parsePolicy, type Statement } from './iam.js';

/** One Allow or Deny of an action on a resource, as a readable key. */
export interface Grant {
  effect: string;
  action: string;
  resource: string;
}

const list = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

export function displayResource(r: unknown): string {
  if (typeof r === 'string') return r;
  if (isUnknown(r)) {
    if (r.pattern === '{?}' && r.refs.length) return r.refs.join(', ');
    if (r.pattern !== undefined && r.refs.length && r.pattern.startsWith('{?}')) return r.refs.join(', ') + r.pattern.slice(3);
    if (r.pattern !== undefined) return r.pattern.replaceAll('{?}', '…');
    return '(unknown)';
  }
  return JSON.stringify(r);
}

export function grantsOf(policy: unknown): Grant[] | undefined {
  const parsed = parsePolicy(policy);
  if (parsed.kind !== 'ok') return undefined;
  return parsed.statements.flatMap((st: Statement) => {
    const effect = String(st.Effect ?? 'Allow');
    const actions = list(st.Action ?? st.NotAction).map((a) => (typeof a === 'string' ? a : '(unknown)'));
    const resources = list(st.Resource ?? st.NotResource).map(displayResource);
    return actions.flatMap((action) => resources.map((resource) => ({ effect, action, resource })));
  });
}

export interface GrantDiff {
  added: Grant[];
  removed: Grant[];
}

export function diffGrants(before: unknown, after: unknown): GrantDiff | undefined {
  const b = grantsOf(before);
  const a = grantsOf(after);
  if (!b || !a) return undefined;
  const key = (g: Grant) => `${g.effect}|${g.action}|${g.resource}`;
  const bk = new Set(b.map(key));
  const ak = new Set(a.map(key));
  return { added: dedupe(a.filter((g) => !bk.has(key(g)))), removed: dedupe(b.filter((g) => !ak.has(key(g)))) };
}

function dedupe(gs: Grant[]): Grant[] {
  const seen = new Set<string>();
  return gs.filter((g) => {
    const k = `${g.effect}|${g.action}|${g.resource}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

/** "s3:GetObject, s3:PutObject on arn:...:bucket/*" grouped by resource. */
export function describeGrants(gs: Grant[], max = 4): string {
  const byResource = new Map<string, string[]>();
  for (const g of gs) byResource.set(`${g.effect === 'Deny' ? 'deny ' : ''}${g.resource}`, [...(byResource.get(`${g.effect === 'Deny' ? 'deny ' : ''}${g.resource}`) ?? []), g.action]);
  const parts = [...byResource.entries()].map(([r, actions]) => `${[...new Set(actions)].join(', ')} on ${r}`);
  return parts.slice(0, max).join('; ') + (parts.length > max ? `; and ${parts.length - max} more` : '');
}
