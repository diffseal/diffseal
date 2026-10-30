import { isUnknown } from '../core/model.js';
import { stableKey } from '../hcl/eval.js';
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

/**
 * True when a glob (IAM `*` and `?`) matches everything `inner` can match. Exact for a literal `inner`,
 * and for an `outer` whose only wildcard is a trailing `*`; anything else is answered false.
 */
function covers(outer: string, inner: string, caseless: boolean): boolean {
  const o = caseless ? outer.toLowerCase() : outer;
  const i = caseless ? inner.toLowerCase() : inner;
  if (o === i || o === '*') return true;
  if (!/[*?]/.test(i)) return new RegExp('^' + o.split('*').map((x) => x.split('?').map((y) => y.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('.')).join('.*') + '$', 's').test(i);
  const prefix = o.slice(0, -1);
  return o.endsWith('*') && !/[*?]/.test(prefix) && i.startsWith(prefix);
}

/**
 * True when a policy update grants nothing the previous version did not: every Allowed action and
 * resource of the new version is covered by an Allow of the old one with no condition (or the same
 * condition), and every Deny of the old version is still there. NotAction, NotResource, NotPrincipal and
 * values not known statically give false: the answer must be certain.
 */
export function grantsWithin(before: unknown, after: unknown): boolean {
  const b = parsePolicy(before);
  const a = parsePolicy(after);
  if (b.kind !== 'ok' || a.kind !== 'ok') return false;
  const plain = (st: Statement) => st.NotAction === undefined && st.NotResource === undefined && st.NotPrincipal === undefined;
  if (![...b.statements, ...a.statements].every(plain)) return false;
  // A value partly known at plan time stands for every value its pattern allows: each unknown part is a
  // wildcard. That only widens the new grants, so a containment found with it holds for the real value.
  const strings = (v: unknown, widen: boolean): string[] | undefined => {
    const xs = list(v).map((x) => (typeof x === 'string' ? x : widen && isUnknown(x) && x.pattern?.startsWith('arn:') ? x.pattern.replaceAll('{?}', '*') : undefined));
    return xs.every((x) => x !== undefined) ? (xs as string[]) : undefined;
  };
  const allow = (st: Statement) => String(st.Effect ?? 'Allow') === 'Allow';
  const denyKey = (st: Statement) => stableKey([st.Action ?? null, st.Resource ?? null, st.Condition ?? null, st.Principal ?? null]);
  const kept = new Set(a.statements.filter((st) => !allow(st)).map(denyKey));
  if (b.statements.some((st) => !allow(st) && !kept.has(denyKey(st)))) return false;
  const old = b.statements.filter(allow).map((st) => ({ actions: strings(st.Action, false), resources: strings(st.Resource, false), condition: st.Condition }));
  for (const st of a.statements.filter(allow)) {
    const actions = strings(st.Action, false);
    const resources = strings(st.Resource, true);
    if (!actions || !resources) return false;
    for (const action of actions) {
      for (const resource of resources) {
        const ok = old.some((o) =>
          o.actions && o.resources &&
          (o.condition === undefined || stableKey(o.condition) === stableKey(st.Condition)) &&
          o.actions.some((x) => covers(x, action, true)) &&
          o.resources.some((x) => covers(x, resource, false)));
        if (!ok) return false;
      }
    }
  }
  return true;
}
