import { isUnknown, reveal } from '../core/model.js';
import { containsUnknown, stableKey } from '../hcl/eval.js';
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

/**
 * The grants a policy update adds and removes. An Allow of the old version counts as removed only when
 * the new version does not certainly still allow it: `dynamodb:*` on `*` keeps `dynamodb:GetItem` on a
 * table.
 */
export function diffGrants(before: unknown, after: unknown): GrantDiff | undefined {
  const b = grantsOf(before);
  const a = grantsOf(after);
  if (!b || !a) return undefined;
  const key = (g: Grant) => `${g.effect}|${g.action}|${g.resource}`;
  const bk = new Set(b.map(key));
  const ak = new Set(a.map(key));
  const kept = stillAllowed(before, after);
  return { added: dedupe(a.filter((g) => !bk.has(key(g)))), removed: dedupe(b.filter((g) => !ak.has(key(g)) && !kept(g))) };
}

/** An action or resource as a glob that matches at least every value it can take; `*` when nothing is known. */
function widened(v: unknown): string {
  if (typeof v === 'string') return v.replace(/\$\{[^}]*\}/g, '*');
  if (isUnknown(v) && v.pattern?.startsWith('arn:')) return v.pattern.replaceAll('{?}', '*');
  return '*';
}

/** False only when no text can match both globs: their literal heads or tails differ. */
function mayOverlap(x: string, y: string, caseless: boolean): boolean {
  const [p, q] = caseless ? [x.toLowerCase(), y.toLowerCase()] : [x, y];
  const wild = /[*?]/;
  if (!wild.test(p) && !wild.test(q)) return p === q;
  if (!wild.test(q)) return globMatch(p, q);
  if (!wild.test(p)) return globMatch(q, p);
  const head = (s: string) => s.slice(0, s.search(wild));
  const tail = (s: string) => s.slice(Math.max(s.lastIndexOf('*'), s.lastIndexOf('?')) + 1);
  const [hp, hq, tp, tq] = [head(p), head(q), tail(p), tail(q)];
  return (hp.startsWith(hq) || hq.startsWith(hp)) && (tp.endsWith(tq) || tq.endsWith(tp));
}

/**
 * A test for an Allow of the old version: true when the new version certainly still allows it. That needs
 * a new Allow with no condition whose action and resource cover it, and no new or changed Deny that may
 * match it. Anything not certain answers false, so the grant is reported as revoked.
 */
function stillAllowed(before: unknown, after: unknown): (g: Grant) => boolean {
  const b = parsePolicy(before);
  const a = parsePolicy(after);
  if (b.kind !== 'ok' || a.kind !== 'ok' || policyVersion(before) !== policyVersion(after)) return () => false;
  const plain = (st: Statement) => st.NotAction === undefined && st.NotResource === undefined && st.NotPrincipal === undefined;
  // The old grants that come from a plain Allow, with what each action and resource can match.
  // A NotAction or NotResource grant shown with the same text is never counted as kept.
  const old = new Map<string, { action: string; resource: string } | undefined>();
  for (const st of b.statements) {
    if (st.Effect !== undefined && st.Effect !== 'Allow') continue;
    for (const action of list(st.Action ?? st.NotAction))
      for (const resource of list(st.Resource ?? st.NotResource)) {
        const k = `${typeof action === 'string' ? action : '(unknown)'}|${displayResource(resource)}`;
        old.set(k, plain(st) && (!old.has(k) || old.get(k)) ? { action: widened(action), resource: widened(resource) } : undefined);
      }
  }
  const allows = a.statements
    .filter((st) => (st.Effect === undefined || st.Effect === 'Allow') && plain(st) && st.Condition === undefined)
    .flatMap((st) => list(st.Action).flatMap((action) => list(st.Resource).map((resource) => ({ action, resource }))))
    .filter((x): x is { action: string; resource: string } => typeof x.action === 'string' && typeof x.resource === 'string');
  const statementKey = (st: Statement) => stableKey(st);
  const oldStatements = new Set(b.statements.map(statementKey));
  // A Deny the old version already had took away the same access then; any other may take it away now.
  // An Effect not known statically may be a Deny.
  const denies = a.statements.filter((st) => st.Effect !== undefined && st.Effect !== 'Allow' && !oldStatements.has(statementKey(st)));
  const denied = (g: { action: string; resource: string }) =>
    denies.some((st) => {
      const actions = st.NotAction !== undefined ? ['*'] : list(st.Action).map(widened);
      const resources = st.NotResource !== undefined ? ['*'] : list(st.Resource).map(widened);
      return actions.some((x) => mayOverlap(x, g.action, true)) && resources.some((x) => mayOverlap(x, g.resource, false));
    });
  return (g) => {
    if (g.effect !== 'Allow') return false;
    const o = old.get(`${g.action}|${g.resource}`);
    if (!o) return false;
    return allows.some((n) => covers(n.action, o.action, true) && covers(n.resource, o.resource, false)) && !denied(o);
  };
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

function policyVersion(policy: unknown): unknown {
  let doc: unknown = reveal(policy);
  if (typeof doc === 'string') {
    try {
      doc = JSON.parse(doc);
    } catch {
      return undefined;
    }
  }
  return doc && typeof doc === 'object' && !isUnknown(doc) ? stableKey((doc as { Version?: unknown }).Version ?? null) : undefined;
}

/** IAM glob matching (`*` any run, `?` one character) in linear passes, without regular expressions. */
function globMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      mark = t;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

/**
 * True when a glob (IAM `*` and `?`) matches everything `inner` can match. Exact for a literal `inner`,
 * and for an `outer` whose only wildcard is a trailing `*`; anything else is answered false.
 */
function covers(outer: string, innerRaw: string, caseless: boolean): boolean {
  // An IAM policy variable (`${aws:username}`) is a value at request time: in the new grant it can be
  // anything, and an old grant that holds one covers only the identical text.
  if (outer.includes('${')) return outer === innerRaw;
  const inner = innerRaw.replace(/\$\{[^}]*\}/g, '*');
  const o = caseless ? outer.toLowerCase() : outer;
  const i = caseless ? inner.toLowerCase() : inner;
  if (o === i || o === '*') return true;
  if (!/[*?]/.test(i)) return globMatch(o, i);
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
  // Policy variables are substituted only from 2012-10-17 on, so the same text can grant something else.
  if (policyVersion(before) !== policyVersion(after)) return false;
  const plain = (st: Statement) => st.NotAction === undefined && st.NotResource === undefined && st.NotPrincipal === undefined;
  if (![...b.statements, ...a.statements].every(plain)) return false;
  // A condition that holds a value not known statically (an endpoint id) may name something else at apply.
  if ([...b.statements, ...a.statements].some((st) => st.Condition !== undefined && containsUnknown(st.Condition))) return false;
  // An Effect not known statically could be either; nothing about such a statement is certain.
  if (![...b.statements, ...a.statements].every((st) => st.Effect === undefined || st.Effect === 'Allow' || st.Effect === 'Deny')) return false;
  // A value partly known at plan time stands for every value its pattern allows: each unknown part is a
  // wildcard. That only widens the new grants, so a containment found with it holds for the real value.
  const strings = (v: unknown, widen: boolean): string[] | undefined => {
    const xs = list(v).map((x) => (typeof x === 'string' ? x : widen && isUnknown(x) && x.pattern?.startsWith('arn:') ? x.pattern.replaceAll('{?}', '*') : undefined));
    return xs.every((x) => x !== undefined) ? (xs as string[]) : undefined;
  };
  const allow = (st: Statement) => (st.Effect ?? 'Allow') === 'Allow';
  const denyKey = (st: Statement) => stableKey([st.Action ?? null, st.Resource ?? null, st.Condition ?? null, st.Principal ?? null]);
  const kept = new Set(a.statements.filter((st) => !allow(st)).map(denyKey));
  if (b.statements.some((st) => !allow(st) && !kept.has(denyKey(st)))) return false;
  const old = b.statements.filter(allow).map((st) => ({ actions: strings(st.Action, false), resources: strings(st.Resource, false), condition: st.Condition }));
  for (const st of a.statements.filter(allow)) {
    const actions = strings(st.Action, false);
    const resources = strings(st.Resource, true);
    if (!actions || !resources || !actions.length || !resources.length) return false;
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
