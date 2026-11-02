import { UNKNOWN_PART, isRedacted, isUnknown, reveal, type Action, type Attrs, type ResourceChange } from '../core/model.js';
import { containsUnknown, redact, stableKey } from '../hcl/eval.js';
import type { ReplaceTrigger, RootEvaluation, StaticInstance } from './expand.js';
import { CONDITIONAL_REPLACE, NESTED_REPLACE, REPLACE_ON_CHANGE, REPLACE_SETS } from './replaceCatalog.js';
import { argumentFacts, retainedOnDestroy } from './schemaCatalog.js';
import { STATEFUL } from '../analysis/blastRadius.js';

/**
 * Turn two static evaluations of the same root into ResourceChanges, the way `terraform plan` would
 * classify them, within what can be known without state: moved/removed/import blocks are honoured,
 * catalogued ForceNew arguments produce replacements, and everything uncertain says so in `confidence`.
 * Unchanged resources are returned as `no-op` so analyzers can use them as context.
 */
export function compareEvaluations(base: RootEvaluation | undefined, head: RootEvaluation | undefined): ResourceChange[] {
  const before = new Map((base?.instances ?? []).map((i) => [i.address, i]));
  const after = new Map((head?.instances ?? []).map((i) => [i.address, i]));
  const out: ResourceChange[] = [];
  const consumedBefore = new Set<string>();
  const consumedAfter = new Set<string>();

  // Availability of source code is not a resource lifecycle change. An opaque module covers its
  // whole subtree when only the opposite snapshot can expand it.
  for (const [opaque, expanded, consumedOpaque, consumedExpanded] of [
    [before, after, consumedBefore, consumedAfter],
    [after, before, consumedAfter, consumedBefore],
  ] as const) {
    for (const [address, instance] of opaque) {
      if (!instance.externalModule || expanded.has(address) || consumedOpaque.has(address)) continue;
      const peers = [...expanded.keys()].filter((peer) => (peer.startsWith(address + '.') || peer.startsWith(address + '[')) && !consumedExpanded.has(peer));
      if (!peers.length) continue;
      consumedOpaque.add(address); for (const peer of peers) consumedExpanded.add(peer);
      out.push({ ...toChange(instance, 'update', instance.attrs, instance.attrs), confidence: 'unknown', actionReason: 'Module source is available in only one snapshot; resource lifecycle changes cannot be established' });
    }
  }

  // moved blocks: pair base-only addresses with head-only addresses (resource or whole-module moves).
  // Moves chain (a -> b, then b -> c), so an address follows them to its final destination.
  const moves = head?.moved ?? [];
  for (const [addr, b] of before) {
    if (after.has(addr) || consumedBefore.has(addr)) continue;
    const target = finalDestination(addr, moves);
    if (target === addr || !after.has(target) || before.has(target) || consumedAfter.has(target)) continue;
    const a = after.get(target)!;
    consumedBefore.add(addr);
    consumedAfter.add(target);
    const change = diffInstance(b, a);
    out.push({ ...change, action: change.action === 'no-op' ? 'move' : change.action, previousAddress: addr });
  }

  // Adding count to a resource moves `t` to `t[0]`, removing it moves `t[0]` back to `t`.
  for (const [addr, b] of before) {
    if (after.has(addr) || consumedBefore.has(addr)) continue;
    const target = countVariants(addr).find((v) => after.has(v) && !before.has(v) && !consumedAfter.has(v));
    if (!target) continue;
    consumedBefore.add(addr);
    consumedAfter.add(target);
    const change = diffInstance(b, after.get(target)!);
    out.push({ ...change, action: change.action === 'no-op' ? 'move' : change.action, previousAddress: addr });
  }

  // count/for_each known on one side and not the other: the instances cannot be paired, so neither a
  // proven create nor a proven delete is claimed.
  for (const [symbolicMap, otherMap, side] of [[after, before, 'head'], [before, after, 'base']] as const) {
    for (const [addr, sym] of symbolicMap) {
      if (!addr.includes('[*]')) continue;
      // Only instances the symbolic address can stand for: `module.m["a"].t[*]` says nothing about
      // module.m["b"], but `t[*]` may be the `t` that had no count before.
      const covers = new RegExp('^' + addr.split('[*]').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(?:\\[[^\\]]*\\])?') + '$');
      const peers = [...otherMap.entries()].filter(
        ([o, i]) => !o.includes('[*]') && i.configAddress === sym.configAddress && !symbolicMap.has(o) && covers.test(o)
      );
      if (!peers.length) continue;
      for (const [o, peer] of peers) {
        (side === 'head' ? consumedBefore : consumedAfter).add(o);
        const [b, a] = side === 'head' ? [peer, sym] : [sym, peer];
        out.push({
          ...toChange(a, 'update', b.attrs, a.attrs),
          address: peer.address,
          confidence: 'unknown',
          actionReason: `count or for_each of ${sym.configAddress} is not known statically at ${side}, so instances may be kept, added or removed`,
        });
      }
      (side === 'head' ? consumedAfter : consumedBefore).add(addr);
    }
  }

  for (const [addr, a] of after) {
    if (consumedAfter.has(addr)) continue;
    const b = before.get(addr);
    if (b) {
      const change = diffInstance(b, a);
      // Both sides symbolic, but the count or for_each expression changed (`var.n` to `var.n - 1`):
      // instances may be added or removed, which neither side can name.
      if (change.action === 'no-op' && (b.expansion || a.expansion) && b.expansion !== a.expansion) {
        out.push({
          ...change,
          action: 'update',
          confidence: 'unknown',
          actionReason: `count or for_each of ${a.configAddress} changed and is not known statically, so instances may be added or removed`,
        });
        continue;
      }
      out.push(change);
      continue;
    }
    const imported = head?.imports.includes(addr);
    out.push(toChange(a, imported ? 'import' : 'create', null, a.attrs));
  }

  const created = out.filter((c) => c.action === 'create');
  const hinted = new Set<ResourceChange>();
  const deleted: Array<{ change: ResourceChange; addr: string; b: StaticInstance }> = [];
  // The instance keys of an address, so `a["x"].t` is paired with `b["x"].t` before any other twin.
  const keysOf = (a: string) => (a.match(/\[("([^"\\]|\\.)*"|[^\]]*)\]/g) ?? []).join('');
  for (const [addr, b] of before) {
    if (after.has(addr) || consumedBefore.has(addr)) continue;
    const removed = head?.removed.find((r) => addr === r.from || addr.startsWith(`${r.from}.`) || addr.startsWith(`${r.from}[`));
    if (removed && !removed.destroy) {
      out.push(toChange(b, 'forget', b.attrs, null));
      continue;
    }
    // prevent_destroy applies while the block is in the configuration: removing the block allows the
    // destroy, but removing instances of a block that still exists makes the plan fail, even when
    // count or for_each drops to zero.
    const guarded = head?.preventDestroy.has(b.configAddress) || undefined;
    // skip_destroy = true: the provider's delete only drops the object from state; it stays in AWS.
    if (!guarded && retainedOnDestroy(b.type, b.attrs)) {
      out.push({ ...toChange(b, 'forget', b.attrs, null), actionReason: 'skip_destroy = true: Terraform removes it from state and the provider leaves it in AWS' });
      continue;
    }
    const change = { ...toChange(b, 'delete', b.attrs, null), preventDestroy: guarded };
    // A symbolic instance stands for a count not known statically at the base, which may have been zero.
    if (addr.includes('[*]')) {
      change.confidence = 'likely';
      change.actionReason = `count or for_each of ${b.configAddress} was not known statically at base, so instances may already have been absent`;
    }
    deleted.push({ change, addr, b });
    out.push(change);
  }
  // Rename hints: a created resource of the same type and body, each used once. Twins with the same
  // instance keys are paired first, so `a["x"]` is not offered `b["y"]` while `b["x"]` exists.
  for (const sameKeys of [true, false]) {
    for (const { change, addr, b } of deleted) {
      if (change.actionReason?.startsWith('looks like a rename')) continue;
      const twin = created.find((c) => c.type === b.type && c.mode === b.mode && !hinted.has(c) && (!sameKeys || keysOf(c.address) === keysOf(addr)) && sameBody(c.after, b.attrs));
      if (!twin) continue;
      hinted.add(twin);
      change.actionReason = `looks like a rename to ${twin.address} without a moved block; add moved { from = ${addr}, to = ${twin.address} } to keep it`;
    }
  }

  // A possible replacement whose forcing arguments are unknown at both commits and differ only in the
  // expression behind them is not likely: the value most often stays the same. It is an unknown update,
  // unless what the value reads is a resource this change creates, replaces or deletes, or a data source
  // whose arguments change (a new AMI filter selects another image).
  const touched = new Set(out.filter((c) => c.action === 'create' || c.action === 'replace' || c.action === 'delete').map((c) => configAddressOf(c.address)));
  // A data source reference names an instance or the whole block; each instance is compared by its address.
  const selects = (m: Map<string, StaticInstance>, ref: string) =>
    stableKey([...m.values()].filter((i) => i.mode === 'data' && (i.address === ref || i.configAddress === ref)).sort((x, y) => (x.address < y.address ? -1 : 1)).map((i) => [i.address, dataSelector(i.type, i.attrs)]));
  for (const c of out) {
    const refs = UNKNOWN_ORIGIN.get(c);
    if (!refs || refs.some((r) => touched.has(configAddressOf(r)) || (isDataRef(r) && selects(before, r) !== selects(after, r)))) continue;
    const keys = (c.replacePaths ?? []).map((p) => p[0]);
    c.action = 'update';
    c.confidence = 'unknown';
    c.actionReason = `${keys.join(', ')} ${keys.length === 1 ? 'is' : 'are'} not known statically at either commit, and only the expression or data source behind ${keys.length === 1 ? 'it' : 'them'} changed, so whether ${keys.length === 1 ? 'it changes' : 'they change'} is not known`;
    delete c.replacePaths;
    delete c.replaceOrder;
  }

  // A replacement gives new computed values, which can replace a dependent, which can trigger the next.
  for (let progressed = true; progressed; ) {
    progressed = propagateReplacements(out, after);
    progressed = applyReplaceTriggers(out, before, after) || progressed;
  }
  return out;
}

/**
 * A replaced resource gets new computed attributes (id, arn, ...). A resource that reads one of them
 * changes in that attribute even though its configuration did not: an update, or a replacement when
 * the attribute forces one. Attributes set in configuration keep their known values and are not
 * affected. Returns whether anything changed.
 */
function propagateReplacements(out: ResourceChange[], after: Map<string, StaticInstance>): boolean {
  let progressed = false;
  for (let changed = true; changed; ) {
    changed = false;
    const replaced = new Set(out.filter((c) => c.action === 'replace').map((c) => c.address));
    if (!replaced.size) break;
    for (const c of out) {
      if (c.action !== 'no-op' && c.action !== 'update' && c.action !== 'move') continue;
      const inst = after.get(c.address);
      if (!inst) continue;
      for (const [k, v] of Object.entries(inst.attrs)) {
        const source = unknownRefs(v).find((r) => replaced.has(r));
        if (!source) continue;
        const forces = REPLACE_ON_CHANGE[inst.type]?.includes(k);
        const reason = `${k} reads a computed attribute of ${source}, which is replaced`;
        if (forces) {
          c.action = 'replace';
          c.replacePaths = [...(c.replacePaths ?? []), [k]];
          c.replaceOrder = inst.createBeforeDestroy ? 'create-first' : 'delete-first';
          c.confidence = 'likely';
          c.actionReason = reason;
          changed = progressed = true;
          break;
        }
        if (c.action === 'no-op' || c.action === 'move') {
          c.action = 'update';
          c.confidence = 'likely';
          c.actionReason = reason;
          changed = progressed = true;
        }
      }
    }
  }
  return progressed;
}

/** Addresses of the resources whose computed attributes a value reads (the refs of its unknown parts). */
function unknownRefs(v: unknown): string[] {
  const x = reveal(v);
  if (isUnknown(x)) return x.refs;
  if (Array.isArray(x)) return x.flatMap(unknownRefs);
  if (x !== null && typeof x === 'object' && !isRedacted(x)) return Object.values(x).flatMap(unknownRefs);
  return [];
}

/**
 * lifecycle replace_triggered_by: a resource that would be kept or updated is replaced when a
 * referenced resource or instance is updated or replaced, or a referenced attribute changes. Runs until
 * nothing changes, so a replacement can trigger the next.
 */
function applyReplaceTriggers(out: ResourceChange[], before: Map<string, StaticInstance>, after: Map<string, StaticInstance>): boolean {
  const byAddress = new Map(out.map((c) => [c.address, c]));
  const fires = (t: ReplaceTrigger): { action: string; confidence: ResourceChange['confidence'] } | undefined => {
    const changes = t.instance ? [byAddress.get(t.address)] : out.filter((c) => c.address === t.address || c.address.startsWith(`${t.address}[`));
    for (const c of changes) {
      if (!c || (c.action !== 'replace' && c.action !== 'update')) continue;
      if (!t.attr) return { action: c.action === 'replace' ? 'replaced' : 'updated', confidence: c.confidence === 'proven' ? 'proven' : 'likely' };
      // An attribute reference fires when the attribute's value changes, whatever happens to its resource.
      // A moved resource was at its previous address before the change.
      const b = before.get(c.previousAddress ?? c.address) ?? before.get(c.address);
      const a = after.get(c.address);
      if (!a || !b) continue;
      const was = valueAt(b.attrs, t.attr);
      const now = valueAt(a.attrs, t.attr);
      if (was === undefined && now === undefined) {
        // Computed by the provider (an id, an output, a version): Terraform plans it as unknown when
        // the resource is replaced, and may when it is updated.
        return { action: c.action === 'replace' ? 'replaced' : 'updated', confidence: 'likely' };
      }
      if (stableKey(was) === stableKey(now)) continue;
      return { action: 'changed', confidence: containsUnknown(was) || containsUnknown(now) ? 'likely' : 'proven' };
    }
    return undefined;
  };
  // Each pass only turns changes into replacements, so passes until nothing changes always end.
  let progressed = false;
  for (let changed = true; changed; ) {
    changed = false;
    for (const c of out) {
      if (c.action !== 'update' && c.action !== 'no-op' && c.action !== 'move') continue;
      const inst = after.get(c.address);
      for (const t of inst?.replaceTriggeredBy ?? []) {
        const hit = fires(t);
        if (!hit) continue;
        c.action = 'replace';
        c.replaceOrder = inst!.createBeforeDestroy ? 'create-first' : 'delete-first';
        c.confidence = hit.confidence === 'proven' && c.confidence === 'proven' ? 'proven' : 'likely';
        c.actionReason = `replace_triggered_by: ${t.label} is ${hit.action}`;
        changed = progressed = true;
        break;
      }
    }
  }
  return progressed;
}

/** The value at a dotted path inside a block; a sub-block list gives the list of its values. */
function fieldAt(block: unknown, path: string): unknown {
  let v: unknown = block;
  for (const part of path.split('.')) {
    const at = (x: unknown): unknown => {
      const r = reveal(x);
      if (Array.isArray(r)) return r.map(at);
      return r !== null && typeof r === 'object' && !isUnknown(r) ? (r as Attrs)[part] : r;
    };
    v = at(v);
  }
  return v;
}

/** A set of blocks compared without order: the same blocks in another order are equal. */
function setKey(v: unknown): string {
  const r = reveal(v);
  return Array.isArray(r) ? stableKey(r.map((x) => stableKey(x)).sort()) : stableKey(v);
}

/**
 * True when two values differ in a part that is known on both sides. An unknown on either side (a
 * sensitive value is judged by what it holds) may equal whatever is on the other side.
 */
function knownDiffer(before: unknown, after: unknown): boolean {
  const b = reveal(before);
  const a = reveal(after);
  if (isUnknown(b) || isUnknown(a) || isRedacted(b) || isRedacted(a)) return false;
  if (Array.isArray(b) && Array.isArray(a)) return b.length !== a.length || b.some((x, i) => knownDiffer(x, a[i]));
  const obj = (x: unknown): x is Attrs => x !== null && typeof x === 'object' && !Array.isArray(x);
  if (obj(b) && obj(a)) {
    const kb = Object.keys(b).sort();
    const ka = Object.keys(a).sort();
    return kb.join('\u0000') !== ka.join('\u0000') || kb.some((k) => knownDiffer(b[k], a[k]));
  }
  return stableKey(b) !== stableKey(a);
}

function valueAt(attrs: Attrs, path: string[]): unknown {
  let v: unknown = attrs;
  for (const p of path) {
    if (v && typeof v === 'object' && !isUnknown(v)) v = (v as Record<string, unknown>)[p];
    else return v;
  }
  return v;
}

/** Apply moved blocks to `addr` until none applies; each block is used at most once, so cycles end. */
function finalDestination(addr: string, moves: Array<{ from: string; to: string }>): string {
  const used = new Set<number>();
  let cur = addr;
  for (let progressed = true; progressed; ) {
    progressed = false;
    for (let i = 0; i < moves.length; i++) {
      if (used.has(i)) continue;
      const next = movedTarget(cur, moves[i].from, moves[i].to);
      if (!next) continue;
      used.add(i);
      cur = next;
      progressed = true;
    }
  }
  return cur;
}

/** Where a moved block sends `addr`, if it applies. Handles `module.a -> module.b` prefix moves. */
function movedTarget(addr: string, from: string, to: string): string | undefined {
  if (addr === from) return to;
  for (const sep of ['.', '[']) {
    if (addr.startsWith(from + sep)) return to + addr.slice(from.length);
  }
  return undefined;
}

function sameBody(a: Attrs | null, b: Attrs | null): boolean {
  const strip = (x: Attrs | null) => {
    if (!x) return x;
    const { tags, tags_all, ...rest } = x;
    void tags;
    void tags_all;
    return rest;
  };
  return stableKey(strip(a)) === stableKey(strip(b));
}

/** Possible replacements that differ only in the origin of unknown values -> the resources and data sources those values read. */
const UNKNOWN_ORIGIN = new WeakMap<ResourceChange, string[]>();

const configAddressOf = (a: string) => a.replace(/\[("([^"\\]|\\.)*"|[^\]]*)\]/g, '');
const isDataRef = (r: string) => /(^|\.)data\./.test(r);

/**
 * Settings of terraform_remote_state that say how to reach the state, not which state is read: changing
 * them (a role moved into assume_role) reads the same outputs.
 */
const REMOTE_STATE_ACCESS = new Set([
  'role_arn', 'assume_role', 'assume_role_with_web_identity', 'profile', 'access_key', 'secret_key', 'token',
  'shared_credentials_file', 'shared_credentials_files', 'shared_config_files', 'external_id', 'session_name',
  'sts_endpoint', 'iam_endpoint', 'max_retries', 'retry_mode', 'skip_credentials_validation',
  'skip_metadata_api_check', 'skip_region_validation', 'skip_requesting_account_id', 'skip_s3_checksum',
  'dynamodb_table', 'use_lockfile', 'encrypt', 'kms_key_id', 'acl',
]);

/** The arguments of a data source that select what it reads. */
function dataSelector(type: string, attrs: Attrs): unknown {
  if (type !== 'terraform_remote_state') return attrs;
  const config = reveal(attrs.config);
  if (config === null || typeof config !== 'object' || Array.isArray(config) || isUnknown(config)) return attrs;
  return { ...attrs, config: Object.fromEntries(Object.entries(config as Attrs).filter(([k]) => !REMOTE_STATE_ACCESS.has(k))) };
}

/**
 * The resources and data sources read by two values that differ only where both are unknown, with the
 * same known text around the unknown parts and reading the same resources and data sources; undefined when they
 * differ in anything known, or when one side is known where the other is not.
 */
function unknownOriginOnly(before: unknown, after: unknown): string[] | undefined {
  const b = reveal(before);
  const a = reveal(after);
  if (isRedacted(b) || isRedacted(a)) return undefined;
  if (isUnknown(b) || isUnknown(a)) {
    if (!isUnknown(b) || !isUnknown(a)) return undefined;
    // No pattern, or `{?}` alone, says nothing about the value's text.
    const text = (u: typeof b) => (u.pattern === undefined || u.pattern === UNKNOWN_PART ? undefined : u.pattern);
    if (text(b) !== text(a)) return undefined;
    // The same resources and data sources on both sides, instance keys included: `s[0]` to `s[1]` reads
    // another subnet. A data source whose arguments change is checked by the caller.
    const refs = (u: typeof b) => [...new Set(u.refs)].sort().join('\u0000');
    return refs(b) === refs(a) ? [...new Set(a.refs)] : undefined;
  }
  const merge = (parts: Array<string[] | undefined>) => (parts.some((x) => x === undefined) ? undefined : [...new Set(parts.flat() as string[])]);
  if (Array.isArray(b) && Array.isArray(a)) return b.length === a.length ? merge(b.map((x, i) => unknownOriginOnly(x, a[i]))) : undefined;
  const obj = (x: unknown): x is Attrs => x !== null && typeof x === 'object' && !Array.isArray(x);
  if (obj(b) && obj(a)) {
    const kb = Object.keys(b).sort();
    if (kb.join('\u0000') !== Object.keys(a).sort().join('\u0000')) return undefined;
    return merge(kb.map((k) => unknownOriginOnly(b[k], a[k])));
  }
  return stableKey(b) === stableKey(a) ? [] : undefined;
}

function toChange(i: StaticInstance, action: Action, before: Attrs | null, after: Attrs | null): ResourceChange {
  return {
    address: i.address,
    type: i.type,
    name: i.name,
    mode: i.mode,
    moduleAddress: i.moduleAddress,
    ...(i.providerAddress ? { providerAddress: i.providerAddress } : {}),
    action: i.mode === 'data' ? 'no-op' : action,
    before,
    after,
    references: i.references,
    // Existing ignored values may have drifted; neither snapshot's configuration attests them.
    ...(i.configuredAttrs ? { configuredAfter: before === null ? i.configuredAttrs : applied({}, i.configuredAttrs, i.ignoreChanges) } : {}),
    source: i.source,
    confidence: i.externalModule ? 'unknown' : 'proven',
    preventDestroy: i.preventDestroy || undefined,
  };
}

function diffInstance(b: StaticInstance, a: StaticInstance): ResourceChange {
  const ignored = a.ignoreChanges;
  const keys = new Set([...Object.keys(b.attrs), ...Object.keys(a.attrs)]);
  // What null means in a plan decides some arguments before their values are compared.
  const semantics = new Map([...keys].map((k) => [k, nullSemantics(a.type, k, b.attrs[k], a.attrs[k])]));
  const possible = new Set([...keys].filter((k) => semantics.get(k) === 'possible'));
  const changed =
    ignored === 'all'
      ? []
      : [...keys].filter((k) => {
          if (semantics.get(k) === 'same') return false;
          const paths = ignored.filter((p) => p[0] === k);
          if (paths.some((p) => p.length === 1)) return false;
          // A set-typed block in another order is the same set.
          const key = REPLACE_SETS[a.type]?.includes(k) ? setKey : stableKey;
          return key(masked(b.attrs[k], paths)) !== key(masked(a.attrs[k], paths));
        });

  const base = toChange(a, 'no-op', b.attrs, applied(b.attrs, a.attrs, ignored));
  base.configuredBefore = b.configuredAttrs;
  base.preventDestroy = a.preventDestroy || undefined;
  if (!changed.length || a.mode === 'data') return base;

  if (a.externalModule) {
    return { ...base, action: 'update', confidence: 'unknown', actionReason: `inputs of external module ${a.externalModule.source ?? ''} changed: ${changed.join(', ')}` };
  }

  const catalogued = REPLACE_ON_CHANGE[a.type];
  const uncertain = changed.some((k) => possible.has(k) || containsUnknown(b.attrs[k]) || containsUnknown(a.attrs[k]));
  const forcing = catalogued ? changed.filter((k) => catalogued.includes(k)) : [];
  if (forcing.length) {
    // A change in a ForceNew argument that is not known statically (a referenced ARN, or a block with an
    // unknown attribute inside, which may hold the same value on both sides) is only a possible
    // replacement. A sensitive value is judged by what it holds, which may itself be unknown.
    // Certain only when something known on both sides differs: a leaf, a list length or object keys.
    // A ForceNew nested block (SDKv2 TypeList/TypeSet of a resource) forces replacement on its element
    // count; inside it, only its own ForceNew fields do (NESTED_REPLACE), others update in place, so a
    // change there is a possible replacement. Ignored paths are masked first.
    const paths = (k: string) => (ignored === 'all' ? [] : ignored.filter((p) => p[0] === k));
    const certain = forcing.filter((k) => {
      if (possible.has(k)) return false;
      const was = masked(b.attrs[k], paths(k));
      const now = masked(a.attrs[k], paths(k));
      const nested = NESTED_REPLACE[a.type]?.[k];
      if (nested) {
        // An absent block is an empty list of blocks.
        const bw = reveal(was) ?? [];
        const an = reveal(now) ?? [];
        if (!Array.isArray(bw) || !Array.isArray(an)) return knownDiffer(was, now);
        // A dynamic block over an unknown collection leaves an Unknown element: the count is not known.
        if (bw.some(isUnknown) || an.some(isUnknown)) return false;
        if (bw.length !== an.length) return true;
        // Same count: only a known change in one of the block's own ForceNew fields is certain. Fields of
        // sub-blocks are dotted paths. A set's blocks are matched by content, not position.
        const project = (x: unknown) => nested.map((f) => fieldAt(reveal(x), f));
        if (REPLACE_SETS[a.type]?.includes(k)) {
          // Certain when some block's ForceNew fields differ, in parts known on both sides, from every
          // block on the other side: no reordering can make the sets equal.
          const pb = bw.map(project);
          const pa = an.map(project);
          return pa.some((p) => pb.every((q) => knownDiffer(q, p))) || pb.some((q) => pa.every((p) => knownDiffer(q, p)));
        }
        return bw.some((x, i) => knownDiffer(project(x), project(an[i])));
      }
      return knownDiffer(was, now);
    });
    const change: ResourceChange = {
      ...base,
      action: 'replace',
      replacePaths: forcing.map((k) => [k]),
      replaceOrder: a.createBeforeDestroy ? 'create-first' : 'delete-first',
      confidence: certain.length ? 'proven' : 'likely',
      actionReason: 'replace_because_cannot_update',
    };
    // Every forcing argument unknown at both commits, differing only in where the unknown comes from.
    // Not for a stateful type: a changed index or literal inside the expression is not seen here, and
    // replacing a database or bucket loses data, so its possible replacement stays reviewed.
    if (!certain.length && !STATEFUL[a.type] && !forcing.some((k) => possible.has(k) || NESTED_REPLACE[a.type]?.[k])) {
      const origins = forcing.map((k) => unknownOriginOnly(masked(b.attrs[k], paths(k)), masked(a.attrs[k], paths(k))));
      if (origins.every((o) => o !== undefined)) UNKNOWN_ORIGIN.set(change, [...new Set(origins.flat() as string[])]);
    }
    return change;
  }
  const conditional = changed.filter((k) => CONDITIONAL_REPLACE[a.type]?.includes(k));
  if (conditional.length) {
    return {
      ...base,
      action: 'replace',
      replacePaths: conditional.map((k) => [k]),
      replaceOrder: a.createBeforeDestroy ? 'create-first' : 'delete-first',
      confidence: 'likely',
      actionReason: `changing ${conditional.join(', ')} can force replacement; the provider decides at plan time`,
    };
  }
  return {
    ...base,
    action: 'update',
    confidence: !catalogued ? 'likely' : uncertain ? 'likely' : 'proven',
    actionReason: catalogued ? undefined : `replacement rules for ${a.type} are not catalogued; reported as an in-place update`,
  };
}

/**
 * How the provider plans a top-level argument when one side is null (absent and null are the same in
 * Terraform), before values are compared:
 * - `same`: no change. Both null; null meets the provider default; a value goes to null on an
 *   Optional+Computed argument of an SDKv2 resource (state keeps it); in SDKv2, "" is null for a string
 *   argument without a default.
 * - `possible`: the planned value depends on state: null becomes a value on an Optional+Computed
 *   argument (state holds whatever the provider computed), or a plugin-framework resource drops one
 *   (the framework may plan it as unknown).
 * - undefined: compare the values as they are.
 * Unknown and sensitive values are never decided here.
 */
function nullSemantics(type: string, key: string, rawBefore: unknown, rawAfter: unknown): 'same' | 'possible' | undefined {
  // A sensitive value is judged by what it holds; an unknown one, or one whose value is hidden, is not decided.
  // Inputs of a module call are not provider arguments: null passed to a nullable variable is not its default.
  if (type === 'terraform_module_call') return undefined;
  const before = reveal(rawBefore);
  const after = reveal(rawAfter);
  if (isUnknown(before) || isUnknown(after) || isRedacted(before) || isRedacted(after)) return undefined;
  const nullish = (v: unknown) => v === undefined || v === null;
  if (nullish(before) && nullish(after)) return 'same';
  const facts = argumentFacts(type);
  if (!facts) return undefined;
  const fallback = facts.defaults.get(key);
  const sdk = !facts.framework;
  // SDKv2 cannot tell "" from null in a string argument; with a default, "" is a value of its own.
  const norm = (v: unknown) => (nullish(v) || (sdk && fallback === undefined && v === '') ? null : v);
  let was = norm(before);
  let now = norm(after);
  if (fallback !== undefined) {
    was ??= fallback;
    now ??= fallback;
  }
  // Only an argument left out (or null) keeps the state value on an Optional and Computed argument; ""
  // is configured, and may be a change from whatever the provider computed. The plugin framework tells
  // "" from null, so a configured value going to "" there is planned as "": compared as it is.
  if (facts.optionalComputed.has(key) && after === '' && before !== '' && (sdk || nullish(before))) return 'possible';
  if (was === null && now === null) return 'same';
  if (facts.optionalComputed.has(key)) {
    if (now === null) return sdk ? 'same' : 'possible';
    if (was === null) return 'possible';
  }
  if (was === null || now === null) return undefined;
  const scalar = (v: unknown) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
  // Terraform converts a configured "30" to the number 30 of the schema, so the default is matched the same way.
  if (fallback !== undefined && scalar(was) && scalar(now) && String(was) === String(now)) return 'same';
  return undefined;
}

/**
 * The attributes Terraform will apply: the configuration, except that ignored paths keep their prior
 * value. Analyzers judge this, not configuration Terraform will not act on.
 */
function applied(before: Attrs, after: Attrs, ignored: Array<Array<string | number>> | 'all'): Attrs {
  if (ignored === 'all') return before;
  if (!ignored.length) return after;
  let out: unknown = after;
  for (const p of ignored) out = withPathValue(out, p, valueAtPath(before, p));
  return out as Attrs;
}

/** A copy of a value with the nested paths (below the top-level attribute) removed. */
function masked(value: unknown, paths: Array<Array<string | number>>): unknown {
  let out = value;
  for (const p of paths) out = withPathValue(out, p.slice(1), undefined);
  return out;
}

/** The value at a path, looking through sensitive values. */
function valueAtPath(v: unknown, path: Array<string | number>): unknown {
  let cur = v;
  for (const k of path) {
    cur = reveal(cur);
    cur = cur && typeof cur === 'object' && !isUnknown(cur) ? (cur as Record<string | number, unknown>)[k] : undefined;
  }
  return cur;
}

/**
 * A copy of a value with the path set (or removed, for undefined). A sensitive value on the way is
 * opened and wrapped again, so an ignored field inside `sensitive({...})` is masked like any other.
 */
function withPathValue(v: unknown, path: Array<string | number>, value: unknown): unknown {
  if (!path.length) return value;
  if (isRedacted(v)) return v.revealed ? redact(withPathValue(v.revealed.value, path, value)) : v;
  const plain = Array.isArray(v) || (v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype);
  if (!plain) return v;
  const copy = (Array.isArray(v) ? [...v] : { ...(v as Attrs) }) as Record<string | number, unknown>;
  const [k, ...rest] = path;
  if (rest.length) copy[k] = withPathValue(copy[k], rest, value);
  else if (value === undefined) delete copy[k];
  else copy[k] = value;
  return copy;
}

/**
 * Addresses Terraform moves to implicitly when count is added to or removed from a resource: `t` to
 * `t[0]` and back. Only the resource's own key: a module call gaining count is not moved implicitly
 * (hashicorp/terraform internal/refactoring ImpliedMoveStatements), so its resources are replaced.
 */
function countVariants(addr: string): string[] {
  const m = addr.match(/^(.*?)(\[[^\]]*\])?$/)!;
  if (m[2] === undefined) return [`${addr}[0]`];
  if (m[2] === '[0]') return [m[1]];
  return [];
}

