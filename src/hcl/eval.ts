import { createHash, createHmac, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { Redacted, UNKNOWN_PART, Unknown, hasRedacted, isRedacted, isUnknown, reveal } from '../core/model.js';
import { knownConfiguration } from '../core/configuration.js';
import type { Expr, TemplatePart } from './ast.js';
import { parseHcl } from './parser.js';

/**
 * Static evaluator for HCL expressions. It never guesses: anything that depends on provider-computed
 * attributes, data sources, files or unresolvable input becomes an Unknown that remembers which
 * resources it came from and, for strings, the known text around the unknown parts.
 */

/** Values whose attributes are resolved on demand (resources, modules, lazily evaluated maps). */
export abstract class Traversable {
  abstract getAttr(name: string): unknown;
  getIndex(key: unknown): unknown {
    return this.getAttr(String(key));
  }
  /** Entries for iteration, or undefined if the shape is not known. */
  entries(): Array<[string, unknown]> | undefined {
    return undefined;
  }
  /** Plain value for functions like jsonencode. */
  toPlain(): unknown {
    const e = this.entries();
    return e ? Object.fromEntries(e.map(([k, v]) => [k, v instanceof Traversable ? v.toPlain() : v])) : new Unknown('opaque object');
  }
}

/** A map whose values are computed on first access. */
export class LazyMap extends Traversable {
  private readonly cache = new Map<string, unknown>();
  constructor(
    private readonly thunks: Map<string, () => unknown>,
    private readonly onMissing: (name: string) => unknown = (name) => {
      throw new EvalError(`no attribute "${name}"`);
    }
  ) {
    super();
  }
  private readonly inProgress = new Set<string>();
  getAttr(name: string): unknown {
    if (this.cache.has(name)) return this.cache.get(name);
    const thunk = this.thunks.get(name);
    if (!thunk) return this.onMissing(name);
    if (this.inProgress.has(name)) return new Unknown(`reference cycle through "${name}"`);
    this.inProgress.add(name);
    try {
      const v = thunk();
      this.cache.set(name, v);
      return v;
    } finally {
      this.inProgress.delete(name);
    }
  }
  has(name: string): boolean {
    return this.thunks.has(name);
  }
  entries(): Array<[string, unknown]> {
    return [...this.thunks.keys()].sort().map((k) => [k, this.getAttr(k)]);
  }
}

/**
 * A resource or data source instance. Known config arguments resolve to their values; any other
 * attribute (arn, id, url...) is computed by the provider and resolves to an Unknown referencing it.
 */
export class ResourceValue extends Traversable {
  constructor(
    readonly address: string,
    private readonly attrs: () => Record<string, unknown>,
    private readonly computed: (name: string) => unknown = () => undefined
  ) {
    super();
  }
  getAttr(name: string): unknown {
    const c = this.computed(name);
    if (c !== undefined) return c;
    const attrs = this.attrs();
    if (name in attrs && name !== 'id' && name !== 'arn') return attrs[name];
    // A data source's computed attributes depend on its arguments: changing a filter changes the result.
    // `data.` after the module path, so a managed resource in `module "data"` is not one.
    const dataSource = /^(module\.[^.[]+(\[[^\]]*\])?\.)*data\./.test(this.address);
    const path = dataSource ? `.${name}@${(this.argsKey ??= keyOf(attrs))}` : `.${name}`;
    return withPath(new Unknown(`${this.address}.${name} is computed`, UNKNOWN_PART, [this.address]), path);
  }
  private argsKey?: string;
  entries(): Array<[string, unknown]> {
    return Object.entries(this.attrs());
  }
}

export class EvalError extends Error {}

export interface EvalScope {
  /** Preserve invalid dependencies instead of simplifying them into encryption evidence. */
  configurationEvidence?: boolean;
  /** Resolve a root name: var, local, each, count, path, terraform, module, data, a resource type, or a loop variable. */
  root(name: string): unknown;
  /** Read a file relative to the module directory, for file() and friends. */
  readFile?(path: string): string | undefined;
}

export function childScope(parent: EvalScope, vars: Record<string, unknown>): EvalScope {
  return {
    root: (name) => (name in vars ? vars[name] : parent.root(name)),
    readFile: parent.readFile,
    configurationEvidence: parent.configurationEvidence,
  };
}

/** Evaluate, turning evaluation errors into Unknown values. */
export function evaluate(expr: Expr, scope: EvalScope): unknown {
  try {
    return ev(expr, scope);
  } catch (e) {
    if (e instanceof EvalError) return new Unknown(`error: ${e.message}`);
    throw e;
  }
}

function refsOf(...vals: unknown[]): string[] {
  const out = new Set<string>();
  for (const v of vals) if (isUnknown(v)) for (const r of v.refs) out.add(r);
  return [...out];
}

/**
 * The access path of an unknown value (`.names[0]`), part of its identity so that `z.names[0]` and
 * `z.names[1]` or `k.arn` and `k.id` are different values. Kept beside the value, never printed.
 */
const PATHS = new WeakMap<Unknown, string>();

/**
 * Paths longer than this are kept as a digest. A derived identity embeds the identity of every operand,
 * escaped once more at each level, so without a bound it grows exponentially with nesting depth.
 */
const MAX_PATH = 256;

function withPath<T extends Unknown>(u: T, path: string | undefined): T {
  if (path) PATHS.set(u, path.length > MAX_PATH ? `#${createHash('sha256').update(path).digest('hex').slice(0, 32)}` : path);
  return u;
}

/** Give an unknown made outside the evaluator (a dynamic block) a comparison identity; never printed. */
export const identifyUnknown = <T extends Unknown>(u: T, identity: string): T => withPath(u, identity);

/** The paths of the unknown values a result was derived from. */
function pathsOf(...vals: unknown[]): string | undefined {
  const paths = vals.flatMap(flattenUnknowns).map((u) => PATHS.get(u)).filter((p): p is string => Boolean(p));
  return paths.length ? paths.join(',') : undefined;
}

/** Arrays that are Terraform sets: iterating one gives each element as its own key, as in cty. */
const SETS = new WeakSet<unknown[]>();
export const markSet = <T extends unknown[]>(a: T): T => (SETS.add(a), a);
export const isTfSet = (v: unknown): v is unknown[] => Array.isArray(v) && SETS.has(v);

function unknownFrom(reason: string, ...vals: unknown[]): Unknown {
  return withPath(new Unknown(reason, undefined, refsOf(...vals)), pathsOf(...vals));
}

/**
 * An unknown derived by an operator or function from its operands. Its identity is the operator and
 * the identity of every operand, known or not, so changing a known branch, a function or a known
 * argument is a change, while the same expression over the same inputs keeps the same identity.
 */
function derivedUnknown(reason: string, op: string, operands: unknown[]): Unknown {
  return withPath(new Unknown(reason, undefined, refsOf(...operands.flatMap(flattenUnknowns))), `${op}(${operands.map(keyOf).join(',')})`);
}

function keyOf(v: unknown): string {
  try {
    return stableKey(v);
  } catch {
    // An operand that cannot be read whole (an object of unknown shape) still names the operation.
    return '?';
  }
}

/** The structure of an expression without its source positions, so moving code is not a change. */
/** The identity of a value, or of the error evaluating it; for origin identities only. */
function safeKey(f: () => unknown): string {
  try {
    return keyOf(f());
  } catch (e) {
    if (e instanceof EvalError) return `error:${e.message}`;
    throw e;
  }
}

/** The identity of template parts as evaluated in a scope: what a branch or body would produce. */
function partsKey(parts: TemplatePart[], scope: EvalScope, anon: unknown): string {
  return safeKey(() => {
    const acc: TemplateAcc = { text: '', unknown: false, sensitive: false, refs: new Set<string>() };
    appendParts(parts, scope, anon, acc);
    const v = acc.unknown ? withPath(new Unknown('template', acc.text, [...acc.refs]), acc.paths?.join(',')) : acc.text;
    // A sensitive branch is identified by its keyed digest, never by its text.
    return acc.sensitive ? redact(v) : v;
  });
}

function fingerprint(x: unknown): string {
  return JSON.stringify(x, (k, v) => (k === 'range' ? undefined : v));
}

const evidenceFrames: Array<{ kind: Expr['kind']; invalid: boolean }> = [];

/** Keep dependency failures even when Terraform can simplify the resulting value. Constructors
 * and traversals retain their shape so selecting a known sibling remains valid evidence. */
function ev(expr: Expr, scope: EvalScope, anon?: unknown): unknown {
  if (!scope.configurationEvidence) return evValue(expr, scope, anon);
  const frame = { kind: expr.kind, invalid: false };
  evidenceFrames.push(frame);
  let value: unknown;
  try {
    value = evValue(expr, scope, anon);
    const structural = ['object', 'tuple', 'scope', 'getattr', 'index', 'paren', 'anon'].includes(expr.kind);
    if (frame.invalid && !structural) value = new Unknown('configuration passed through a null, unknown or computed value');
    return value;
  } finally {
    evidenceFrames.pop();
    const parent = evidenceFrames.at(-1);
    // Lazy objects are examined when traversed or consumed, rather than enumerated here.
    if (parent && !(value instanceof Traversable) && !knownConfiguration(value)) {
      const projecting = ['getattr', 'index', 'object', 'tuple', 'paren'].includes(parent.kind);
      if (!projecting || value == null || isUnknown(value) || isRedacted(value)) parent.invalid = true;
    }
  }
}

function evValue(expr: Expr, scope: EvalScope, anon?: unknown): unknown {
  switch (expr.kind) {
    case 'literal':
      return expr.value;
    case 'paren':
      return ev(expr.expr, scope, anon);
    case 'template':
      return evalTemplate(expr.parts, scope, anon);
    case 'tuple':
      return expr.items.map((i) => ev(i, scope, anon));
    case 'object': {
      const out: Record<string, unknown> = {};
      const pairs = expr.items.map((item) => [ev(item.key, scope, anon), ev(item.value, scope, anon)] as const);
      // With a key not known statically the object has no shape, but every key and value is still
      // part of its identity: { (var.k) = "old" } and { (var.k) = "new" } differ.
      if (pairs.some(([k]) => isUnknown(k))) return derivedUnknown('object key not known', '{}', pairs.flat());
      for (const [k, v] of pairs) out[keyString(k)] = v;
      return out;
    }
    case 'scope': {
      const v = scope.root(expr.name);
      if (v === undefined) throw new EvalError(`unknown reference "${expr.name}"`);
      return v;
    }
    case 'anon':
      return anon;
    case 'getattr':
      return getAttr(ev(expr.obj, scope, anon), expr.name);
    case 'index':
      return getIndex(ev(expr.obj, scope, anon), ev(expr.key, scope, anon));
    case 'splat': {
      // A splat over a sensitive collection works on its elements; the result is sensitive.
      const t = taint();
      const coll = t.open(ev(expr.obj, scope, anon));
      // The projected traversal is part of the identity: rules[*].private_cidr is not rules[*].public_cidr.
      if (isUnknown(coll)) return t.close(derivedUnknown('splat over a collection not known statically', `[*]${fingerprint(expr.each)}`, [coll]));
      if (coll === null || coll === undefined) return t.close([]);
      const items = Array.isArray(coll) ? coll : coll instanceof Traversable && !(coll instanceof ResourceValue) ? (coll.entries() ?? []).map(([, v]) => v) : [coll];
      return t.close(items.map((item) => ev(expr.each, scope, item)));
    }
    case 'call':
      return callFunction(expr.name, expr.args, expr.expandFinal, scope, anon);
    case 'for':
      return evalFor(expr, scope, anon);
    // Operators and conditions work on the values behind sensitive operands; the result is sensitive.
    case 'unary': {
      const t = taint();
      const v = t.open(ev(expr.operand, scope, anon));
      if (isUnknown(v)) return derivedUnknown('operand not known', expr.op, [v]);
      return t.close(expr.op === '!' ? !toBool(v) : -toNumber(v));
    }
    case 'binary': {
      const t = taint();
      return t.close(evalBinary(expr.op, () => t.open(ev(expr.left, scope, anon)), () => t.open(ev(expr.right, scope, anon))));
    }
    case 'conditional': {
      const t = taint();
      const c = t.open(ev(expr.cond, scope, anon));
      if (isUnknown(c)) {
        const a = ev(expr.then, scope, anon);
        const b = ev(expr.else, scope, anon);
        return stableKey(a) === stableKey(b) ? t.close(a) : derivedUnknown('condition not known', '?:', [c, a, b]);
      }
      return t.close(toBool(c) ? ev(expr.then, scope, anon) : ev(expr.else, scope, anon));
    }
  }
}

/**
 * Reveal a sensitive operand for an operator, and mark its result sensitive if any operand was.
 * Only the operand itself is unwrapped: elements of a collection keep their own marks, as in
 * Terraform, so a map with one sensitive value is still a map with known keys.
 */
function taint() {
  let sensitive = false;
  return {
    open(v: unknown): unknown {
      if (!isRedacted(v) || !v.revealed) return v;
      sensitive = true;
      return v.revealed.value;
    },
    close(v: unknown): unknown {
      return sensitive ? redact(v) : v;
    },
    get sensitive() {
      return sensitive;
    },
  };
}

function keyString(k: unknown): string {
  if (typeof k === 'string') return k;
  if (typeof k === 'number' || typeof k === 'boolean') return String(k);
  throw new EvalError('object key must be a string');
}

/**
 * A value read from a known collection by a key not known statically (`configs[var.env]`): every key's
 * value, so reading through it keeps one value per key and its identity is made of those values only.
 * An edit elsewhere in the collection then changes nothing read through the lookup, while an attribute
 * whose value changes for any key still differs. Kept beside the value, never printed.
 */
interface Keyed {
  /** The identity of the key. */
  key: string;
  keyRefs: string[];
  candidates: Array<[string, unknown]>;
}
const KEYED = new WeakMap<Unknown, Keyed>();
/** Collections with more keys than this keep the identity of the whole collection. */
const MAX_KEYED = 64;

/** Reading from a key that holds no such attribute fails only where that key is the one selected. */
class KeyError {
  constructor(readonly message: string) {}
}

const candidateKey = (v: unknown) => (v instanceof KeyError ? `error:${v.message}` : keyOf(v));

function keyedUnknown(k: Omit<Keyed, 'candidates'>, candidates: Array<[string, unknown]>): Unknown {
  const refs = new Set(k.keyRefs);
  for (const [, v] of candidates) for (const u of flattenUnknowns(v)) for (const r of u.refs) refs.add(r);
  const u = withPath(new Unknown('index not known', undefined, [...refs].sort()), `[?${k.key}]{${candidates.map(([c, v]) => `${JSON.stringify(c)}:${candidateKey(v)}`).join(',')}}`);
  KEYED.set(u, { ...k, candidates });
  return u;
}

/** The keyed value read one step further on every key. */
function project(k: Keyed, step: (v: unknown) => unknown): Unknown {
  return keyedUnknown(
    k,
    k.candidates.map(([c, v]) => {
      if (v instanceof KeyError) return [c, v];
      try {
        return [c, step(v)];
      } catch (e) {
        if (e instanceof EvalError) return [c, new KeyError(e.message)];
        throw e;
      }
    })
  );
}

/** The entries of a known collection a key not known statically selects from, or undefined. */
function keyedEntries(obj: unknown): Array<[string, unknown]> | undefined {
  if (obj instanceof ResourceValue) return undefined;
  const entries = Array.isArray(obj)
    ? obj.map((v, i) => [String(i), v] as [string, unknown])
    : obj instanceof Traversable
      ? obj.entries()
      : obj && typeof obj === 'object' && !isRedacted(obj)
        ? Object.entries(obj as Record<string, unknown>)
        : undefined;
  return entries && entries.length <= MAX_KEYED ? entries : undefined;
}

/**
 * The keys whose value differs between two values read by a key not known statically, compared per key,
 * or undefined when neither holds such a value. Values read through different keys are not paired.
 */
export function keyedChanges(before: unknown, after: unknown): string[] | undefined {
  const keyed = (v: unknown) => flattenUnknowns(v).map((u) => KEYED.get(u)).filter((k): k is Keyed => k !== undefined);
  const b = keyed(before);
  const a = keyed(after);
  if (!b.length || !a.length) return undefined;
  const out = new Set<string>();
  const used = new Set<Keyed>();
  for (const x of a) {
    const y = b.find((k) => k.key === x.key && !used.has(k));
    if (!y) return undefined;
    used.add(y);
    const was = new Map(y.candidates.map(([c, v]) => [c, candidateKey(v)]));
    const now = new Map(x.candidates.map(([c, v]) => [c, candidateKey(v)]));
    for (const c of new Set([...was.keys(), ...now.keys()])) if (was.get(c) !== now.get(c)) out.add(c);
  }
  return [...out].sort();
}

export function getAttr(obj: unknown, name: string): unknown {
  if (isUnknown(obj) && KEYED.has(obj)) return project(KEYED.get(obj)!, (v) => getAttr(v, name));
  if (isUnknown(obj)) return withPath(new Unknown(obj.reason, obj.pattern === UNKNOWN_PART ? UNKNOWN_PART : undefined, obj.refs), `${PATHS.get(obj) ?? ''}.${name}`);
  if (isRedacted(obj)) return obj.revealed ? redact(getAttr(obj.revealed.value, name)) : obj;
  if (obj instanceof Traversable) return obj.getAttr(name);
  if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
    if (name in (obj as object)) return (obj as Record<string, unknown>)[name];
    throw new EvalError(`object has no attribute "${name}"`);
  }
  if (Array.isArray(obj) && /^\d+$/.test(name)) return getIndex(obj, Number(name));
  throw new EvalError(`cannot read attribute "${name}" of ${describe(obj)}`);
}

export function getIndex(obj: unknown, key: unknown): unknown {
  if (isUnknown(obj) && KEYED.has(obj)) return project(KEYED.get(obj)!, (v) => getIndex(v, key));
  if (isUnknown(obj)) {
    const k = isUnknown(key) ? `?${PATHS.get(key) ?? ''}` : stableKey(key);
    return withPath(new Unknown(obj.reason, obj.pattern === UNKNOWN_PART ? UNKNOWN_PART : undefined, obj.refs), `${PATHS.get(obj) ?? ''}[${k}]`);
  }
  if (isUnknown(key)) {
    const entries = keyedEntries(obj);
    if (entries) return keyedUnknown({ key: keyOf(key), keyRefs: [...key.refs] }, entries);
    return derivedUnknown('index not known', '[]', [obj, key]);
  }
  if (isRedacted(obj)) return obj.revealed ? redact(getIndex(obj.revealed.value, reveal(key))) : obj;
  if (isRedacted(key)) {
    if (!key.revealed) return unknownFrom('index not known');
    try {
      return redact(getIndex(obj, key.revealed.value));
    } catch (e) {
      // The error would print the key.
      if (e instanceof EvalError) throw new EvalError('no element for a sensitive index');
      throw e;
    }
  }
  if (obj instanceof Traversable) return obj.getIndex(key);
  if (Array.isArray(obj)) {
    const i = toNumber(key);
    if (i < 0 || i >= obj.length) throw new EvalError(`index ${i} out of range`);
    return obj[i];
  }
  if (obj && typeof obj === 'object') {
    const k = keyString(key);
    if (k in (obj as object)) return (obj as Record<string, unknown>)[k];
    throw new EvalError(`map has no key "${k}"`);
  }
  throw new EvalError(`cannot index ${describe(obj)}`);
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'a list';
  return typeof v;
}

function evalTemplate(parts: TemplatePart[], scope: EvalScope, anon: unknown): unknown {
  if (parts.length === 1 && parts[0].kind === 'interp') return ev(parts[0].expr, scope, anon);
  const acc: TemplateAcc = { text: '', unknown: false, sensitive: false, refs: new Set<string>() };
  appendParts(parts, scope, anon, acc);
  const path = acc.paths?.join(',');
  if (acc.unknown && acc.sensitive) return redact(withPath(new Unknown('template contains unknown values', acc.text, [...acc.refs]), path));
  if (acc.unknown) return withPath(new Unknown('template contains unknown values', acc.text, [...acc.refs]), path);
  return acc.sensitive ? redact(acc.text) : acc.text;
}

interface TemplateAcc {
  text: string;
  unknown: boolean;
  /** A sensitive value was interpolated: the result is sensitive too, as in Terraform. */
  sensitive: boolean;
  refs: Set<string>;
  /** Access paths of the unknown parts, so `x-${z.names[0]}` and `x-${z.names[1]}` differ. */
  paths?: string[];
}

function appendParts(parts: TemplatePart[], scope: EvalScope, anon: unknown, acc: TemplateAcc) {
  for (const p of parts) {
    if (p.kind === 'text') {
      acc.text += p.value;
    } else if (p.kind === 'interp') {
      appendValue(ev(p.expr, scope, anon), acc);
    } else if (p.kind === 'if') {
      // A sensitive condition picks its branch by value; the text it chose is sensitive.
      const t = taint();
      const c = t.open(ev(p.cond, scope, anon));
      if (t.sensitive) acc.sensitive = true;
      if (isUnknown(c)) {
        acc.unknown = true;
        acc.text += UNKNOWN_PART;
        (acc.paths ??= []).push(`%if(${keyOf(c)},${fingerprint(p.then)},${fingerprint(p.else)},${partsKey(p.then, scope, anon)},${partsKey(p.else, scope, anon)})`);
        continue;
      }
      appendParts(toBool(c) ? p.then : p.else, scope, anon, acc);
    } else {
      const t = taint();
      const coll = t.open(ev(p.coll, scope, anon));
      if (t.sensitive) acc.sensitive = true;
      if (isUnknown(coll)) {
        acc.unknown = true;
        acc.text += UNKNOWN_PART;
        const each = { [p.valVar]: new Unknown('element'), ...(p.keyVar ? { [p.keyVar]: new Unknown('key') } : {}) };
        (acc.paths ??= []).push(`%for(${keyOf(coll)},${fingerprint(p)},${partsKey(p.body, childScope(scope, each), anon)})`);
        continue;
      }
      for (const [k, v] of iterate(coll)) {
        const vars: Record<string, unknown> = { [p.valVar]: v };
        if (p.keyVar) vars[p.keyVar] = k;
        appendParts(p.body, childScope(scope, vars), anon, acc);
      }
    }
  }
}

function appendValue(v: unknown, acc: TemplateAcc) {
  if (isUnknown(v)) {
    acc.unknown = true;
    acc.text += v.pattern ?? UNKNOWN_PART;
    for (const r of v.refs) acc.refs.add(r);
    const path = PATHS.get(v);
    if (path) (acc.paths ??= []).push(path);
    return;
  }
  if (isRedacted(v)) {
    const r = v.revealed;
    if (!r) {
      acc.unknown = true;
      acc.text += UNKNOWN_PART;
      return;
    }
    acc.sensitive = true;
    appendValue(r.value, acc);
    return;
  }
  if (v === null || v === undefined) throw new EvalError('null value in template');
  // A partly unknown jsonencode() result is JSON text whose unknown parts are not known: its known parts
  // are kept, and its identity is the whole value, so an edit anywhere in it is a change.
  if (typeof v === 'object' && JSON_KEPT.has(v)) {
    acc.unknown = true;
    acc.text += jsonPattern(v, acc);
    (acc.paths ??= []).push(`jsonencode(${keyOf(v)})`);
    return;
  }
  if (typeof v === 'object') throw new EvalError('cannot interpolate a collection into a string');
  acc.text += String(v);
}

function iterate(coll: unknown): Array<[unknown, unknown]> {
  if (isRedacted(coll)) throw new EvalError('cannot iterate a sensitive value that is not available');
  if (isTfSet(coll)) return coll.map((v) => [v, v]);
  if (Array.isArray(coll)) return coll.map((v, i) => [i, v]);
  if (coll instanceof Traversable) {
    const e = coll.entries();
    if (!e) throw new EvalError('cannot iterate an object of unknown shape');
    return e;
  }
  if (coll && typeof coll === 'object') return Object.keys(coll).sort().map((k) => [k, (coll as Record<string, unknown>)[k]]);
  throw new EvalError(`cannot iterate ${describe(coll)}`);
}

function evalFor(expr: Extract<Expr, { kind: 'for' }>, scope: EvalScope, anon: unknown): unknown {
  // A for over a sensitive collection iterates its values; the result is sensitive, as in Terraform.
  const t = taint();
  return t.close(evalForOver(t.open(ev(expr.coll, scope, anon)), expr, scope, anon, t));
}

function evalForOver(coll: unknown, expr: Extract<Expr, { kind: 'for' }>, scope: EvalScope, anon: unknown, t: ReturnType<typeof taint>): unknown {
  // The body is part of the identity: [for s in x : "${s}-a"] and [... "${s}-b"] differ, and so do
  // bodies that read a changed local. The body is evaluated once with placeholder elements for that.
  const body = () => {
    const each = { [expr.valVar]: new Unknown('element'), ...(expr.keyVar ? { [expr.keyVar]: new Unknown('key') } : {}) };
    const s = childScope(scope, each);
    const parts = [expr.cond, expr.keyExpr, expr.valExpr].map((e) => (e ? safeKey(() => ev(e, s, anon)) : ''));
    return `${fingerprint({ ...expr, coll: undefined })}${parts.join('|')}`;
  };
  if (isUnknown(coll)) return derivedUnknown('for expression over an unknown collection', `for${body()}`, [coll]);
  const list: unknown[] = [];
  const obj: Record<string, unknown> = {};
  for (const [k, v] of iterate(coll)) {
    const vars: Record<string, unknown> = { [expr.valVar]: v };
    if (expr.keyVar) vars[expr.keyVar] = k;
    const s = childScope(scope, vars);
    if (expr.cond) {
      // A sensitive filter selects by value, and makes the result sensitive.
      const c = t.open(ev(expr.cond, s, anon));
      if (isUnknown(c)) return derivedUnknown('for condition not known', `for${body()}`, [coll, c]);
      if (!toBool(c)) continue;
    }
    if (expr.isObject) {
      const key = ev(expr.keyExpr!, s, anon);
      if (isUnknown(key)) return derivedUnknown('for key not known', `for${body()}`, [coll, key]);
      const ks = keyString(key);
      const val = ev(expr.valExpr, s, anon);
      if (expr.grouping) obj[ks] = [...((obj[ks] as unknown[]) ?? []), val];
      else obj[ks] = val;
    } else {
      list.push(ev(expr.valExpr, s, anon));
    }
  }
  return expr.isObject ? obj : list;
}

function evalBinary(op: string, left: () => unknown, right: () => unknown): unknown {
  if (op === '&&' || op === '||') {
    const a = left();
    if (!isUnknown(a)) {
      if (op === '&&' && !toBool(a)) return false;
      if (op === '||' && toBool(a)) return true;
      const b = right();
      return isUnknown(b) ? b : toBool(b);
    }
    const b = right();
    if (!isUnknown(b)) {
      if (op === '&&' && !toBool(b)) return false;
      if (op === '||' && toBool(b)) return true;
    }
    return derivedUnknown('operand not known', op, [a, b]);
  }
  const a = left();
  const b = right();
  if (isUnknown(a) || isUnknown(b)) return derivedUnknown('operand not known', op, [a, b]);
  switch (op) {
    case '==':
    case '!=': {
      const eq = equalValues(a, b);
      if (eq === 'unknown') return derivedUnknown('operand not known', op, [a, b]);
      return op === '==' ? eq : !eq;
    }
    case '+':
      return toNumber(a) + toNumber(b);
    case '-':
      return toNumber(a) - toNumber(b);
    case '*':
      return toNumber(a) * toNumber(b);
    case '/':
      return toNumber(a) / toNumber(b);
    case '%':
      return toNumber(a) % toNumber(b);
    case '<':
      return toNumber(a) < toNumber(b);
    case '>':
      return toNumber(a) > toNumber(b);
    case '<=':
      return toNumber(a) <= toNumber(b);
    case '>=':
      return toNumber(a) >= toNumber(b);
  }
  throw new EvalError(`unsupported operator ${op}`);
}

/**
 * Terraform equality on values: collections compare element by element. A part known on both sides
 * that differs makes them unequal, whatever else is unknown; otherwise an unknown part makes the result
 * unknown. Values of different types are unequal.
 */
function equalValues(x: unknown, y: unknown): boolean | 'unknown' {
  const a = reveal(toPlain(x));
  const b = reveal(toPlain(y));
  if (isUnknown(a) || isUnknown(b) || isRedacted(a) || isRedacted(b)) return 'unknown';
  // Sets compare by membership, not position.
  if (isTfSet(a) && isTfSet(b)) {
    if (a.length !== b.length) return false;
    return combine(
      a.map((x) => {
        const hits = b.map((y) => equalValues(x, y));
        return hits.includes(true) ? true : hits.includes('unknown') ? 'unknown' : false;
      })
    );
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return combine(a.map((v, i) => equalValues(v, b[i])));
  }
  const obj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object';
  if (obj(a) || obj(b)) {
    if (!obj(a) || !obj(b)) return false;
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    if (ka.join('\u0000') !== kb.join('\u0000')) return false;
    return combine(ka.map((k) => equalValues(a[k], b[k])));
  }
  return a === b;
}

function combine(parts: Array<boolean | 'unknown'>): boolean | 'unknown' {
  if (parts.includes(false)) return false;
  return parts.includes('unknown') ? 'unknown' : true;
}

export function toBool(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  throw new EvalError(`expected a bool, got ${describe(v)}`);
}

export function toNumber(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/.test(v) && Number.isFinite(Number(v))) return Number(v);
  throw new EvalError(`expected a number, got ${describe(v)}`);
}

function toStr(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  throw new EvalError(`expected a string, got ${describe(v)}`);
}

function toList(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (v instanceof Traversable) return (v.entries() ?? []).map(([, x]) => x);
  if (v && typeof v === 'object') return Object.keys(v).sort().map((k) => (v as Record<string, unknown>)[k]);
  throw new EvalError(`expected a list, got ${describe(v)}`);
}

function toMap(v: unknown): Record<string, unknown> {
  if (v instanceof Traversable) {
    const e = v.entries();
    if (!e) throw new EvalError('object of unknown shape');
    return Object.fromEntries(e);
  }
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  throw new EvalError(`expected a map, got ${describe(v)}`);
}

/** A deterministic string key for comparing values; Unknowns compare by what they were derived from. */
export function stableKey(v: unknown): string {
  return JSON.stringify(canonical(v));
}

// Built by hand: JSON.stringify calls toJSON() before any replacer, which would hide an Unknown's refs.
function canonical(x: unknown): unknown {
  if (isUnknown(x)) {
    const identity = x.pattern === undefined && !x.refs.length ? x.reason : '';
    return `\u0000unknown:${x.pattern ?? ''}:${[...x.refs].sort().join(',')}:${PATHS.get(x) ?? ''}:${identity}`;
  }
  if (isRedacted(x)) return `\u0000sensitive:${x.digest ?? ''}`;
  if (x instanceof ResourceValue) return `\u0000resource:${x.address}`;
  if (x instanceof Traversable) return canonical(x.toPlain());
  if (Array.isArray(x)) return x.map(canonical);
  if (x && typeof x === 'object') {
    return Object.fromEntries(Object.keys(x).sort().map((k) => [k, canonical((x as Record<string, unknown>)[k])]));
  }
  return x;
}

export function containsUnknown(v: unknown): boolean {
  if (isUnknown(v) || isRedacted(v)) return true;
  if (Array.isArray(v)) return v.some(containsUnknown);
  if (v instanceof Traversable) return true;
  if (v && typeof v === 'object') return Object.values(v).some(containsUnknown);
  return false;
}

/** Deep-convert Traversables to plain values. */
export function toPlain(v: unknown): unknown {
  if (v instanceof Traversable) return v instanceof ResourceValue ? new Unknown(`${v.address}`, UNKNOWN_PART, [v.address]) : toPlain(v.toPlain());
  if (Array.isArray(v)) return isTfSet(v) ? markSet(v.map(toPlain)) : v.map(toPlain);
  if (v && typeof v === 'object' && !isUnknown(v) && !isRedacted(v)) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toPlain(x)]));
  }
  return v;
}

// ---------------------------------------------------------------- functions

type Fn = (args: unknown[]) => unknown;

/** Functions whose result is unknown whenever any argument contains an unknown value. */
const STRICT: Record<string, Fn> = {
  lower: ([s]) => toStr(s).toLowerCase(),
  upper: ([s]) => toStr(s).toUpperCase(),
  title: ([s]) => toStr(s).replace(/\b\w/g, (c) => c.toUpperCase()),
  trimspace: ([s]) => toStr(s).trim(),
  trim: ([s, c]) => {
    const chars = new Set(toStr(c));
    let str = toStr(s);
    while (str && chars.has(str[0])) str = str.slice(1);
    while (str && chars.has(str[str.length - 1])) str = str.slice(0, -1);
    return str;
  },
  trimprefix: ([s, p]) => (toStr(s).startsWith(toStr(p)) ? toStr(s).slice(toStr(p).length) : toStr(s)),
  trimsuffix: ([s, p]) => (toStr(s).endsWith(toStr(p)) ? toStr(s).slice(0, toStr(s).length - toStr(p).length) : toStr(s)),
  chomp: ([s]) => toStr(s).replace(/(\r?\n)+$/, ''),
  startswith: ([s, p]) => toStr(s).startsWith(toStr(p)),
  endswith: ([s, p]) => toStr(s).endsWith(toStr(p)),
  strcontains: ([s, p]) => toStr(s).includes(toStr(p)),
  strrev: ([s]) => [...toStr(s)].reverse().join(''),
  substr: ([s, o, l]) => {
    const str = toStr(s);
    const off = toNumber(o);
    const len = toNumber(l);
    return str.substr(off < 0 ? str.length + off : off, len < 0 ? undefined : len);
  },
  replace: ([s, search, rep]) => {
    const str = toStr(s);
    const pat = toStr(search);
    if (pat.length > 1 && pat.startsWith('/') && pat.endsWith('/')) {
      return str.replace(re2(pat.slice(1, -1), 'g'), toStr(rep).replace(/\$\{(\d+)\}/g, '$$$1'));
    }
    return str.split(pat).join(toStr(rep));
  },
  split: ([sep, s]) => toStr(s).split(toStr(sep)),
  join: ([sep, ...lists]) => lists.flatMap(toList).map(toStr).join(toStr(sep)),
  format: ([f, ...rest]) => formatOrUnknown('format', toStr(f), rest),
  formatlist: ([f, ...rest]) => {
    // With list arguments, all must have one length and the result has that many elements (none for
    // empty lists); with none, the result is a single string.
    const lengths = [...new Set(rest.filter(Array.isArray).map((l) => (l as unknown[]).length))];
    if (lengths.length > 1) throw new EvalError('formatlist(): lists of different lengths');
    const n = lengths.length ? lengths[0] : 1;
    const out = Array.from({ length: n }, (_, i) => formatOrUnknown('formatlist', toStr(f), rest.map((r) => (Array.isArray(r) ? r[i] : r))));
    return out.some(isUnknown) ? derivedUnknown('formatlist() with a verb that is not evaluated', 'formatlist', [f, ...rest]) : out;
  },
  indent: ([n, s]) => toStr(s).split('\n').map((l, i) => (i === 0 ? l : ' '.repeat(toNumber(n)) + l)).join('\n'),
  length: ([v]) => (typeof v === 'string' ? [...v].length : toList(v).length),
  concat: (lists) => lists.flatMap(toList),
  flatten: ([l]) => {
    const flat = (x: unknown[]): unknown[] => x.flatMap((i) => (Array.isArray(i) ? flat(i) : [i]));
    return flat(toList(l));
  },
  distinct: ([l]) => dedupe(unifyCollection(toList(l))),
  toset: ([l]) => l === null ? null : markSet(dedupe(unifyCollection(toList(l))).sort(compareSetItems)),
  tolist: ([l]) => l === null ? null : unifyCollection(toList(l)),
  tomap: ([m]) => {
    if (m === null) return null;
    const map = toMap(m), keys = Object.keys(map);
    const values = unifyCollection(keys.map((k) => map[k]));
    return Object.fromEntries(keys.map((k, i) => [k, values[i]]));
  },
  tostring: ([s]) => (s === null ? null : toStr(s)),
  tonumber: ([n]) => (n === null ? null : toNumber(n)),
  tobool: ([b]) => (b === null ? null : toBool(b)),
  compact: ([l]) => toList(l).filter((x) => x !== null && x !== ''),
  keys: ([m]) => Object.keys(toMap(m)).sort(),
  values: ([m]) => Object.keys(toMap(m)).sort().map((k) => toMap(m)[k]),
  contains: ([l, v]) => toList(l).some((x) => stableKey(x) === stableKey(v)),
  element: ([l, i]) => {
    const list = toList(l);
    if (!list.length) throw new EvalError('element() on an empty list');
    const index = toNumber(i);
    if (!Number.isInteger(index)) throw new EvalError('element(): index must be a whole number');
    return list[((index % list.length) + list.length) % list.length];
  },
  index: ([l, v]) => {
    const i = toList(l).findIndex((x) => stableKey(x) === stableKey(v));
    if (i < 0) throw new EvalError('index(): value not found');
    return i;
  },
  slice: ([l, a, b]) => toList(l).slice(toNumber(a), toNumber(b)),
  reverse: ([l]) => [...toList(l)].reverse(),
  sort: ([l]) => toList(l).map(toStr).sort(),
  merge: (maps) => Object.assign({}, ...maps.filter((m) => m !== null).map(toMap)),
  zipmap: ([k, v]) => Object.fromEntries(toList(k).map((key, i) => [toStr(key), toList(v)[i]])),
  setunion: (sets) => markSet(dedupe(unifyCollection(sets.flatMap(toList))).sort(compareSetItems)),
  setintersection: ([first, ...rest]) => markSet(toList(first).filter((x) => rest.every((r) => toList(r).some((y) => stableKey(x) === stableKey(y))))),
  setsubtract: ([a, b]) => markSet(toList(a).filter((x) => !toList(b).some((y) => stableKey(x) === stableKey(y)))),
  // As go-cty: the size is a whole number, never negative; 0 returns the list as one chunk.
  chunklist: ([l, n]) => {
    const list = toList(l);
    const size = toNumber(n);
    if (!Number.isInteger(size)) throw new EvalError('chunklist(): invalid size: value must be a whole number');
    if (size < 0) throw new EvalError('chunklist(): the size argument must be positive');
    if (!list.length) return [];
    if (size === 0) return [list];
    const out: unknown[][] = [];
    for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
    return out;
  },
  // As go-cty's RangeFunc: the default step counts down when end is below start, a zero step is an
  // error, a step in the wrong direction is an error, and more than 1024 values is an error.
  range: (args) => {
    const [start, end] = args.length === 1 ? [0, toNumber(args[0])] : [toNumber(args[0]), toNumber(args[1])];
    const step = args.length > 2 ? toNumber(args[2]) : end < start ? -1 : 1;
    if (step === 0 || Number.isNaN(step)) throw new EvalError('range(): step must not be zero');
    if ((step < 0 && end > start) || (step > 0 && end < start)) throw new EvalError('range(): step must move toward the end');
    const out: number[] = [];
    for (let i = start; step > 0 ? i < end : i > end; i += step) {
      if (out.length === 1024) throw new EvalError('range(): more than 1024 values were generated; decrease the difference between start and end or use a larger step');
      out.push(i);
    }
    return out;
  },
  one: ([l]) => {
    const list = toList(l);
    if (list.length > 1) throw new EvalError('one() on a list with more than one element');
    return list.length ? list[0] : null;
  },
  sum: ([l]) => toList(l).reduce((s: number, x) => s + toNumber(x), 0),
  min: (ns) => Math.min(...ns.map(toNumber)),
  max: (ns) => Math.max(...ns.map(toNumber)),
  abs: ([n]) => Math.abs(toNumber(n)),
  ceil: ([n]) => Math.ceil(toNumber(n)),
  floor: ([n]) => Math.floor(toNumber(n)),
  signum: ([n]) => Math.sign(toNumber(n)),
  pow: ([a, b]) => toNumber(a) ** toNumber(b),
  parseint: ([s, b]) => parseInt(toStr(s), toNumber(b)),
  alltrue: ([l]) => toList(l).every(toBool),
  anytrue: ([l]) => toList(l).some(toBool),
  jsondecode: ([s]) => {
    try {
      return JSON.parse(toStr(s));
    } catch {
      throw new EvalError('jsondecode(): invalid JSON');
    }
  },
  yamldecode: () => new Unknown('yamldecode is not evaluated'),
  base64encode: ([s]) => Buffer.from(toStr(s)).toString('base64'),
  base64decode: ([s]) => Buffer.from(toStr(s), 'base64').toString('utf8'),
  urlencode: ([s]) => encodeURIComponent(toStr(s)),
  basename: ([s]) => toStr(s).split('/').pop() ?? '',
  dirname: ([s]) => toStr(s).split('/').slice(0, -1).join('/') || '.',
  abspath: ([s]) => toStr(s),
  transpose: ([m]) => {
    const out: Record<string, string[]> = {};
    for (const [k, vs] of Object.entries(toMap(m))) for (const v of toList(vs)) (out[toStr(v)] ??= []).push(k);
    return out;
  },
  regex: ([p, s]) => {
    const m = toStr(s).match(re2(toStr(p)));
    if (!m) throw new EvalError('regex(): no match');
    if (m.groups) return Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, v ?? null]));
    return m.length > 1 ? m.slice(1).map((v) => v ?? null) : m[0];
  },
  // Like regex(): named captures give a map per match.
  regexall: ([p, s]) => [...toStr(s).matchAll(re2(toStr(p), 'g'))].map((m) => (m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, v ?? null])) : m.length > 1 ? m.slice(1).map((v) => v ?? null) : m[0])),
  cidrsubnet: ([prefix, newbits, netnum]) => cidrSubnet(toStr(prefix), toNumber(newbits), toNumber(netnum)),
};

const STRUCTURAL = new Set([
  'merge', 'length', 'keys', 'values', 'tolist', 'toset', 'tomap', 'flatten', 'distinct', 'compact', 'zipmap',
  'slice', 'reverse', 'setunion', 'chunklist', 'one', 'element', 'concat',
]);

/** Functions of a file's content: the read is tracked, the value stays unknown. */
const FILE_HASHES = new Set(['filebase64', 'filemd5', 'filesha1', 'filesha256', 'filesha512', 'filebase64sha256', 'filebase64sha512']);

/** Functions that cannot be evaluated offline. */
const ALWAYS_UNKNOWN = new Set([
  'file', 'filebase64', 'fileexists', 'fileset', 'templatefile', 'filemd5', 'filesha1', 'filesha256', 'filesha512', 'filebase64sha256', 'filebase64sha512',
  'timestamp', 'plantimestamp', 'uuid', 'uuidv5', 'bcrypt', 'md5', 'sha1', 'sha256', 'sha512', 'base64sha256', 'base64sha512', 'rsadecrypt',
  'timeadd', 'formatdate', 'cidrhost', 'cidrnetmask', 'cidrsubnets', 'textencodebase64', 'textdecodebase64', 'base64gzip', 'yamlencode', 'pathexpand',
]);

function callFunction(rawName: string, argExprs: Expr[], expandFinal: boolean, scope: EvalScope, anon: unknown): unknown {
  const name = rawName.replace(/^provider::[^:]+::/, '');
  // try/can/coalesce and structural functions must not hide an invalid dependency. Keep
  // this check before their normal simplifications, and include every function argument.
  if (scope.configurationEvidence) {
    const values = argExprs.map((arg) => {
      try { return ev(arg, scope, anon); }
      catch (error) {
        if (error instanceof EvalError) return new Unknown('configuration argument could not be resolved');
        throw error;
      }
    });
    if (!values.every((v) => knownConfiguration(toPlain(v)))) return derivedUnknown('configuration function argument is null or unknown', name, values);
  }
  if (name === 'try') {
    for (const a of argExprs) {
      try {
        const v = ev(a, scope, anon);
        if (isUnknown(v) && v.reason.startsWith('error:')) continue;
        return v;
      } catch (e) {
        if (!(e instanceof EvalError)) throw e;
      }
    }
    throw new EvalError('try(): no argument succeeded');
  }
  if (name === 'can') {
    try {
      const v = ev(argExprs[0], scope, anon);
      return isUnknown(v) ? (v.reason.startsWith('error:') ? false : v) : true;
    } catch (e) {
      if (e instanceof EvalError) return false;
      throw e;
    }
  }

  let args = argExprs.map((a) => ev(a, scope, anon));
  if (expandFinal && args.length) {
    const last = args[args.length - 1];
    if (isUnknown(last)) return unknownFrom('expanded argument not known', last);
    args = [...args.slice(0, -1), ...toList(last)];
  }
  if (name === 'sensitive') return redact(args[0]);
  if (name === 'nonsensitive') {
    const a = args[0];
    return isRedacted(a) ? (a.revealed ? a.revealed.value : new Unknown('nonsensitive() of a value Diffseal cannot see')) : a;
  }
  // A function of a sensitive value is sensitive, as in Terraform: compute on the value, hide the result.
  // ALWAYS_UNKNOWN functions are skipped because their reason prints the arguments.
  if (!ALWAYS_UNKNOWN.has(name) && args.some(hasRedacted)) {
    const revealed = args.map(reveal);
    if (!revealed.some(hasRedacted)) {
      let out: unknown;
      try {
        out = applyFunction(name, rawName, revealed, scope);
      } catch (e) {
        if (e instanceof EvalError) throw new EvalError(`${rawName}() failed on a sensitive value`);
        throw e;
      }
      return redact(out);
    }
  }
  return applyFunction(name, rawName, args, scope);
}

/** Terraform JSON sorts every object's keys, including integer-looking keys, and
 * escapes HTML characters and Unicode line separators. Construct objects as text
 * because JavaScript reorders integer keys even after sorting an object's entries.
 */
/** Partly unknown jsonencode() results kept as structure: a template interpolates them as JSON text. */
const JSON_KEPT = new WeakSet<object>();

/**
 * The JSON text of a partly unknown jsonencode() result, with `{?}` for each unknown part (a string
 * built from a template keeps its known text). A sensitive part is never written: it is `{?}` too.
 */
function jsonPattern(value: unknown, acc: TemplateAcc): string {
  const encode = (v: unknown): string => {
    if (isUnknown(v)) {
      for (const r of v.refs) acc.refs.add(r);
      return v.pattern !== undefined && v.pattern !== UNKNOWN_PART ? JSON.stringify(v.pattern) : UNKNOWN_PART;
    }
    if (isRedacted(v)) {
      acc.sensitive = true;
      return UNKNOWN_PART;
    }
    if (Array.isArray(v)) return `[${v.map(encode).join(',')}]`;
    if (v && typeof v === 'object') {
      return `{${Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
        .map((k) => `${JSON.stringify(k)}:${encode((v as Record<string, unknown>)[k])}`).join(',')}}`;
    }
    return JSON.stringify(v);
  };
  return encode(value);
}

function terraformJson(value: unknown): string {
  const encode = (v: unknown): string => {
    if (Array.isArray(v)) return `[${v.map(encode).join(',')}]`;
    if (v && typeof v === 'object') {
      return `{${Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
        .map((k) => `${JSON.stringify(k)}:${encode((v as Record<string, unknown>)[k])}`).join(',')}}`;
    }
    return JSON.stringify(v);
  };
  const escapes: Record<string, string> = { '<': '\\u003c', '>': '\\u003e', '&': '\\u0026', '\u2028': '\\u2028', '\u2029': '\\u2029' };
  return encode(value).replace(/[<>&\u2028\u2029]/g, (c) => escapes[c]);
}

function applyFunction(name: string, rawName: string, args: unknown[], scope: EvalScope): unknown {
  if (name === 'type') return new Unknown('type() is not evaluated');
  if (name === 'jsonencode') {
    const plain = toPlain(args[0]);
    // Keep structure when parts are unknown: policy documents are analyzed as objects either way.
    if (!containsUnknown(plain)) return terraformJson(plain);
    if (plain !== null && typeof plain === 'object' && !isUnknown(plain) && !isRedacted(plain)) JSON_KEPT.add(plain);
    return plain;
  }
  if (name === 'coalesce') {
    for (const a of args) {
      if (isUnknown(a)) return derivedUnknown('coalesce() argument not known', 'coalesce', args);
      if (a !== null && a !== '') return a;
    }
    throw new EvalError('coalesce(): all arguments are null or empty');
  }
  if (name === 'coalescelist') {
    for (const a of args) {
      if (isUnknown(a)) return derivedUnknown('coalescelist() argument not known', 'coalescelist', args);
      if (toList(a).length) return a;
    }
    throw new EvalError('coalescelist(): all lists are empty');
  }
  if (name === 'lookup') {
    const [m, k, def] = args;
    if (!isUnknown(m) && isUnknown(k)) {
      // Each key's value, and the default for a key the map does not hold.
      const entries = keyedEntries(m);
      if (entries) return keyedUnknown({ key: keyOf(k), keyRefs: [...k.refs] }, args.length > 2 ? [...entries, ['\u0000default', def]] : entries);
    }
    if (isUnknown(m) || isUnknown(k)) return derivedUnknown('lookup() argument not known', 'lookup', args);
    const map = toMap(m);
    const key = toStr(k);
    if (key in map) return map[key];
    if (args.length > 2) return def;
    throw new EvalError(`lookup(): no key "${key}"`);
  }
  if (name === 'concat' && args.some(isUnknown)) {
    return derivedUnknown('concat() of an unknown list', 'concat', args);
  }
  if (name === 'concat') {
    return args.flatMap(toList);
  }
  if ((name === 'file' || name === 'fileexists' || name === 'templatefile') && scope.readFile) {
    const p = args[0];
    if (typeof p !== 'string') return unknownFrom(`${name}() of an unknown path`, p);
    const content = scope.readFile(p);
    if (name === 'fileexists') return content !== undefined;
    if (content === undefined) return new Unknown(`${name}(${p}): file not found in this snapshot`);
    if (name === 'file') return content;
    return renderTemplateFile(content, args[1], scope);
  }
  if (FILE_HASHES.has(name) && scope.readFile) {
    const p = args[0];
    if (typeof p !== 'string') return unknownFrom(`${name}() of an unknown path`, p);
    const content = scope.readFile(p);
    if (content === undefined) return new Unknown(`${name}(${p}): file not found in this snapshot`);
    // Not computed (snapshots are read as text), but the keyed digest changes when the file does.
    return new Unknown(`${name}(${p}) of content ${keyedDigest(content)} is not evaluated offline`);
  }
  // The reason carries the arguments, so a changed argument changes the value's identity.
  if (ALWAYS_UNKNOWN.has(name)) return derivedUnknown(`${name}() is not evaluated offline`, name, args);
  const fn = STRICT[name];
  // The identity carries the arguments, so changing one is still a change.
  if (!fn) return derivedUnknown(`function ${rawName}() is not supported`, name, args);
  // Structural functions only need the shape of their arguments: unknown elements or values pass through.
  const unknownArgs = STRUCTURAL.has(name) ? args.some((a) => isUnknown(a) || isRedacted(a)) : args.some(containsUnknownShallow);
  if (unknownArgs) return derivedUnknown(`${name}() of unknown value`, name, args);
  return fn(args.map((a) => (a instanceof Traversable ? a : a)));
}

function containsUnknownShallow(v: unknown): boolean {
  if (isUnknown(v) || isRedacted(v)) return true;
  if (Array.isArray(v)) return v.some(containsUnknownShallow);
  if (v && typeof v === 'object' && !(v instanceof Traversable)) return Object.values(v).some(containsUnknownShallow);
  return false;
}

function flattenUnknowns(v: unknown): Unknown[] {
  if (isUnknown(v)) return [v];
  if (Array.isArray(v)) return v.flatMap(flattenUnknowns);
  if (v && typeof v === 'object' && !(v instanceof Traversable) && !(v instanceof Redacted)) return Object.values(v).flatMap(flattenUnknowns);
  return [];
}

/** Terraform regexes are RE2: translate named groups and leading inline flags; anything else invalid is an EvalError. */
export function re2(pattern: string, flags = ''): RegExp {
  // JavaScript accepts lookaround and backreferences; RE2 rejects them.
  if (/\(\?(?:[=!]|<[=!])|\\[1-9]/.test(pattern)) throw new EvalError('regular expression uses a construct unsupported by RE2');
  const classes: Record<string, string> = { alpha: 'A-Za-z', alnum: '0-9A-Za-z', digit: '0-9', lower: 'a-z', upper: 'A-Z', xdigit: '0-9A-Fa-f', word: '0-9A-Za-z_', space: '\\t\\n\\v\\f\\r ', blank: '\\t ', ascii: '\\x00-\\x7f', cntrl: '\\x00-\\x1f\\x7f', graph: '!-~', print: ' -~', punct: '!-/:-@[-`{-~' };
  pattern = pattern.replace(/\[:([a-z]+):\]/g, (match, name) => classes[name] ?? match);
  if (!flags.includes('u')) flags += 'u';

  let p = pattern.replace(/\(\?P</g, '(?<');
  const lead = p.match(/^\(\?([imsU]+)\)/);
  if (lead) {
    p = p.slice(lead[0].length);
    for (const f of lead[1]) if ('ims'.includes(f) && !flags.includes(f)) flags += f;
  }
  try {
    return new RegExp(p, flags);
  } catch {
    throw new EvalError(`invalid or unsupported regular expression "${pattern}"`);
  }
}

/** cty unifies collection element types before conversion and set operations.
 * A string element allows primitive numbers/bools to convert to strings. Nulls
 * and unknown elements keep their value while known elements determine the type.
 */
function unifyCollection(values: unknown[]): unknown[] {
  const known = values.filter((v) => v !== null && !isUnknown(v));
  const types = new Set(known.map((v) => Array.isArray(v) ? 'list' : typeof v));
  if (types.has('string') && [...types].every((t) => ['string', 'number', 'boolean'].includes(t))) {
    return values.map((v) => v === null || isUnknown(v) ? v : toStr(v));
  }
  if (types.size > 1) throw new EvalError('collection elements must have a common type');
  return [...values];
}

function dedupe(l: unknown[]): unknown[] {
  const seen = new Set<string>();
  return l.filter((x) => {
    const k = stableKey(x);
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

function compareSetItems(a: unknown, b: unknown): number {
  if (typeof a === 'string' && typeof b === 'string') return a < b ? -1 : a > b ? 1 : 0;
  return 0;
}

/** A format Diffseal cannot render exactly; the value is then unknown, never a wrong string. */
class UnsupportedFormat extends Error {}

function formatOrUnknown(name: string, f: string, args: unknown[]): unknown {
  try {
    return formatString(f, args);
  } catch (e) {
    if (e instanceof UnsupportedFormat) return derivedUnknown(`${name}() with a verb that is not evaluated`, name, [f, ...args]);
    throw e;
  }
}

/**
 * Terraform's format(): Go fmt verbs with flags (`-+# 0`), width and precision. Explicit argument
 * indexes (`%[2]s`) and `*` widths are not evaluated.
 */
function formatString(f: string, args: unknown[]): string {
  let i = 0;
  let out = '';
  let pos = 0;
  const re = /%([-+# 0]*)(\d+)?(?:\.(\d*))?([a-zA-Z%[*])/g;
  for (let m = re.exec(f); m; m = re.exec(f)) {
    out += f.slice(pos, m.index);
    pos = m.index + m[0].length;
    const [, flags, w, p, verb] = m;
    if (verb === '%') {
      out += '%';
      continue;
    }
    if (verb === '[' || verb === '*') throw new UnsupportedFormat();
    if (i >= args.length) throw new EvalError('format(): not enough arguments');
    out += pad(formatVerb(verb, flags, p === undefined ? undefined : Number(p || 0), args[i++]), flags, w === undefined ? 0 : Number(w), 'dbxXoeEfFgG'.includes(verb));
  }
  if (i < args.length) throw new EvalError('format(): too many arguments');
  return out + f.slice(pos);
}

function pad(s: string, flags: string, width: number, numeric: boolean): string {
  const n = [...s].length;
  if (n >= width) return s;
  if (flags.includes('-')) return s + ' '.repeat(width - n);
  if (flags.includes('0') && numeric) {
    // Zeros go after the sign and after a 0x prefix.
    const lead = s.match(/^([+\- ]?(?:0[xXbo])?)/)![1];
    return lead + '0'.repeat(width - n) + s.slice(lead.length);
  }
  return ' '.repeat(width - n) + s;
}

function formatVerb(verb: string, flags: string, prec: number | undefined, a: unknown): string {
  const sign = (n: number, body: string) => (n < 0 || Object.is(n, -0) ? '-' : flags.includes('+') ? '+' : flags.includes(' ') ? ' ' : '') + body;
  const integer = () => {
    const n = toNumber(a);
    if (!Number.isInteger(n)) throw new EvalError(`format(): %${verb} needs a whole number`);
    return n;
  };
  switch (verb) {
    case 'v':
      if (flags.includes('#') || (a !== null && typeof a === 'object')) return JSON.stringify(toPlain(a));
      return typeof a === 'number' ? String(a) : toStr(a);
    case 's':
    case 'q': {
      if (a !== null && typeof a === 'object') throw new UnsupportedFormat();
      let s = typeof a === 'number' ? String(a) : toStr(a);
      if (prec !== undefined) s = [...s].slice(0, prec).join('');
      return verb === 'q' ? JSON.stringify(s) : s;
    }
    case 't':
      if (typeof a !== 'boolean') throw new EvalError('format(): %t needs a bool');
      return String(a);
    case 'd': {
      const n = integer();
      return sign(n, String(Math.abs(n)));
    }
    case 'b':
    case 'o':
    case 'x':
    case 'X': {
      if (typeof a === 'string' && Number.isNaN(Number(a))) throw new UnsupportedFormat();
      const n = integer();
      const radix = verb === 'b' ? 2 : verb === 'o' ? 8 : 16;
      let digits = Math.abs(n).toString(radix);
      if (verb === 'X') digits = digits.toUpperCase();
      const prefix = flags.includes('#') ? (verb === 'o' ? '0' : verb === 'b' ? '0b' : verb === 'x' ? '0x' : '0X') : '';
      return sign(n, prefix + digits);
    }
    case 'e':
    case 'E': {
      const n = toNumber(a);
      const s = goExponent(Math.abs(n).toExponential(prec ?? 6));
      return sign(n, verb === 'E' ? s.toUpperCase() : s);
    }
    case 'f':
    case 'F': {
      const n = toNumber(a);
      return sign(n, terraformFixed(Math.abs(n), prec ?? 6));
    }
    case 'g':
    case 'G': {
      const n = toNumber(a);
      const s = goG(Math.abs(n), prec);
      return sign(n, verb === 'G' ? s.toUpperCase() : s);
    }
  }
  throw new UnsupportedFormat();
}

/** Round decimal input through cty's 512-bit binary significand before fixed
 * formatting. Binary64 toFixed rounds some decimal ties differently (1.235).
 * The evaluator still uses JS numbers for arithmetic; this does not introduce
 * arbitrary-precision numeric values into the rest of the language.
 */
function terraformFixed(value: number, precision: number): string {
  if (!Number.isFinite(value) || precision < 0 || precision > 1000) throw new EvalError('format(): invalid numeric precision');
  const round = (n: bigint, d: bigint): bigint => {
    const q = n / d, twice = (n % d) * 2n;
    return q + (twice > d || (twice === d && (q & 1n) === 1n) ? 1n : 0n);
  };
  const [mantissa, exponent = '0'] = String(value).split('e');
  const fraction = mantissa.split('.')[1]?.length ?? 0;
  const scale = Number(exponent) - fraction;
  let n = BigInt(mantissa.replace('.', '')), d = 1n;
  if (scale >= 0) n *= 10n ** BigInt(scale); else d = 10n ** BigInt(-scale);
  if (n !== 0n) {
    let binaryExponent = n.toString(2).length - d.toString(2).length;
    if (binaryExponent >= 0 ? n < (d << BigInt(binaryExponent)) : (n << BigInt(-binaryExponent)) < d) binaryExponent--;
    const shift = 511 - binaryExponent;
    const significand = shift >= 0 ? round(n << BigInt(shift), d) : round(n, d << BigInt(-shift));
    n = shift >= 0 ? significand : significand << BigInt(-shift);
    d = shift >= 0 ? 1n << BigInt(shift) : 1n;
  }
  const digits = round(n * 10n ** BigInt(precision), d).toString().padStart(precision + 1, '0');
  return precision ? digits.slice(0, -precision) + '.' + digits.slice(-precision) : digits;
}

/** JavaScript writes e+3, Go e+03. */
function goExponent(s: string): string {
  return s.replace(/e([+-])(\d)$/, 'e$10$2');
}

/**
 * Go's %g (strconv 'g'): the shortest digits, or `prec` significant digits, written with an exponent
 * when the exponent is below -4 or at least the precision (6 for the shortest form).
 */
function goG(n: number, prec: number | undefined): string {
  if (n === 0) return '0';
  const p = prec === undefined ? undefined : Math.max(prec, 1);
  const [mant, e] = (p === undefined ? n.toExponential() : n.toExponential(p - 1)).split('e');
  const digits = mant.replace('.', '').replace(/0+$/, '') || '0';
  const exp = Number(e);
  let eprec = p ?? 6;
  if (p !== undefined && eprec > digits.length && digits.length >= exp + 1) eprec = digits.length;
  if (exp < -4 || exp >= eprec) {
    return `${digits[0]}${digits.length > 1 ? `.${digits.slice(1)}` : ''}e${exp < 0 ? '-' : '+'}${String(Math.abs(exp)).padStart(2, '0')}`;
  }
  if (exp < 0) return `0.${'0'.repeat(-exp - 1)}${digits}`;
  const whole = digits.slice(0, exp + 1).padEnd(exp + 1, '0');
  const frac = digits.slice(exp + 1);
  return frac ? `${whole}.${frac}` : whole;
}

function cidrSubnet(prefix: string, newbits: number, netnum: number): string {
  const [ip, prefixText, extra] = prefix.split('/');
  const oldLength = Number(prefixText);
  const ipv4 = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
  const bits = ipv4 ? 32 : 128;
  if (extra !== undefined || prefixText === undefined || !/^\d+$/.test(prefixText) ||
      !Number.isInteger(oldLength) || oldLength < 0 || oldLength > bits ||
      !Number.isInteger(newbits) || !Number.isSafeInteger(netnum) || netnum < 0) {
    throw new EvalError('cidrsubnet(): invalid prefix, newbits or netnum');
  }
  const length = oldLength + newbits;
  if (length < 0 || length > bits || (newbits >= 0 ? BigInt(netnum) >= (1n << BigInt(newbits)) : netnum !== 0)) {
    throw new EvalError('cidrsubnet(): prefix too long or netnum does not fit');
  }
  let address: bigint;
  if (ipv4) {
    const octets = ip.split('.').map(Number);
    if (octets.some((n) => n > 255)) throw new EvalError('cidrsubnet(): invalid IPv4 prefix');
    address = octets.reduce((n, octet) => (n << 8n) | BigInt(octet), 0n);
  } else {
    if (isIP(ip) !== 6) throw new EvalError('cidrsubnet(): invalid IPv6 prefix');
    let text = ip;
    if (text.includes('.')) {
      const at = text.lastIndexOf(':');
      const v4 = text.slice(at + 1).split('.').map(Number);
      text = text.slice(0, at + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
    }
    const [left, right] = text.split('::');
    const a = left ? left.split(':') : [];
    const b = right ? right.split(':') : [];
    const groups = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b];
    address = groups.reduce((n, group) => (n << 16n) | BigInt('0x' + group), 0n);
  }
  // Discard host bits before adding the requested subnet number.
  const oldHost = BigInt(bits - oldLength), host = BigInt(bits - length);
  const base = (address >> oldHost) << oldHost;
  const subnet = ((base >> host) << host) + (BigInt(netnum) << host);
  if (ipv4) return `${[24n, 16n, 8n, 0n].map((shift) => Number((subnet >> shift) & 255n)).join('.')}/${length}`;
  const groups = Array.from({ length: 8 }, (_, i) => Number((subnet >> BigInt((7 - i) * 16)) & 65535n).toString(16));
  let start = -1, size = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') { i++; continue; }
    let end = i; while (end < 8 && groups[end] === '0') end++;
    if (end - i > size) { start = i; size = end - i; } i = end;
  }
  const rendered = start < 0 ? groups.join(':') : groups.slice(0, start).join(':') + '::' + groups.slice(start + size).join(':');
  return `${rendered}/${length}`;
}

const TEMPLATE_DELIMITER = '__DIFFSEAL_TEMPLATE_END__';

/** templatefile(): parse the file as an HCL template and evaluate it with only the given variables. */
function renderTemplateFile(content: string, vars: unknown, scope: EvalScope): unknown {
  if (isUnknown(vars)) return unknownFrom('templatefile() with unknown variables', vars);
  const bindings = vars && typeof vars === 'object' && !Array.isArray(vars) ? (vars as Record<string, unknown>) : {};
  const { body, diagnostics } = parseHcl(`t = <<${TEMPLATE_DELIMITER}\n${content.endsWith('\n') ? content : content + '\n'}${TEMPLATE_DELIMITER}\n`);
  const attr = body.attributes[0];
  if (!attr || diagnostics.length) return new Unknown('templatefile(): template could not be parsed');
  const v = evaluate(attr.expr, { root: (n) => bindings[n], readFile: scope.readFile });
  return typeof v === 'string' && !content.endsWith('\n') ? v.replace(/\n$/, '') : v;
}

// Per process: a digest compares values within one run and says nothing about the value outside it.
const DIGEST_KEY = randomBytes(32);

/** Hide a value from every report while keeping a digest, so a change to it is still detected. */
export function redact(v: unknown): unknown {
  if (isRedacted(v)) return v;
  // Partly unknown values are wrapped too: rules still see their known structure, reports print
  // "(sensitive)" instead of an Unknown's pattern, which would show the known text.
  return new Redacted(createHmac('sha256', DIGEST_KEY).update(stableKey(v)).digest('hex').slice(0, 16), v);
}

function keyedDigest(text: string): string {
  return createHmac('sha256', DIGEST_KEY).update(text).digest('hex').slice(0, 16);
}
