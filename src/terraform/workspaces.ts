import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Body, Expr, TemplatePart } from '../hcl/ast.js';
import { re2 } from '../hcl/eval.js';
import { parseHcl } from '../hcl/parser.js';
import { loadModule, moduleClosure } from './config.js';
import type { FileSource } from './source.js';
import { normalize } from './source.js';

/** At most this many workspaces besides `default` are evaluated per root. */
export const MAX_WORKSPACES = 8;

const WORKSPACE_TEXT = /\bterraform\s*\.\s*workspace\b/;
/** A name Terraform accepts for a workspace. */
const VALID_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,89}$/;
/** Functions that keep the workspace name recognisable as it is: `lower(terraform.workspace)`. */
const SAME_NAME = new Set(['lower', 'upper', 'title', 'trimspace', 'trim', 'tostring', 'nonsensitive']);
/** Functions that pass a collection through unchanged for the purpose of naming its items or keys. */
const PASS_THROUGH = new Set(['toset', 'tolist', 'tomap', 'distinct', 'sort', 'compact', 'flatten', 'nonsensitive', 'sensitive']);
/** Characters that separate the parts of a workspace name built from parts (`app-production`). */
const SEPARATOR = /[-_.]/;
/** At most this many variants of one derivation, when its arguments have several possible values. */
const MAX_VARIANTS = 8;

/**
 * One step of deriving a value from the workspace name. A step whose argument is not known offline has it
 * undefined: the derivation is recognised, but no full name can be built back from it.
 */
type Op =
  | { k: 'trimprefix' | 'trimsuffix'; s?: string }
  | { k: 'replace'; a?: string; b?: string }
  /** `substr(ws, length(prefix), ...)` has `prefix`; a literal offset has `off`. No `len` means the rest. */
  | { k: 'substr'; prefix?: string; off?: number; len?: number }
  | { k: 'split'; sep?: string }
  | { k: 'reverse' }
  | { k: 'index'; i?: number | string }
  | { k: 'regex'; pattern?: string };
/** The steps applied in order to the workspace name; no step is the name itself. */
type View = Op[];

interface Parsed {
  dir: string;
  bodies: Body[];
  locals: Map<string, Expr>;
  outputs: Map<string, Expr>;
  variables: Map<string, Expr | undefined>;
  calls: Array<{ childDir?: string; args: Map<string, Expr> }>;
}

/** What a root's configuration says about its workspaces. */
export interface WorkspaceSurvey {
  /** Full workspace names to evaluate besides `default`, sorted. */
  names: string[];
  /** Every derivation of `terraform.workspace` that removes or takes a part, described as Terraform writes it. */
  transforms: string[];
  /**
   * The derivations that tell environments apart but from which no full name could be built
   * (`trimprefix(terraform.workspace, (not known))`), so those environments are not evaluated.
   */
  unbuilt: string[];
  /** True when at least one full name was built from a derivation. */
  built: boolean;
  /** True when a `count` or `for_each` depends on a part derived from the workspace. */
  gated: boolean;
}

/** Modules parsed for their expressions, per snapshot: many roots share the same modules. */
const parseCache = new WeakMap<FileSource, Map<string, Parsed>>();

/** True when any module of the root's configuration reads `terraform.workspace`. */
export function readsWorkspace(source: FileSource, root: string): boolean {
  for (const dir of moduleClosure(source, root)) {
    const mod = loadModule(source, dir);
    if (mod && [...mod.sources.values()].some((t) => WORKSPACE_TEXT.test(t))) return true;
  }
  return false;
}

/** The workspace names a root's configuration tells apart (see `surveyWorkspaces`). */
export function workspaceNames(source: FileSource, root: string, rootVarValues: (name: string) => unknown[] = () => []): string[] {
  return surveyWorkspaces(source, root, rootVarValues).names;
}

/** Applies a derivation to a workspace name, as Terraform would; undefined when it fails or is not known. */
function derive(view: View, ws: string): unknown {
  let v: unknown = ws;
  for (const op of view) {
    if (v === undefined) return undefined;
    switch (op.k) {
      case 'trimprefix':
        if (typeof v !== 'string' || op.s === undefined) return undefined;
        v = v.startsWith(op.s) ? v.slice(op.s.length) : v;
        break;
      case 'trimsuffix':
        if (typeof v !== 'string' || op.s === undefined) return undefined;
        v = v.endsWith(op.s) && op.s ? v.slice(0, v.length - op.s.length) : v;
        break;
      case 'replace':
        if (typeof v !== 'string' || op.a === undefined || op.b === undefined || !op.a) return undefined;
        if (isPattern(op.a)) {
          try {
            v = v.replace(re2(op.a.slice(1, -1), 'g'), op.b.replace(/\$\{(\d+)\}/g, '$$$1'));
          } catch {
            return undefined;
          }
        } else v = v.split(op.a).join(op.b);
        break;
      case 'substr': {
        if (typeof v !== 'string') return undefined;
        const off = op.prefix !== undefined ? op.prefix.length : op.off;
        if (off === undefined) return undefined;
        v = v.substr(off < 0 ? v.length + off : off, op.len === undefined || op.len < 0 ? undefined : op.len);
        break;
      }
      case 'split':
        if (typeof v !== 'string' || op.sep === undefined) return undefined;
        v = op.sep === '' ? [...v] : v.split(op.sep);
        break;
      case 'reverse':
        if (!Array.isArray(v)) return undefined;
        v = [...v].reverse();
        break;
      case 'index':
        if (op.i === undefined) return undefined;
        if (Array.isArray(v) && typeof op.i === 'number') v = v[op.i];
        else if (v && typeof v === 'object' && !Array.isArray(v) && typeof op.i === 'string') v = (v as Record<string, unknown>)[op.i];
        else return undefined;
        break;
      case 'regex': {
        if (typeof v !== 'string' || op.pattern === undefined) return undefined;
        let m: RegExpMatchArray | null;
        try {
          m = v.match(re2(op.pattern));
        } catch {
          return undefined;
        }
        if (!m) return undefined;
        v = m.groups ? { ...m.groups } : m.length > 1 ? m.slice(1) : m[0];
        break;
      }
    }
  }
  return v;
}

/** `replace(s, "/-[a-z]+$/", "")`: a search written between slashes is a regular expression. */
const isPattern = (a: string) => a.length > 1 && a.startsWith('/') && a.endsWith('/');

/** How a derivation is described in a note: `trimprefix(terraform.workspace, "app-")`. */
function describe(view: View): string {
  const q = (s: string | number | undefined) => (s === undefined ? '(not known)' : JSON.stringify(s));
  let out = 'terraform.workspace';
  for (const op of view) {
    switch (op.k) {
      case 'trimprefix':
      case 'trimsuffix':
        out = `${op.k}(${out}, ${q(op.s)})`;
        break;
      case 'replace':
        out = `replace(${out}, ${q(op.a)}, ${q(op.b)})`;
        break;
      case 'substr':
        out = `substr(${out}, ${op.prefix !== undefined ? `length(${q(op.prefix)})` : q(op.off)}, ${op.len ?? -1})`;
        break;
      case 'split':
        out = `split(${q(op.sep)}, ${out})`;
        break;
      case 'reverse':
        out = `reverse(${out})`;
        break;
      case 'index':
        out = `${out}[${q(op.i)}]`;
        break;
      case 'regex':
        out = `regex(${q(op.pattern)}, ${out})`;
        break;
    }
  }
  return out;
}

/**
 * Full names whose derivation gives `part`, built by undoing each step: `trimprefix(ws, "app-")` compared
 * with "production" was `app-production`. Undefined when a step cannot be undone (a split, a regex, an
 * argument not known offline).
 */
function undo(view: View, part: string): string[] | undefined {
  let targets = [part];
  for (const op of [...view].reverse()) {
    switch (op.k) {
      case 'trimprefix':
        if (op.s === undefined) return undefined;
        targets = targets.map((t) => op.s + t);
        break;
      case 'trimsuffix':
        if (op.s === undefined) return undefined;
        targets = targets.map((t) => t + op.s);
        break;
      case 'replace': {
        const { a, b } = op;
        if (a === undefined || b === undefined || !a || isPattern(a)) return undefined;
        if (b === '') {
          // Removing a part: a prefix unless it starts with a separator and does not end with one.
          const suffix = SEPARATOR.test(a[0]) && !SEPARATOR.test(a[a.length - 1]);
          targets = targets.map((t) => (suffix ? t + a : a + t));
        } else {
          // A name without the replaced text is itself; otherwise the replacement is put back.
          targets = targets.map((t) => (t.includes(b) ? t.split(b).join(a) : t));
        }
        break;
      }
      case 'substr':
        if (op.len !== undefined && op.len >= 0) return undefined;
        if (op.prefix !== undefined) targets = targets.map((t) => op.prefix + t);
        else if (op.off !== 0) return undefined;
        break;
      default:
        return undefined;
    }
  }
  return targets;
}

/**
 * What a root's configuration says about its workspaces, read without evaluating.
 *
 * Names are found where the workspace, or a value derived from it, is compared with string literals
 * (directly, or through a local, a module output or a module input that holds it), looked up in a literal
 * list (`contains`, a `for` filter on it), or used as a key of a literal map (`lookup`, `m[...]`). A map or
 * list may come from a local, a variable default, `rootVarValues` (the values tfvars files give a root
 * variable), or a JSON or YAML file the configuration decodes.
 *
 * A value derived from the workspace by removing a part (`trimprefix(terraform.workspace, "app-")`,
 * `substr(terraform.workspace, length(local.app), -1)`, `replace`) names the environment, not the
 * workspace: each key it is compared with is turned back into a full name (`app-production`). A part
 * taken by `split` or `regex` cannot be turned back on its own; it is joined with the prefixes and
 * suffixes the configuration removes or tests elsewhere (`startswith(terraform.workspace, "app-")`), and
 * kept when deriving it again gives the key. A key never becomes a bare workspace name this way.
 * `default` is never returned: it is always evaluated.
 */
export function surveyWorkspaces(source: FileSource, root: string, rootVarValues: (name: string) => unknown[] = () => []): WorkspaceSurvey {
  const dirs = [...moduleClosure(source, root)];
  const parsed = new Map<string, Parsed>();
  let perSource = parseCache.get(source);
  if (!perSource) parseCache.set(source, (perSource = new Map()));
  for (const dir of dirs) {
    const known = perSource.get(dir);
    if (known) {
      parsed.set(dir, known);
      continue;
    }
    const mod = loadModule(source, dir);
    if (!mod) continue;
    const p: Parsed = { dir, bodies: [], locals: new Map(), outputs: new Map(), variables: new Map(), calls: [] };
    for (const [file, text] of mod.sources) {
      if (file.endsWith('.json')) continue;
      const { body } = parseHcl(text, path.posix.join(dir, file));
      p.bodies.push(body);
      for (const b of body.blocks) {
        if (b.type === 'locals') for (const a of b.body.attributes) p.locals.set(a.name, a.expr);
        if (b.type === 'output' && b.labels[0]) p.outputs.set(b.labels[0], b.body.attributes.find((a) => a.name === 'value')?.expr as Expr);
        if (b.type === 'variable' && b.labels[0]) p.variables.set(b.labels[0], b.body.attributes.find((a) => a.name === 'default')?.expr);
        if (b.type === 'module' && b.labels[0]) {
          const call = mod.moduleCalls.get(b.labels[0]);
          p.calls.push({ childDir: call?.localDir, args: new Map(b.body.attributes.map((a) => [a.name, a.expr])) });
        }
      }
    }
    parsed.set(dir, p);
    perSource.set(dir, p);
  }
  const empty: WorkspaceSurvey = { names: [], transforms: [], unbuilt: [], built: false, gated: false };
  if (![...parsed.values()].length) return empty;
  const callOf = (p: Parsed, name: string) => {
    const mod = loadModule(source, p.dir);
    return mod?.moduleCalls.get(name)?.localDir;
  };

  // Static values of collections and arguments, without evaluating.
  const callers = (dir: string) => [...parsed.values()].flatMap((p) => p.calls.filter((c) => c.childDir === dir).map((c) => ({ p, args: c.args })));
  const resolving = new Set<string>();
  /** `path.module` is resolved to this marker and the module directory, so a file path can be read. */
  const MODULE_DIR = '\0module:';
  const decode = (fn: string, file: unknown): unknown[] => {
    if (typeof file !== 'string') return [];
    const rel = file.startsWith(MODULE_DIR) ? file.slice(MODULE_DIR.length) : path.posix.join(dirs[0], file);
    const full = normalize(rel);
    if (full === '..' || full.startsWith('../') || full.startsWith('/')) return [];
    const text = source.readFile(full);
    if (text === undefined || text === null) return [];
    try {
      return [fn === 'jsondecode' ? JSON.parse(text) : parseYaml(text)];
    } catch {
      return [];
    }
  };
  const resolve = (e: Expr | undefined, p: Parsed, depth = 0): unknown[] => {
    if (!e || depth > 12) return [];
    switch (e.kind) {
      case 'literal':
        return [e.value];
      case 'paren':
        return resolve(e.expr, p, depth + 1);
      case 'template': {
        // Every interpolation with known values: one string per combination, a few at most.
        let out = [''];
        for (const part of e.parts) {
          if (part.kind === 'text') out = out.map((s) => s + part.value);
          else if (part.kind === 'interp') {
            const vals = resolve(part.expr, p, depth + 1).filter((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean');
            if (!vals.length) return [];
            out = out.flatMap((s) => vals.map((v) => s + String(v))).slice(0, MAX_VARIANTS);
          } else return [];
        }
        return out;
      }
      case 'tuple': {
        const items = e.items.map((x) => resolve(x, p, depth + 1));
        return items.every((x) => x.length === 1) ? [items.map((x) => x[0])] : [];
      }
      case 'object': {
        const out: Record<string, unknown> = {};
        for (const item of e.items) {
          const key = item.key.kind === 'paren' ? resolve(item.key.expr, p, depth + 1) : resolve(item.key, p, depth + 1);
          if (key.length !== 1 || typeof key[0] !== 'string') return [];
          const value = resolve(item.value, p, depth + 1);
          out[key[0]] = value.length === 1 ? value[0] : null;
        }
        return [out];
      }
      case 'conditional':
        return [...resolve(e.then, p, depth + 1), ...resolve(e.else, p, depth + 1)];
      case 'getattr': {
        if (e.obj.kind === 'scope' && e.obj.name === 'path') {
          if (e.name === 'module') return [MODULE_DIR + p.dir];
          if (e.name === 'root' || e.name === 'cwd') return ['.'];
          return [];
        }
        if (e.obj.kind === 'scope' && (e.obj.name === 'local' || e.obj.name === 'var')) {
          const key = `${p.dir}\0${e.obj.name}\0${e.name}`;
          if (resolving.has(key)) return [];
          resolving.add(key);
          try {
            if (e.obj.name === 'local') return resolve(p.locals.get(e.name), p, depth + 1);
            const out = [...resolve(p.variables.get(e.name), p, depth + 1)];
            if (p.dir === dirs[0]) out.push(...rootVarValues(e.name));
            for (const c of callers(p.dir)) out.push(...resolve(c.args.get(e.name), c.p, depth + 1));
            return out;
          } finally {
            resolving.delete(key);
          }
        }
        return resolve(e.obj, p, depth + 1).flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) && e.name in v ? [(v as Record<string, unknown>)[e.name]] : []));
      }
      case 'index': {
        const keys = resolve(e.key, p, depth + 1);
        if (keys.length !== 1) return [];
        return resolve(e.obj, p, depth + 1).flatMap((v) => {
          const k = keys[0];
          if (Array.isArray(v) && typeof k === 'number') return k in v ? [v[k]] : [];
          return v && typeof v === 'object' && typeof k === 'string' && k in v ? [(v as Record<string, unknown>)[k]] : [];
        });
      }
      case 'call': {
        if (e.name === 'keys') return resolve(e.args[0], p, depth + 1).flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) ? [Object.keys(v)] : []));
        if (PASS_THROUGH.has(e.name)) return resolve(e.args[0], p, depth + 1);
        if (e.name === 'try' || e.name === 'coalesce') return e.args.flatMap((a) => resolve(a, p, depth + 1));
        if (e.name === 'length') return resolve(e.args[0], p, depth + 1).flatMap((v) => (typeof v === 'string' ? [[...v].length] : Array.isArray(v) ? [v.length] : []));
        if (e.name === 'concat') {
          const parts = e.args.map((a) => resolve(a, p, depth + 1));
          return parts.every((x) => x.length >= 1 && x.every(Array.isArray)) ? [parts.flatMap((x) => x.flat())] : [];
        }
        if (e.name === 'merge') {
          const parts = e.args.map((a) => resolve(a, p, depth + 1));
          return parts.every((x) => x.length >= 1) ? [Object.assign({}, ...parts.flat().filter((x) => x && typeof x === 'object' && !Array.isArray(x)))] : [];
        }
        // jsondecode(file("./envs.json")): a data file of the configuration.
        if ((e.name === 'jsondecode' || e.name === 'yamldecode') && e.args[0]?.kind === 'call' && e.args[0].name === 'file') {
          return resolve(e.args[0].args[0], p, depth + 1).flatMap((f) => decode(e.name, f));
        }
        return [];
      }
      default:
        return [];
    }
  };
  const strings = (values: unknown[]) => [...new Set(values.filter((v): v is string => typeof v === 'string'))];

  // Which locals, outputs and variables hold the workspace or a value derived from it, to a fixed point
  // across modules. Each holds the derivations it can be (one per combination of argument values).
  const wsLocals = new Map<string, Map<string, View[]>>();
  const wsOutputs = new Map<string, Map<string, View[]>>();
  const wsVars = new Map<string, Map<string, View[]>>();
  const get = (m: Map<string, Map<string, View[]>>, dir: string, name: string) => m.get(dir)?.get(name);
  const add = (m: Map<string, Map<string, View[]>>, dir: string, name: string, views: View[]) => {
    const s = m.get(dir) ?? new Map<string, View[]>();
    if (s.has(name)) return false;
    s.set(name, views);
    m.set(dir, s);
    return true;
  };
  /** Each of one step's argument values extends each view. */
  const extend = (views: View[], ops: Op[]): View[] => views.flatMap((v) => ops.map((op) => [...v, op])).slice(0, MAX_VARIANTS);
  const argStrings = (e: Expr | undefined, p: Parsed): Array<string | undefined> => {
    const s = strings(resolve(e, p));
    return s.length ? s.slice(0, MAX_VARIANTS) : [undefined];
  };
  const argNumbers = (e: Expr | undefined, p: Parsed): Array<number | undefined> => {
    const n = [...new Set(resolve(e, p).filter((v): v is number => typeof v === 'number'))];
    return n.length ? n.slice(0, MAX_VARIANTS) : [undefined];
  };
  const viewsOf = (e: Expr | undefined, p: Parsed): View[] | undefined => {
    if (!e) return undefined;
    switch (e.kind) {
      case 'paren':
        return viewsOf(e.expr, p);
      case 'template':
        return e.parts.length === 1 && e.parts[0].kind === 'interp' ? viewsOf(e.parts[0].expr, p) : undefined;
      case 'call': {
        if (SAME_NAME.has(e.name)) return viewsOf(e.args[0], p);
        if (e.name === 'trimprefix' || e.name === 'trimsuffix') {
          const v = viewsOf(e.args[0], p);
          const k = e.name;
          return v && extend(v, argStrings(e.args[1], p).map((s) => ({ k, s })));
        }
        if (e.name === 'replace') {
          const v = viewsOf(e.args[0], p);
          if (!v) return undefined;
          const ops: Op[] = argStrings(e.args[1], p).flatMap((a) => argStrings(e.args[2], p).map((b) => ({ k: 'replace' as const, a, b })));
          return extend(v, ops);
        }
        if (e.name === 'substr') {
          const v = viewsOf(e.args[0], p);
          if (!v) return undefined;
          const offset = e.args[1];
          // The length of the rest: -1, or any length() (of the workspace, typically).
          const lenArg = e.args[2];
          const lens = lenArg?.kind === 'call' && lenArg.name === 'length' ? [undefined] : argNumbers(lenArg, p);
          const ops: Op[] =
            offset?.kind === 'call' && offset.name === 'length'
              ? argStrings(offset.args[0], p).flatMap((prefix) => (prefix === undefined ? [{ k: 'substr' as const }] : lens.map((len) => ({ k: 'substr' as const, prefix, ...(len !== undefined ? { len } : {}) }))))
              : argNumbers(offset, p).flatMap((off) => lens.map((len) => ({ k: 'substr' as const, ...(off !== undefined ? { off } : {}), ...(len !== undefined ? { len } : {}) })));
          return extend(v, ops);
        }
        if (e.name === 'split') {
          const v = viewsOf(e.args[1], p);
          return v && extend(v, argStrings(e.args[0], p).map((sep) => ({ k: 'split', sep })));
        }
        if (e.name === 'regex') {
          const v = viewsOf(e.args[1], p);
          return v && extend(v, argStrings(e.args[0], p).map((pattern) => ({ k: 'regex', pattern })));
        }
        if (e.name === 'reverse') {
          const v = viewsOf(e.args[0], p);
          return v && extend(v, [{ k: 'reverse' }]);
        }
        if (e.name === 'element') {
          const v = viewsOf(e.args[0], p);
          return v && extend(v, argNumbers(e.args[1], p).map((i) => ({ k: 'index', i })));
        }
        return undefined;
      }
      case 'index': {
        const v = viewsOf(e.obj, p);
        if (!v) return undefined;
        const keys = resolve(e.key, p).filter((k): k is string | number => typeof k === 'string' || typeof k === 'number');
        return extend(v, keys.length ? keys.map((i) => ({ k: 'index', i })) : [{ k: 'index' }]);
      }
      case 'getattr': {
        if (e.obj.kind === 'scope') {
          if (e.obj.name === 'terraform') return e.name === 'workspace' ? [[]] : undefined;
          if (e.obj.name === 'local') return get(wsLocals, p.dir, e.name);
          if (e.obj.name === 'var') return get(wsVars, p.dir, e.name);
        }
        // module.<name>.<output>
        if (e.obj.kind === 'getattr' && e.obj.obj.kind === 'scope' && e.obj.obj.name === 'module') {
          const child = callOf(p, e.obj.name);
          return child !== undefined ? get(wsOutputs, child, e.name) : undefined;
        }
        // A map derived from the workspace by regex() with named groups: `local.parts.env`.
        const v = viewsOf(e.obj, p);
        return v && v.some((x) => x.length) ? extend(v, [{ k: 'index', i: e.name }]) : undefined;
      }
      default:
        return undefined;
    }
  };
  for (let round = 0, changed = true; changed && round < 32; round++) {
    changed = false;
    for (const p of parsed.values()) {
      for (const [k, e] of p.locals) {
        const v = viewsOf(e, p);
        if (v && add(wsLocals, p.dir, k, v)) changed = true;
      }
      for (const [k, e] of p.outputs) {
        const v = viewsOf(e, p);
        if (v && add(wsOutputs, p.dir, k, v)) changed = true;
      }
      for (const c of p.calls) {
        if (!c.childDir) continue;
        for (const [k, e] of c.args) {
          const v = viewsOf(e, p);
          if (v && add(wsVars, c.childDir, k, v)) changed = true;
        }
      }
    }
  }

  // Prefixes and suffixes the configuration removes from or tests on the workspace name, to rebuild a
  // name from a part a split or a regex took.
  const prefixes = new Set<string>();
  const suffixes = new Set<string>();
  const transforms: View[] = [];
  const noteView = (views: View[]) => {
    for (const view of views) {
      if (!view.length) continue;
      transforms.push(view);
      for (const op of view) {
        if (op.k === 'trimprefix' && op.s) prefixes.add(op.s);
        if (op.k === 'trimsuffix' && op.s) suffixes.add(op.s);
        if (op.k === 'substr' && op.prefix) {
          prefixes.add(op.prefix);
          // `substr(ws, length("app"), -1) == "-production"`: the separator is part of the key, but a
          // split by it needs it on the prefix.
          for (const sep of ['-', '_', '.']) prefixes.add(op.prefix + sep);
        }
        if (op.k === 'replace' && op.a && !isPattern(op.a) && op.b === '') (SEPARATOR.test(op.a[0]) && !SEPARATOR.test(op.a[op.a.length - 1]) ? suffixes : prefixes).add(op.a);
        if (op.k === 'regex' && op.pattern) {
          // The literal start of an anchored pattern: `^app-(.+)$` starts names with `app-`.
          const lead = op.pattern.match(/^\^((?:[A-Za-z0-9_-]|\\[.-])+)/);
          if (lead) prefixes.add(lead[1].replace(/\\/g, ''));
        }
      }
    }
  };
  for (const m of [wsLocals, wsOutputs, wsVars]) for (const per of m.values()) for (const views of per.values()) noteView(views);
  // `startswith(terraform.workspace, "app-")`: names of this root start so. Read before any name is built.
  for (const p of parsed.values()) {
    for (const body of p.bodies) {
      walkBody(body, (top) =>
        walkExpr(top, (e) => {
          if (e.kind !== 'call' || (e.name !== 'startswith' && e.name !== 'endswith') || e.args.length !== 2) return;
          if (!viewsOf(e.args[0], p)?.some((v) => !v.length)) return;
          for (const s of strings(resolve(e.args[1], p))) (e.name === 'startswith' ? prefixes : suffixes).add(s);
        })
      );
    }
  }

  const names = new Set<string>();
  const unbuilt = new Set<string>();
  let builtFromTransform = false;
  /** Full names whose derivation by `view` gives `part`, checked by deriving again. */
  const build = (view: View, part: string): string[] => {
    // The default workspace is always evaluated: a key it derives to needs no name of its own.
    if (derive(view, 'default') === part) return [];
    const direct = undo(view, part) ?? [];
    const joined = [...prefixes].flatMap((pre) => [pre + part, ...[...suffixes].map((suf) => pre + part + suf)]).concat([...suffixes].map((suf) => part + suf));
    const ok = (n: string) => VALID_NAME.test(n) && n !== 'default' && derive(view, n) === part;
    const found = direct.filter(ok);
    return found.length ? found : joined.filter(ok);
  };
  const nameFrom = (views: View[], parts: string[]) => {
    for (const view of views) {
      if (!view.length) {
        for (const s of parts) names.add(s);
        continue;
      }
      noteView([view]);
      let any = false;
      for (const s of parts) {
        const built = build(view, s);
        if (built.length) any = true;
        for (const n of built) names.add(n);
      }
      // Keys that are the default workspace's own value need no name; other keys need one.
      const needed = parts.some((s) => derive(view, 'default') !== s);
      if (any) builtFromTransform = true;
      else if (needed) unbuilt.add(describe(view));
    }
  };
  const itemsOf = (values: unknown[]) => values.flatMap((v) => (Array.isArray(v) ? strings(v) : []));
  const valuesOf = (values: unknown[]) => values.flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) ? strings(Object.values(v)) : []));
  const keysOf = (values: unknown[]) => values.flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : []));

  // In a filter, `can(regex("${x}$", terraform.workspace))` tests the name; the regex takes no part of it.
  const viewsIn = (e: Expr, p: Parsed): View[] => {
    const out: View[] = [];
    walkExpr(e, (x) => {
      const v = viewsOf(x, p);
      if (v) out.push(...v.map((view) => (view.some((op) => op.k === 'regex') ? view.slice(0, view.findIndex((op) => op.k === 'regex')) : view)));
    });
    return out;
  };
  for (const p of parsed.values()) {
    const visit = (e: Expr, loops: Map<string, { coll: Expr; key: boolean }>) => {
      switch (e.kind) {
        case 'binary':
          if (e.op === '==' || e.op === '!=') {
            for (const [a, b] of [[e.left, e.right], [e.right, e.left]] as const) {
              const views = viewsOf(a, p);
              if (!views) continue;
              const parts = strings(resolve(b, p));
              const loopVar = b.kind === 'scope' ? loops.get(b.name) : undefined;
              if (loopVar) parts.push(...(loopVar.key ? keysOf(resolve(loopVar.coll, p)) : itemsOf(resolve(loopVar.coll, p))));
              nameFrom(views, parts);
            }
          }
          break;
        case 'call': {
          const views = e.args.length === 2 ? viewsOf(e.args[1], p) : undefined;
          if (e.name === 'contains' && views) nameFrom(views, itemsOf(resolve(e.args[0], p)));
          const lookupViews = e.name === 'lookup' && e.args.length >= 2 ? viewsOf(e.args[1], p) : undefined;
          if (lookupViews) nameFrom(lookupViews, keysOf(resolve(e.args[0], p)));
          break;
        }
        case 'index': {
          const views = viewsOf(e.key, p);
          if (views) nameFrom(views, keysOf(resolve(e.obj, p)));
          break;
        }
        case 'for':
          // `[for x in local.envs : x if endswith(terraform.workspace, x)]`: the filter tells the items apart by workspace.
          if (e.cond) {
            const views = viewsIn(e.cond, p);
            if (views.length) {
              const usesVal = refersTo(e.cond, (x) => x.kind === 'scope' && x.name === e.valVar);
              const usesKey = e.keyVar !== undefined && refersTo(e.cond, (x) => x.kind === 'scope' && x.name === e.keyVar);
              const coll = resolve(e.coll, p);
              // Over a list the value is an item; over a map it is a value, and the key names the entry.
              const parts = [...(usesVal ? [...itemsOf(coll), ...valuesOf(coll)] : []), ...(usesKey ? keysOf(coll) : [])];
              // A part tested by endswith or startswith on the name itself is a bare name, as before.
              nameFrom(views, parts);
            }
          }
          break;
      }
      const inner = e.kind === 'for' ? new Map([...loops, [e.valVar, { coll: e.coll, key: false }], ...(e.keyVar ? [[e.keyVar, { coll: e.coll, key: true }] as const] : [])]) : loops;
      for (const child of children(e)) visit(child, inner);
    };
    for (const body of p.bodies) walkBody(body, (e) => visit(e, new Map()));
  }

  // Does a count or for_each depend on a part derived from the workspace (not on the name as it is, which
  // the names found cover)? Locals, outputs and module inputs that read one, to a fixed point, then every
  // resource, data source and module call. A regex that only tests the name derives nothing.
  const tainted = new Set<string>();
  const derives = (x: Expr, p: Parsed) => (x.kind !== 'getattr' ? viewsOf(x, p) : undefined)?.some((v) => v.length && v[v.length - 1].k !== 'regex') ?? false;
  const readsWs = (e: Expr | undefined, p: Parsed): boolean =>
    e !== undefined &&
    refersTo(e, (x) => {
      if (derives(x, p)) return true;
      if (x.kind !== 'getattr') return false;
      if (x.obj.kind === 'scope') {
        if (x.obj.name === 'local' || x.obj.name === 'var') return tainted.has(`${p.dir}\0${x.obj.name}\0${x.name}`) || Boolean(viewsOf(x, p)?.some((v) => v.length));
      }
      if (x.obj.kind === 'getattr' && x.obj.obj.kind === 'scope' && x.obj.obj.name === 'module') {
        const child = callOf(p, x.obj.name);
        return child !== undefined && tainted.has(`${child}\0output\0${x.name}`);
      }
      return false;
    });
  for (let round = 0, changed = true; changed && round < 32; round++) {
    changed = false;
    const mark = (key: string) => {
      if (!tainted.has(key)) {
        tainted.add(key);
        changed = true;
      }
    };
    for (const p of parsed.values()) {
      for (const [k, e] of p.locals) if (!tainted.has(`${p.dir}\0local\0${k}`) && readsWs(e, p)) mark(`${p.dir}\0local\0${k}`);
      for (const [k, e] of p.outputs) if (!tainted.has(`${p.dir}\0output\0${k}`) && readsWs(e, p)) mark(`${p.dir}\0output\0${k}`);
      for (const c of p.calls) if (c.childDir) for (const [k, e] of c.args) if (!tainted.has(`${c.childDir}\0var\0${k}`) && readsWs(e, p)) mark(`${c.childDir}\0var\0${k}`);
    }
  }
  const gated = [...parsed.values()].some((p) =>
    p.bodies.some((body) => body.blocks.some((b) => (b.type === 'resource' || b.type === 'data' || b.type === 'module') && b.body.attributes.some((a) => (a.name === 'count' || a.name === 'for_each') && readsWs(a.expr, p)))),
  );

  names.delete('default');
  return {
    names: [...names].filter((n) => VALID_NAME.test(n)).sort(),
    transforms: [...new Set(transforms.map(describe))].sort(),
    unbuilt: [...unbuilt].sort(),
    built: builtFromTransform,
    gated,
  };
}

function refersTo(e: Expr, test: (x: Expr) => boolean): boolean {
  let found = false;
  walkExpr(e, (x) => {
    if (!found && test(x)) found = true;
  });
  return found;
}

function walkBody(body: Body, fn: (e: Expr) => void) {
  for (const a of body.attributes) fn(a.expr);
  for (const b of body.blocks) walkBody(b.body, fn);
}

function walkExpr(e: Expr, fn: (e: Expr) => void) {
  fn(e);
  for (const c of children(e)) walkExpr(c, fn);
}

function templateChildren(parts: TemplatePart[]): Expr[] {
  return parts.flatMap((p) => {
    if (p.kind === 'interp') return [p.expr];
    if (p.kind === 'if') return [p.cond, ...templateChildren(p.then), ...templateChildren(p.else)];
    if (p.kind === 'for') return [p.coll, ...templateChildren(p.body)];
    return [];
  });
}

function children(e: Expr): Expr[] {
  switch (e.kind) {
    case 'template':
      return templateChildren(e.parts);
    case 'tuple':
      return e.items;
    case 'object':
      return e.items.flatMap((i) => [i.key, i.value]);
    case 'getattr':
      return [e.obj];
    case 'index':
      return [e.obj, e.key];
    case 'splat':
      return [e.obj, e.each];
    case 'call':
      return e.args;
    case 'for':
      return [e.coll, ...(e.keyExpr ? [e.keyExpr] : []), e.valExpr, ...(e.cond ? [e.cond] : [])];
    case 'unary':
      return [e.operand];
    case 'binary':
      return [e.left, e.right];
    case 'conditional':
      return [e.cond, e.then, e.else];
    case 'paren':
      return [e.expr];
    default:
      return [];
  }
}
