import * as path from 'node:path';
import type { Body, Expr, TemplatePart } from '../hcl/ast.js';
import { parseHcl } from '../hcl/parser.js';
import { loadModule, moduleClosure } from './config.js';
import type { FileSource } from './source.js';

/** At most this many workspaces besides `default` are evaluated per root. */
export const MAX_WORKSPACES = 8;

const WORKSPACE_TEXT = /\bterraform\s*\.\s*workspace\b/;
/** A name Terraform accepts for a workspace. */
const VALID_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,89}$/;
/** Functions that keep the workspace name recognisable: `lower(terraform.workspace)`. */
const TRANSFORMS = new Set(['lower', 'upper', 'title', 'trimspace', 'trim', 'trimprefix', 'trimsuffix', 'replace', 'tostring', 'nonsensitive']);
/** Functions that pass a collection through unchanged for the purpose of naming its items or keys. */
const PASS_THROUGH = new Set(['toset', 'tolist', 'tomap', 'distinct', 'sort', 'compact', 'flatten', 'nonsensitive', 'sensitive']);

interface Parsed {
  dir: string;
  bodies: Body[];
  locals: Map<string, Expr>;
  outputs: Map<string, Expr>;
  variables: Map<string, Expr | undefined>;
  calls: Array<{ childDir?: string; args: Map<string, Expr> }>;
}

/** True when any module of the root's configuration reads `terraform.workspace`. */
export function readsWorkspace(source: FileSource, root: string): boolean {
  for (const dir of moduleClosure(source, root)) {
    const mod = loadModule(source, dir);
    if (mod && [...mod.sources.values()].some((t) => WORKSPACE_TEXT.test(t))) return true;
  }
  return false;
}

/**
 * The workspace names a root's configuration tells apart, read without evaluating: string literals
 * compared with `terraform.workspace` (directly, or through a local, a module output or a module input
 * that holds it), items of a literal list it is looked up in (`contains`, a `for` filter on it), and
 * keys of a literal map indexed by it (`lookup`, `m[terraform.workspace]`). A map or list may come from
 * a local, a variable default, or `rootVarValues` (the values tfvars files give a root variable).
 * `default` is never returned: it is always evaluated.
 */
export function workspaceNames(source: FileSource, root: string, rootVarValues: (name: string) => unknown[] = () => []): string[] {
  const dirs = [...moduleClosure(source, root)];
  const parsed = new Map<string, Parsed>();
  for (const dir of dirs) {
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
  }
  if (![...parsed.values()].length) return [];
  const callOf = (p: Parsed, name: string) => {
    const mod = loadModule(source, p.dir);
    return mod?.moduleCalls.get(name)?.localDir;
  };

  // Which locals, outputs and variables hold the workspace name, to a fixed point across modules.
  const wsLocals = new Map<string, Set<string>>();
  const wsOutputs = new Map<string, Set<string>>();
  const wsVars = new Map<string, Set<string>>();
  const has = (m: Map<string, Set<string>>, dir: string, name: string) => m.get(dir)?.has(name) ?? false;
  const add = (m: Map<string, Set<string>>, dir: string, name: string) => {
    const s = m.get(dir) ?? new Set();
    if (s.has(name)) return false;
    s.add(name);
    m.set(dir, s);
    return true;
  };
  const isWs = (e: Expr | undefined, p: Parsed): boolean => {
    if (!e) return false;
    switch (e.kind) {
      case 'paren':
        return isWs(e.expr, p);
      case 'template':
        return e.parts.length === 1 && e.parts[0].kind === 'interp' && isWs(e.parts[0].expr, p);
      case 'call':
        return TRANSFORMS.has(e.name) && isWs(e.args[0], p);
      case 'getattr': {
        if (e.obj.kind === 'scope') {
          if (e.obj.name === 'terraform') return e.name === 'workspace';
          if (e.obj.name === 'local') return has(wsLocals, p.dir, e.name);
          if (e.obj.name === 'var') return has(wsVars, p.dir, e.name);
        }
        // module.<name>.<output>
        if (e.obj.kind === 'getattr' && e.obj.obj.kind === 'scope' && e.obj.obj.name === 'module') {
          const child = callOf(p, e.obj.name);
          return child !== undefined && has(wsOutputs, child, e.name);
        }
        return false;
      }
      default:
        return false;
    }
  };
  for (let round = 0, changed = true; changed && round < 32; round++) {
    changed = false;
    for (const p of parsed.values()) {
      for (const [k, e] of p.locals) if (isWs(e, p) && add(wsLocals, p.dir, k)) changed = true;
      for (const [k, e] of p.outputs) if (isWs(e, p) && add(wsOutputs, p.dir, k)) changed = true;
      for (const c of p.calls) {
        if (!c.childDir) continue;
        for (const [k, e] of c.args) if (isWs(e, p) && add(wsVars, c.childDir, k)) changed = true;
      }
    }
  }

  // Static values of collections the workspace is looked up in.
  const callers = (dir: string) => [...parsed.values()].flatMap((p) => p.calls.filter((c) => c.childDir === dir).map((c) => ({ p, args: c.args })));
  const resolving = new Set<string>();
  const resolve = (e: Expr | undefined, p: Parsed, depth = 0): unknown[] => {
    if (!e || depth > 12) return [];
    switch (e.kind) {
      case 'literal':
        return [e.value];
      case 'paren':
        return resolve(e.expr, p, depth + 1);
      case 'template':
        return e.parts.every((x) => x.kind === 'text') ? [e.parts.map((x) => (x.kind === 'text' ? x.value : '')).join('')] : [];
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
      case 'getattr': {
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
        if (e.name === 'concat') {
          const parts = e.args.map((a) => resolve(a, p, depth + 1));
          return parts.every((x) => x.length >= 1 && x.every(Array.isArray)) ? [parts.flatMap((x) => x.flat())] : [];
        }
        if (e.name === 'merge') {
          const parts = e.args.map((a) => resolve(a, p, depth + 1));
          return parts.every((x) => x.length >= 1) ? [Object.assign({}, ...parts.flat().filter((x) => x && typeof x === 'object' && !Array.isArray(x)))] : [];
        }
        return [];
      }
      default:
        return [];
    }
  };
  const strings = (values: unknown[]) => values.filter((v): v is string => typeof v === 'string');
  const itemsOf = (values: unknown[]) => values.flatMap((v) => (Array.isArray(v) ? strings(v) : []));
  const valuesOf = (values: unknown[]) => values.flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) ? strings(Object.values(v)) : []));
  const keysOf = (values: unknown[]) => values.flatMap((v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : []));

  const names = new Set<string>();
  const refersTo = (e: Expr, test: (x: Expr) => boolean): boolean => {
    let found = false;
    walkExpr(e, (x) => {
      if (!found && test(x)) found = true;
    });
    return found;
  };
  for (const p of parsed.values()) {
    const visit = (e: Expr, loops: Map<string, { coll: Expr; key: boolean }>) => {
      switch (e.kind) {
        case 'binary':
          if (e.op === '==' || e.op === '!=') {
            for (const [a, b] of [[e.left, e.right], [e.right, e.left]] as const) {
              if (!isWs(a, p)) continue;
              for (const s of strings(resolve(b, p))) names.add(s);
              const loopVar = b.kind === 'scope' ? loops.get(b.name) : undefined;
              if (loopVar) for (const s of loopVar.key ? keysOf(resolve(loopVar.coll, p)) : itemsOf(resolve(loopVar.coll, p))) names.add(s);
            }
          }
          break;
        case 'call':
          if (e.name === 'contains' && e.args.length === 2 && isWs(e.args[1], p)) for (const s of itemsOf(resolve(e.args[0], p))) names.add(s);
          if (e.name === 'lookup' && e.args.length >= 2 && isWs(e.args[1], p)) for (const s of keysOf(resolve(e.args[0], p))) names.add(s);
          break;
        case 'index':
          if (isWs(e.key, p)) for (const s of keysOf(resolve(e.obj, p))) names.add(s);
          break;
        case 'for':
          // `[for x in local.envs : x if endswith(terraform.workspace, x)]`: the filter tells the items apart by workspace.
          if (e.cond && refersTo(e.cond, (x) => isWs(x, p))) {
            const usesVal = refersTo(e.cond, (x) => x.kind === 'scope' && x.name === e.valVar);
            const usesKey = e.keyVar !== undefined && refersTo(e.cond, (x) => x.kind === 'scope' && x.name === e.keyVar);
            const coll = resolve(e.coll, p);
            // Over a list the value is an item; over a map it is a value, and the key names the entry.
            if (usesVal) for (const s of [...itemsOf(coll), ...valuesOf(coll)]) names.add(s);
            if (usesKey) for (const s of keysOf(coll)) names.add(s);
          }
          break;
      }
      const inner = e.kind === 'for' ? new Map([...loops, [e.valVar, { coll: e.coll, key: false }], ...(e.keyVar ? [[e.keyVar, { coll: e.coll, key: true }] as const] : [])]) : loops;
      for (const child of children(e)) visit(child, inner);
    };
    for (const body of p.bodies) walkBody(body, (e) => visit(e, new Map()));
  }
  names.delete('default');
  return [...names].filter((n) => VALID_NAME.test(n)).sort();
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
