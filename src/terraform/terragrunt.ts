import * as path from 'node:path';
import { isUnknown, Unknown } from '../core/model.js';
import type { Block, Body, Expr, TemplatePart } from '../hcl/ast.js';
import { LazyMap, evaluate, stableKey, toPlain, type EvalScope } from '../hcl/eval.js';
import { parseHcl } from '../hcl/parser.js';
import { loadModule } from './config.js';
import { normalize, type FileSource } from './source.js';

/**
 * Terragrunt configuration, read statically. Nothing is run: not Terragrunt, not `run_cmd`, not a hook.
 *
 * A deployment is a `terragrunt.hcl` whose `terraform { source }` is a local path (or which has no source
 * and sits next to Terraform files). Its inputs are read from `inputs`, with literal values and locals
 * built from literals and pure functions, merged with the `inputs` of a parent it includes (found with
 * `find_in_parent_folders()` or a path). Values that need something Diffseal does not evaluate
 * (dependency outputs, `get_env`, `run_cmd`, `read_terragrunt_config`, an exposed include) stay unknown,
 * and name what they need.
 */

export interface TerragruntInput {
  value: unknown;
  /** The file that sets it. */
  file: string;
  /** Text of the expression and of everything it reads, so an edit anywhere on the way shows. */
  fingerprint: string;
  /** What the value needs that is not evaluated: `dependency.network outputs`, `get_env("APP_ENV")`. */
  constructs: string[];
  /** Locals of its file it reads, and repository files it reads. */
  locals: string[];
  reads: string[];
}

export interface TerragruntDeployment {
  /** The `terragrunt.hcl`. */
  file: string;
  dir: string;
  /** Files it includes, resolved. */
  includes: string[];
  /** Other repository files its inputs read: with file(), read_terragrunt_config() and the like. */
  reads: Set<string>;
  /** The Terraform module directory it runs. */
  moduleDir?: string;
  /** Why it cannot be evaluated at all. */
  problems: string[];
  inputs: Map<string, TerragruntInput>;
  /** Parts Diffseal does not evaluate, by name, with a fingerprint each: generate, remote_state, hooks... */
  elements: Map<string, string>;
  /** True when a generate block may write Terraform files (variable declarations among them). */
  generates: boolean;
}

export const TERRAGRUNT_FILE = /(^|\/)terragrunt\.hcl$/;

/** Functions that read the machine, the network, other configuration or run code: never evaluated. */
const IMPURE = new Set([
  'run_cmd', 'get_env', 'read_terragrunt_config', 'read_tfvars_file', 'sops_decrypt_file', 'get_aws_account_id', 'get_aws_account_alias',
  'get_aws_caller_identity_arn', 'get_aws_caller_identity_user_id', 'get_terraform_command', 'get_terraform_cli_args', 'get_platform',
  'get_working_dir', 'mark_as_read', 'constraint_check', 'get_default_retryable_errors',
]);
/** Scopes whose values come from outside the file. */
const OUTSIDE = new Set(['dependency', 'include', 'feature', 'values', 'unit', 'stack']);
const MOCK_ATTRIBUTES = /^mock_outputs/;

interface ParsedFile {
  file: string;
  dir: string;
  body: Body;
  text: string;
  broken: boolean;
  locals: Map<string, Expr>;
}

function parseFile(source: FileSource, file: string): ParsedFile | undefined {
  const text = source.readFile(file);
  if (text === undefined) return undefined;
  const { body, diagnostics } = parseHcl(text, file);
  const locals = new Map<string, Expr>();
  for (const b of body.blocks) if (b.type === 'locals') for (const a of b.body.attributes) locals.set(a.name, a.expr);
  return { file, dir: path.posix.dirname(file), body, text, broken: diagnostics.length > 0, locals };
}

const sliceOf = (f: ParsedFile, r: { start: { offset: number }; end: { offset: number } }) => f.text.slice(r.start.offset, r.end.offset).replace(/\s+/g, ' ');
/**
 * The text of a range with whitespace outside quoted strings collapsed, so realigning `=` signs is not an
 * edit while a space inside a string is. Text with a heredoc is kept exactly.
 */
function canonical(f: ParsedFile, r: { start: { offset: number }; end: { offset: number } }): string {
  const t = f.text.slice(r.start.offset, r.end.offset);
  if (t.includes('<<')) return t;
  let out = '';
  let inString = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (inString) {
      out += c;
      if (c === '\\') out += t[++i] ?? '';
      else if (c === '"') inString = false;
    } else if (/\s/.test(c)) {
      if (!out.endsWith(' ')) out += ' ';
    } else {
      if (c === '"') inString = true;
      out += c;
    }
  }
  return out.trim();
}

const abs = (repoPath: string) => '/' + (repoPath === '.' ? '' : repoPath);
const fromAbs = (p: string, base: string) => normalize(p.startsWith('/') ? p.replace(/^\/+/, '') || '.' : path.posix.join(base, p));
const inside = (p: string) => p !== '..' && !p.startsWith('../');

/** Every `terragrunt.hcl` and every file one of them includes. */
export function terragruntFiles(source: FileSource): Set<string> {
  const out = new Set<string>();
  for (const d of terragruntDeployments(source).values()) {
    out.add(d.file);
    for (const i of [...d.includes, ...d.reads]) out.add(i);
  }
  for (const f of source.allFiles()) if (TERRAGRUNT_FILE.test(f)) out.add(f);
  return out;
}

const cache = new WeakMap<FileSource, Map<string, TerragruntDeployment>>();

/** Deployments of a snapshot, by `terragrunt.hcl` path. A file only included by others is not one. */
export function terragruntDeployments(source: FileSource): Map<string, TerragruntDeployment> {
  const known = cache.get(source);
  if (known) return known;
  const out = new Map<string, TerragruntDeployment>();
  cache.set(source, out);
  for (const f of source.allFiles()) {
    if (!TERRAGRUNT_FILE.test(f) || /(^|\/)(\.terragrunt-cache|\.terraform|node_modules)\//.test(f)) continue;
    const d = readDeployment(source, f);
    if (d) out.set(f, d);
  }
  return out;
}

function readDeployment(source: FileSource, file: string): TerragruntDeployment | undefined {
  const child = parseFile(source, file);
  if (!child) return undefined;
  const d: TerragruntDeployment = { file, dir: child.dir, includes: [], reads: new Set(), problems: [], inputs: new Map(), elements: new Map(), generates: false };
  if (child.broken) d.problems.push(`${file} does not parse`);

  // Includes, resolved in the child's context.
  const includeBlocks = child.body.blocks.filter((b) => b.type === 'include');
  const parents: Array<{ label: string; file: ParsedFile; merge: string }> = [];
  const pathFns = (ctx: { includeDirs: Map<string, string> }) => pathFunctions(source, child.dir, ctx.includeDirs);
  const preIncludes = new Map<string, string>();
  for (const b of includeBlocks) {
    const label = b.labels[0] ?? '';
    const expr = attrOf(b.body, 'path');
    const v = expr ? evalIn(source, child, expr, pathFns({ includeDirs: preIncludes })).value : undefined;
    if (typeof v !== 'string') {
      d.problems.push(`include${label ? ` "${label}"` : ''} has a path that is not known statically`);
      continue;
    }
    const target = fromAbs(v, child.dir);
    const parsed = inside(target) ? parseFile(source, target) : undefined;
    if (!parsed) {
      d.problems.push(`include${label ? ` "${label}"` : ''} names ${v}, which is not in the repository at this commit`);
      continue;
    }
    if (parsed.broken) d.problems.push(`${target} does not parse`);
    const mergeExpr = attrOf(b.body, 'merge_strategy');
    const merge = mergeExpr ? String(evalIn(source, child, mergeExpr, pathFns({ includeDirs: preIncludes })).value ?? 'shallow') : 'shallow';
    preIncludes.set(label, parsed.dir);
    parents.push({ label, file: parsed, merge });
    d.includes.push(target);
  }
  const fns = pathFns({ includeDirs: preIncludes });
  const parentTexts = new Map(parents.map((p) => [p.label, p.file.text]));

  // The module it runs: the child's source wins over a parent's.
  const sourceOf = (f: ParsedFile) => {
    const tf = f.body.blocks.find((b) => b.type === 'terraform');
    return tf ? attrOf(tf.body, 'source') : undefined;
  };
  // A later include overrides an earlier one, and the child overrides both.
  const withSource = [child, ...parents.filter((p) => p.merge !== 'no_merge').map((p) => p.file).reverse()].find((f) => sourceOf(f));
  if (withSource) {
    const r = evalIn(source, withSource, sourceOf(withSource)!, fns);
    const s = r.value;
    if (typeof s !== 'string') d.problems.push(`terraform source is not known statically${r.constructs.length ? ` (it reads ${r.constructs.join(', ')})` : ''}`);
    else if (isRemote(s)) d.problems.push(`terraform source ${s} is not a local path`);
    else {
      const local = s.replace(/\?.*$/, '');
      const cut = local.indexOf('//');
      const dir = fromAbs(cut >= 0 ? `${local.slice(0, cut)}/${local.slice(cut + 2)}` : local, child.dir);
      if (!inside(dir)) d.problems.push(`terraform source ${s} leaves the repository`);
      else if (!loadModule(source, dir)) d.problems.push(`terraform source ${s} has no Terraform files at this commit`);
      else d.moduleDir = dir;
    }
  } else if (loadModule(source, child.dir)) {
    d.moduleDir = child.dir;
  } else {
    // No module of its own: a parent other files include, not a deployment.
    return undefined;
  }

  // Inputs: parents in order, then the child. Each include folds in with its own strategy: shallow sets a
  // key, deep merges maps and appends lists; a later include, and the child, win.
  type Item = { key: string; value: TerragruntInput; known: boolean; reads: string[] };
  const inputsOf = (f: ParsedFile): Item[] | string => {
    const expr = attrOf(f.body, 'inputs');
    if (!expr) return [];
    const item = (key: string, r: Evaluated, value: unknown): Item => ({
      key,
      value: { value, file: f.file, fingerprint: r.fingerprint, constructs: r.constructs, locals: r.locals, reads: r.reads },
      known: !r.constructs.length && !containsUnknownDeep(value),
      reads: r.reads,
    });
    if (expr.kind === 'object') {
      const out: Item[] = [];
      for (const it of expr.items) {
        const key = it.key.kind === 'paren' ? undefined : literalKey(it.key);
        if (key === undefined) return `inputs in ${f.file} has a key that is not known statically`;
        const r = evalIn(source, f, it.value, fns, f === child ? parentTexts : new Map());
        out.push(item(key, r, r.value));
      }
      return out;
    }
    const r = evalIn(source, f, expr, fns, f === child ? parentTexts : new Map());
    if (!isObject(r.value)) return `inputs in ${f.file} is not known statically${r.constructs.length ? ` (it reads ${r.constructs.join(', ')})` : ''}`;
    return Object.entries(r.value).map(([k, v]) => item(k, r, v));
  };
  const items = new Map<ParsedFile, Item[]>();
  const fold = (got: Item[], deep: boolean) => {
    for (const it of got) {
      for (const p of it.reads) d.reads.add(p);
      const was = d.inputs.get(it.key);
      const mergeable = was && ((isObject(was.value) && isObject(it.value.value)) || (Array.isArray(was.value) && Array.isArray(it.value.value)));
      d.inputs.set(it.key, deep && mergeable ? { ...it.value, value: deepMerge(was!.value, it.value.value), constructs: [...new Set([...was!.constructs, ...it.value.constructs])], locals: [...was!.locals, ...it.value.locals], reads: [...was!.reads, ...it.value.reads] } : it.value);
    }
  };
  for (const p of parents) {
    if (p.merge === 'no_merge') continue;
    const got = inputsOf(p.file);
    if (typeof got === 'string') {
      d.problems.push(got);
      continue;
    }
    items.set(p.file, got);
    fold(got, p.merge === 'deep');
  }
  const own = inputsOf(child);
  if (typeof own === 'string') d.problems.push(own);
  else {
    items.set(child, own);
    // A child key merges deeply with what the last include that set it gave, when that include is deep.
    const lastDeep = new Map<string, boolean>();
    for (const p of parents) if (p.merge !== 'no_merge') for (const it of items.get(p.file) ?? []) lastDeep.set(it.key, p.merge === 'deep');
    for (const it of own) fold([it], lastDeep.get(it.key) ?? false);
  }

  // Everything else in these files is not evaluated. Each top-level part is kept by name with its exact
  // text (whitespace outside strings aside), so any edit to it is named: blocks, attributes, locals,
  // inputs whose value is not known, and files those inputs read. An input with a known value is
  // evaluated, and so is a local that only such inputs read; they are left out.
  const childExprs = [...child.body.attributes.map((a) => a.expr), ...child.body.blocks.flatMap((b) => blockExprs(b.body))];
  const exposed = new Set<string>();
  for (const e of childExprs) walk(e, (x) => {
    if (x.kind === 'getattr' && x.obj.kind === 'scope' && x.obj.name === 'include') exposed.add(x.name);
  });
  const active = [...parents.filter((p) => p.merge !== 'no_merge'), { label: '', file: child, merge: '' }];
  for (const { label, file: f } of active) {
    const where = f === child ? '' : ` (in include${label ? ` "${label}"` : ''})`;
    // A parent the child reads through include.<label> is not evaluated at all.
    const whole = f !== child && exposed.has(label);
    const known = new Set((items.get(f) ?? []).filter((it) => it.known && !whole).map((it) => it.key));
    const parts: Array<{ name: string; text: string; exprs: Expr[]; local?: string }> = [];
    for (const b of f.body.blocks) {
      if (b.type === 'dependencies' || (f === child && b.type === 'include')) continue;
      if (b.type === 'locals') {
        for (const a of b.body.attributes) parts.push({ name: `local.${a.name}`, text: canonical(f, a.range), exprs: [a.expr], local: a.name });
        continue;
      }
      if (b.type === 'generate') d.generates = true;
      // A dependency's mock outputs are used only where it has no state; they do not change what is applied.
      // terraform.source is evaluated: the module it names is what is compared.
      const attrs = b.type === 'dependency' ? b.body.attributes.filter((a) => !MOCK_ATTRIBUTES.test(a.name)) : b.type === 'terraform' ? b.body.attributes.filter((a) => a.name !== 'source') : undefined;
      const text = attrs ? attrs.map((a) => canonical(f, a.range)).join('\n') + b.body.blocks.map((x) => canonical(f, x.range)).join('\n') : canonical(f, b.range);
      parts.push({ name: `${b.type}${b.labels[0] ? ` "${b.labels[0]}"` : ''}`, text, exprs: blockExprs(b.body) });
    }
    for (const a of f.body.attributes) {
      if (a.name !== 'inputs') {
        parts.push({ name: a.name, text: canonical(f, a.range), exprs: [a.expr] });
        continue;
      }
      if (a.expr.kind === 'object') {
        for (const it of a.expr.items) {
          const key = literalKey(it.key);
          if (key !== undefined && known.has(key)) continue;
          parts.push({ name: `input ${key ?? '(computed key)'}`, text: canonical(f, { start: it.key.range.start, end: it.value.range.end }), exprs: [it.key, it.value] });
        }
      } else if (!(items.get(f) ?? []).every((it) => known.has(it.key)) || whole || !items.has(f)) {
        parts.push({ name: 'inputs', text: canonical(f, a.range), exprs: [a.expr] });
      }
    }
    // Locals read by something kept are kept; a local only known inputs read is evaluated with them.
    const needed = new Set<string>();
    const visit = (e: Expr) => walk(e, (x) => {
      if (x.kind === 'getattr' && x.obj.kind === 'scope' && x.obj.name === 'local' && !needed.has(x.name)) {
        needed.add(x.name);
        const def = f.locals.get(x.name);
        if (def) visit(def);
      }
    });
    for (const part of parts) if (!part.local) part.exprs.forEach(visit);
    for (const part of parts) if (!part.local || whole || needed.has(part.local)) d.elements.set(part.name + where, part.text);
    // Files that inputs not known statically read.
    for (const it of items.get(f) ?? []) if (!known.has(it.key)) for (const p of it.reads) d.elements.set(`file ${p}${where}`, source.readFile(p) ?? '(missing)');
  }
  return d;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v) && !isUnknown(v);
}

/** Terragrunt's deep merge: maps merge key by key, lists are appended, anything else the child sets wins. */
function deepMerge(a: unknown, b: unknown): unknown {
  if (Array.isArray(a) && Array.isArray(b)) return [...a, ...b];
  if (!isObject(a) || !isObject(b)) return b;
  const out: Record<string, unknown> = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = k in out ? deepMerge(out[k], v) : v;
  return out;
}

function isRemote(s: string): boolean {
  return /^[a-z0-9]+::/i.test(s) || /^(git@|https?:\/\/|tfr:\/\/|github\.com\/|bitbucket\.org\/|gitlab\.com\/)/i.test(s) || /^[\w.-]+\.[a-z]{2,}\/[\w.-]+\/[\w.-]+/i.test(s);
}

function attrOf(body: Body, name: string): Expr | undefined {
  return body.attributes.find((a) => a.name === name)?.expr;
}

function literalKey(e: Expr): string | undefined {
  if (e.kind === 'literal' && typeof e.value === 'string') return e.value;
  if (e.kind === 'template' && e.parts.every((p) => p.kind === 'text')) return e.parts.map((p) => (p.kind === 'text' ? p.value : '')).join('');
  return undefined;
}

function blockExprs(body: Body): Expr[] {
  return [...body.attributes.map((a) => a.expr), ...body.blocks.flatMap((b) => blockExprs(b.body))];
}

/** Pure path functions of Terragrunt, evaluated for one child. Paths are absolute from the repository root (`/env/app`). */
function pathFunctions(source: FileSource, childDir: string, includeDirs: Map<string, string>): (name: string, args: unknown[]) => unknown {
  const includeDir = (label: unknown) => (typeof label === 'string' ? includeDirs.get(label) : [...includeDirs.values()][0]);
  const exists = (p: string) => source.readFile(p) !== undefined || source.listFiles(p).length > 0;
  return (name, args) => {
    switch (name) {
      case 'get_terragrunt_dir':
      case 'get_original_terragrunt_dir':
        return abs(childDir);
      case 'get_parent_terragrunt_dir':
        return abs(includeDir(args[0]) ?? childDir);
      case 'get_repo_root':
        return '/';
      case 'get_path_from_repo_root':
        return childDir;
      case 'get_path_to_repo_root':
        return path.posix.relative(childDir === '.' ? '' : childDir, '') || '.';
      case 'path_relative_to_include':
        return path.posix.relative(includeDir(args[0]) ?? childDir, childDir) || '.';
      case 'path_relative_from_include':
        return path.posix.relative(childDir, includeDir(args[0]) ?? childDir) || '.';
      case 'find_in_parent_folders': {
        const target = typeof args[0] === 'string' ? args[0] : 'terragrunt.hcl';
        for (let d = childDir; d !== '.'; ) {
          d = path.posix.dirname(d);
          const p = normalize(path.posix.join(d, target));
          if (inside(p) && exists(p)) return abs(p);
        }
        return args.length > 1 ? args[1] : new Unknown(`find_in_parent_folders("${target}") finds nothing`);
      }
      default:
        return undefined;
    }
  };
}

const PATH_FUNCTIONS = new Set(['get_terragrunt_dir', 'get_original_terragrunt_dir', 'get_parent_terragrunt_dir', 'get_repo_root', 'get_path_from_repo_root', 'get_path_to_repo_root', 'path_relative_to_include', 'path_relative_from_include', 'find_in_parent_folders']);

/** Replace calls of the pure path functions by their values, when their arguments are literal. */
function substitute(e: Expr, fns: (name: string, args: unknown[]) => unknown): Expr {
  const s = (x: Expr) => substitute(x, fns);
  const parts = (ps: TemplatePart[]): TemplatePart[] =>
    ps.map((p) => {
      if (p.kind === 'interp') return { ...p, expr: s(p.expr) };
      if (p.kind === 'if') return { ...p, cond: s(p.cond), then: parts(p.then), else: parts(p.else) };
      if (p.kind === 'for') return { ...p, coll: s(p.coll), body: parts(p.body) };
      return p;
    });
  switch (e.kind) {
    case 'call': {
      const args = e.args.map(s);
      if (PATH_FUNCTIONS.has(e.name)) {
        const literal = args.map((a) => literalKey(a));
        if (literal.every((x) => x !== undefined)) {
          const v = fns(e.name, literal);
          if (typeof v === 'string') return { kind: 'literal', value: v, range: e.range };
        }
      }
      return { ...e, args };
    }
    case 'template': {
      // "${get_terragrunt_dir()}/x" becomes the text "/live/app/x".
      const folded = parts(e.parts).map((p): TemplatePart => (p.kind === 'interp' && p.expr.kind === 'literal' && typeof p.expr.value === 'string' ? { kind: 'text', value: p.expr.value } : p));
      return { ...e, parts: folded };
    }
    case 'tuple':
      return { ...e, items: e.items.map(s) };
    case 'object':
      return { ...e, items: e.items.map((i) => ({ key: s(i.key), value: s(i.value) })) };
    case 'getattr':
      return { ...e, obj: s(e.obj) };
    case 'index':
      return { ...e, obj: s(e.obj), key: s(e.key) };
    case 'splat':
      return { ...e, obj: s(e.obj) };
    case 'for':
      return { ...e, coll: s(e.coll), ...(e.keyExpr ? { keyExpr: s(e.keyExpr) } : {}), valExpr: s(e.valExpr), ...(e.cond ? { cond: s(e.cond) } : {}) };
    case 'unary':
      return { ...e, operand: s(e.operand) };
    case 'binary':
      return { ...e, left: s(e.left), right: s(e.right) };
    case 'conditional':
      return { ...e, cond: s(e.cond), then: s(e.then), else: s(e.else) };
    case 'paren':
      return { ...e, expr: s(e.expr) };
    default:
      return e;
  }
}

function walk(e: Expr, fn: (x: Expr) => void) {
  fn(e);
  switch (e.kind) {
    case 'template': {
      const visit = (ps: TemplatePart[]) => {
        for (const p of ps) {
          if (p.kind === 'interp') walk(p.expr, fn);
          else if (p.kind === 'if') { walk(p.cond, fn); visit(p.then); visit(p.else); }
          else if (p.kind === 'for') { walk(p.coll, fn); visit(p.body); }
        }
      };
      visit(e.parts);
      return;
    }
    case 'tuple': return e.items.forEach((x) => walk(x, fn));
    case 'object': return e.items.forEach((i) => { walk(i.key, fn); walk(i.value, fn); });
    case 'getattr': return walk(e.obj, fn);
    case 'index': walk(e.obj, fn); return walk(e.key, fn);
    case 'splat': walk(e.obj, fn); return walk(e.each, fn);
    case 'call': return e.args.forEach((x) => walk(x, fn));
    case 'for': walk(e.coll, fn); if (e.keyExpr) walk(e.keyExpr, fn); walk(e.valExpr, fn); if (e.cond) walk(e.cond, fn); return;
    case 'unary': return walk(e.operand, fn);
    case 'binary': walk(e.left, fn); return walk(e.right, fn);
    case 'conditional': walk(e.cond, fn); walk(e.then, fn); return walk(e.else, fn);
    case 'paren': return walk(e.expr, fn);
  }
}

/** Locals an expression reads, transitively. */
function localsRead(f: ParsedFile, e: Expr, seen = new Set<string>()): Set<string> {
  walk(e, (x) => {
    if (x.kind === 'getattr' && x.obj.kind === 'scope' && x.obj.name === 'local' && !seen.has(x.name)) {
      seen.add(x.name);
      const def = f.locals.get(x.name);
      if (def) localsRead(f, def, seen);
    }
  });
  return seen;
}

function localFingerprints(f: ParsedFile, e: Expr): string[] {
  return [...localsRead(f, e)].sort().map((n) => `local.${n} = ${f.locals.has(n) ? sliceOf(f, f.locals.get(n)!.range) : '(none)'}`);
}

/** What an expression reads that is not evaluated, itself and through locals. */
function constructsOf(f: ParsedFile, e: Expr): string[] {
  const out = new Set<string>();
  const visit = (x: Expr) => {
    if (x.kind === 'call' && IMPURE.has(x.name)) {
      const first = x.args[0] ? literalKey(x.args[0]) : undefined;
      out.add(`${x.name}(${first !== undefined ? JSON.stringify(first) : ''})`);
    }
    if (x.kind === 'getattr' && x.obj.kind === 'scope' && OUTSIDE.has(x.obj.name)) out.add(x.obj.name === 'dependency' ? `dependency.${x.name} outputs` : `${x.obj.name}.${x.name}`);
  };
  walk(e, visit);
  for (const n of localsRead(f, e)) {
    const def = f.locals.get(n);
    if (def) walk(def, visit);
  }
  return [...out].sort();
}

/** Functions whose first argument names a file they read. */
const FILE_READERS = new Set(['file', 'templatefile', 'filebase64', 'read_terragrunt_config', 'read_tfvars_file', 'sops_decrypt_file']);

interface Evaluated {
  value: unknown;
  /** Text of the expression and of everything it reads: locals, dependency blocks, included parents, files. */
  fingerprint: string;
  constructs: string[];
  /** Repository files it reads. */
  reads: string[];
  /** Locals it reads, transitively. */
  locals: string[];
}

/**
 * Evaluate an expression of one file: its locals, pure functions, path functions in the child's context.
 * `includes` holds the text of each parent by label, for inputs read from an exposed include.
 */
function evalIn(source: FileSource, f: ParsedFile, expr: Expr, fns: (name: string, args: unknown[]) => unknown, includes: Map<string, string> = new Map()): Evaluated {
  const constructs = constructsOf(f, expr);
  const resolvePath = (p: string) => fromAbs(p, f.dir);
  // What the expression reads, itself and through locals.
  const exprs = [expr, ...[...localsRead(f, expr)].map((n) => f.locals.get(n)).filter((x): x is Expr => Boolean(x))];
  const deps = new Set<string>();
  const exposed = new Set<string>();
  const reads = new Set<string>();
  for (const e of exprs) {
    walk(e, (x) => {
      if (x.kind === 'getattr' && x.obj.kind === 'scope' && x.obj.name === 'dependency') deps.add(x.name);
      if (x.kind === 'getattr' && x.obj.kind === 'scope' && x.obj.name === 'include') exposed.add(x.name);
    });
    walk(substitute(e, fns), (x) => {
      if (x.kind !== 'call' || !FILE_READERS.has(x.name) || !x.args[0]) return;
      const p = literalKey(x.args[0]);
      if (p !== undefined && inside(resolvePath(p))) reads.add(resolvePath(p));
    });
  }
  // Dependency blocks an input reads are part of what it depends on (their mocks are not), with the locals they read.
  const depText = [...deps].sort().map((name) => {
    const b = f.body.blocks.find((x) => x.type === 'dependency' && x.labels[0] === name);
    if (!b) return `dependency.${name}: (none)`;
    const attrs = b.body.attributes.filter((a) => !MOCK_ATTRIBUTES.test(a.name));
    return `dependency.${name}: ${attrs.map((a) => `${a.name} = ${sliceOf(f, a.expr.range)}`).join('; ')}\n${attrs.flatMap((a) => localFingerprints(f, a.expr)).join('\n')}`;
  });
  // An exposed include can read anything in the parent: all of its text counts.
  const exposedText = [...exposed].sort().map((label) => `include.${label}: ${includes.get(label) ?? '(none)'}`);
  const fileText = [...reads].sort().map((p) => `file ${p}: ${source.readFile(p) ?? '(missing)'}`);
  const fingerprint = [sliceOf(f, expr.range), ...localFingerprints(f, expr), ...depText, ...exposedText, ...fileText].join('\n');
  let locals: LazyMap | undefined;
  const scope: EvalScope = {
    root(name) {
      // One map for every reference, so a cycle between locals is found instead of recursing.
      if (name === 'local') return (locals ??= new LazyMap(new Map([...f.locals.keys()].map((k) => [k, () => evaluate(substitute(f.locals.get(k)!, fns), scope)]))));
      if (OUTSIDE.has(name)) return new Unknown(`${name} is not evaluated`);
      return undefined;
    },
    readFile(p) {
      // Relative to the file that holds the expression, or from the repository root; inside it only.
      const candidate = resolvePath(p);
      if (!inside(candidate)) return undefined;
      // Every file the evaluation reads is tracked, however its path was built.
      reads.add(candidate);
      return source.readFile(candidate);
    },
  };
  let value: unknown = constructs.length ? new Unknown(`reads ${constructs.join(', ')}`) : toPlain(evaluate(substitute(expr, fns), scope));
  if (value === undefined) value = new Unknown('not known statically');
  return { value, fingerprint, constructs, reads: [...reads], locals: [...localsRead(f, expr)] };
}

function keysOf(base: TerragruntDeployment | undefined, head: TerragruntDeployment): Set<string> {
  return new Set([...head.inputs.keys(), ...(base?.inputs.keys() ?? [])]);
}

/** True when two input values are the same, known value. */
export function sameKnownValue(a: unknown, b: unknown): boolean {
  return !containsUnknownDeep(a) && !containsUnknownDeep(b) && stableKey(a) === stableKey(b);
}

function containsUnknownDeep(v: unknown): boolean {
  if (isUnknown(v)) return true;
  if (Array.isArray(v)) return v.some(containsUnknownDeep);
  if (v && typeof v === 'object') return Object.values(v).some(containsUnknownDeep);
  return false;
}

/** Input values to pass as `TF_VAR_` variables: every input, unknown ones as unknown. */
export function inputValues(d: TerragruntDeployment | undefined): Record<string, unknown> {
  return Object.fromEntries([...(d?.inputs ?? new Map<string, TerragruntInput>())].map(([k, v]) => [k, v.value]));
}

/**
 * What a change to a deployment does that static replay does not evaluate, one line each. Empty when
 * everything it changes was evaluated. `declared` gives the variables of the module each side runs.
 */
export function unevaluatedChanges(base: TerragruntDeployment | undefined, head: TerragruntDeployment, declared: { head: Set<string>; base: Set<string> }): string[] {
  const out: string[] = [];
  for (const p of head.problems) out.push(p);
  if (!head.problems.length) for (const p of base?.problems ?? []) out.push(`${p} at the base`);
  const names = new Set([...head.elements.keys(), ...(base?.elements.keys() ?? [])]);
  for (const n of [...names].sort()) {
    const was = base?.elements.get(n);
    const now = head.elements.get(n);
    if (was === now) continue;
    const input = /^input (\S+)(?: \(in include.*\))?$/.exec(n)?.[1];
    const reads = (k: string) => {
      const constructs = [...new Set([...(base?.inputs.get(k)?.constructs ?? []), ...(head.inputs.get(k)?.constructs ?? [])])];
      return constructs.length ? `input ${k} reads ${constructs.join(', ')}` : `input ${k} is not known statically`;
    };
    if (input) {
      out.push(reads(input));
      continue;
    }
    // A local, a file or an exposed parent changes: name the inputs that are not known and read it.
    const via = /^local\.(\S+)$/.exec(n)?.[1];
    const file = n.startsWith('file ') ? n.slice(5).replace(/ \(in include.*\)$/, '') : undefined;
    const label = / \(in include(?: "([^"]*)")?\)$/.exec(n)?.[1];
    const affected = [...keysOf(base, head)].filter((k) => {
      const its = [base?.inputs.get(k), head.inputs.get(k)].filter((x): x is TerragruntInput => Boolean(x));
      return its.some((i) => (via !== undefined && i.locals.includes(via)) || (file !== undefined && i.reads.includes(file)) || (label !== undefined && i.constructs.includes(`include.${label}`)));
    });
    const what = file ?? n;
    if (affected.length) {
      for (const k of affected) out.push(`${reads(k)} (${what} changes)`);
      continue;
    }
    out.push(`${n} ${was === undefined ? 'is added' : now === undefined ? 'is removed' : 'changes'}, and Diffseal does not evaluate it`);
  }
  // Inputs with known values were evaluated; one the module does not declare goes nowhere Diffseal can see.
  const keys = new Set([...head.inputs.keys(), ...(base?.inputs.keys() ?? [])]);
  for (const k of [...keys].sort()) {
    const was = base?.inputs.get(k);
    const now = head.inputs.get(k);
    if (was && now && sameKnownValue(was.value, now.value)) continue;
    if (out.some((l) => l.startsWith(`input ${k} `))) continue;
    const undeclared = (now && !declared.head.has(k)) || (was && !declared.base.has(k));
    if (undeclared) out.push(`input ${k}, which ${head.moduleDir ?? 'its module'} does not declare${head.generates || base?.generates ? ' (a generate block may declare it)' : ''}`);
  }
  return [...new Set(out)];
}
