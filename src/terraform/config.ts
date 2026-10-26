import {parseJsonConfig} from '../hcl/json.js';
import * as path from 'node:path';
import type { Attribute, Block, Body, Expr, ParseDiagnostic } from '../hcl/ast.js';
import { parseHcl } from '../hcl/parser.js';
import { normalize, type FileSource } from './source.js';

/** One Terraform module directory: every `.tf` file in it, parsed and indexed by block kind. */
export interface ModuleConfig {
  dir: string;
  files: string[];
  variables: Map<string, Block>;
  locals: Map<string, { attr: Attribute; file: string }>;
  outputs: Map<string, Block>;
  resources: Map<string, ResourceBlock>;
  data: Map<string, ResourceBlock>;
  moduleCalls: Map<string, ModuleCall>;
  moved: Array<{ from: string; to: string }>;
  removed: Array<{ from: string; destroy: boolean }>;
  imports: Array<{ to: string }>;
  hasBackend: boolean;
  /** AWS account ids this module's provider blocks target (assume_role ARNs, allowed_account_ids). */
  providerAccounts: string[];
  providers: Map<string, Block>;
  diagnostics: Array<ParseDiagnostic & { file: string }>;
  /** File name -> source text, for slicing expressions back to text. */
  sources: Map<string, string>;
}

export interface ResourceBlock {
  type: string;
  name: string;
  mode: 'managed' | 'data';
  block: Block;
  file: string;
}

export interface ModuleCall {
  name: string;
  block: Block;
  file: string;
  /** Raw `source` string. */
  source?: string;
  /** Resolved directory for local sources, undefined for registry/git sources. */
  localDir?: string;
  version?: string;
}

const attr = (body: Body, name: string) => body.attributes.find((a) => a.name === name);

/** Literal string of an attribute, if it is a plain string. */
export function literalString(expr: Expr | undefined): string | undefined {
  if (!expr) return undefined;
  if (expr.kind === 'template' && expr.parts.every((p) => p.kind === 'text')) {
    return expr.parts.map((p) => (p.kind === 'text' ? p.value : '')).join('');
  }
  if (expr.kind === 'literal' && typeof expr.value === 'string') return expr.value;
  return undefined;
}

/** The source text of an expression; used for moved/removed/import addresses. */
export function exprText(src: string, expr: Expr): string {
  const text = src.slice(expr.range.start.offset, expr.range.end.offset).trim();
  if (expr.kind !== 'template' && expr.kind !== 'literal' && text.startsWith('"')) {try {const value=JSON.parse(text);if(typeof value==='string')return value;}catch{}}
  return text;
}

export const isConfigFile=(name:string):boolean=>name.endsWith('.tf')||name.endsWith('.tf.json')||name.endsWith('.tofu');

const cache = new WeakMap<FileSource, Map<string, ModuleConfig | undefined>>();

export function loadModule(source: FileSource, dir: string): ModuleConfig | undefined {
  const d = normalize(dir);
  let perSource = cache.get(source);
  if (!perSource) cache.set(source, (perSource = new Map()));
  if (perSource.has(d)) return perSource.get(d);

  const files = source.listFiles(d).filter(isConfigFile).sort();
  if (!files.length) {
    perSource.set(d, undefined);
    return undefined;
  }
  if ('prefetch' in source && typeof source.prefetch === 'function') {
    (source.prefetch as (p: string[]) => void)(files.map((f) => path.posix.join(d, f)));
  }

  const mod: ModuleConfig = {
    dir: d,
    files,
    variables: new Map(),
    locals: new Map(),
    outputs: new Map(),
    resources: new Map(),
    data: new Map(),
    moduleCalls: new Map(),
    moved: [],
    removed: [],
    imports: [],
    hasBackend: false,
    providerAccounts: [],
    providers: new Map(),
    diagnostics: [],
    sources: new Map(),
  };

  // OpenTofu: a .tofu file overrides the .tf file of the same name.
  const tofuStems = new Set(files.filter((f) => f.endsWith('.tofu')).map((f) => f.slice(0, -5)));
  // Override files are read after all others, in lexical order, and merge into the blocks they name.
  const isOverride = (f: string) => /(^|_)override\.(tf|tofu)(?:\.json)?$/.test(f);
  for (const file of [...files.filter((f) => !isOverride(f)), ...files.filter(isOverride)]) {
    if (file.endsWith('.tf') && tofuStems.has(file.slice(0, -3))) continue;
    const rel = path.posix.join(d, file);
    const src = source.readFile(rel) ?? '';
    mod.sources.set(rel, src);
    const { body, diagnostics } = file.endsWith('.json') ? parseJsonConfig(src, rel) : parseHcl(src, rel);
    for (const diag of diagnostics) mod.diagnostics.push({ ...diag, file: rel });
    for (const b of body.blocks) {
      const merged = isOverride(file) ? overrideBlock(mod, b) : undefined;
      if (merged) indexBlock(mod, merged.block, merged.file, src);
      else indexBlock(mod, b, rel, src);
    }
  }

  for (const call of mod.moduleCalls.values()) {
    if (call.localDir && source.allowsModulePath?.(d, call.localDir) === false) call.localDir = undefined;
    if (!call.localDir && call.source && !call.source.startsWith('./') && !call.source.startsWith('../') && !(call.version === undefined && call.block.body.attributes.some((attr) => attr.name === 'version'))) call.localDir = source.resolveModule?.(call.source, call.version);
  }
  perSource.set(d, mod);
  return mod;
}

/**
 * The original block an override block names, merged with it. Locals need no merge: indexing replaces
 * them by name. Blocks with nothing to override are indexed as they are.
 */
function overrideBlock(mod: ModuleConfig, b: Block): { block: Block; file: string } | undefined {
  const [l0, l1] = b.labels;
  let original: { block: Block; file: string } | undefined;
  if (b.type === 'resource' || b.type === 'data') original = (b.type === 'resource' ? mod.resources : mod.data).get(`${l0}.${l1}`);
  else if (b.type === 'module') original = l0 ? mod.moduleCalls.get(l0) : undefined;
  else if (b.type === 'variable' || b.type === 'output') {
    const block = l0 ? (b.type === 'variable' ? mod.variables : mod.outputs).get(l0) : undefined;
    original = block && { block, file: '' };
  }
  if (!original) return undefined;
  return { block: { ...original.block, body: mergeBody(original.block.body, b.body) }, file: original.file };
}

/**
 * Terraform's override merge: arguments replace arguments of the same name; nested blocks of a type the
 * override contains replace every original nested block of that type (`dynamic "x"` counts as type x);
 * `lifecycle` merges argument by argument.
 */
function mergeBody(original: Body, override: Body): Body {
  const names = new Set(override.attributes.map((a) => a.name));
  const kind = (x: Block) => (x.type === 'dynamic' ? (x.labels[0] ?? '') : x.type);
  const replaced = new Set(override.blocks.map(kind).filter((k) => k !== 'lifecycle'));
  const blocks = original.blocks.filter((x) => !replaced.has(kind(x)));
  for (const ob of override.blocks) {
    const i = ob.type === 'lifecycle' ? blocks.findIndex((x) => x.type === 'lifecycle') : -1;
    if (i >= 0) blocks[i] = { ...blocks[i], body: mergeBody(blocks[i].body, ob.body) };
    else blocks.push(ob);
  }
  return { ...original, attributes: [...original.attributes.filter((a) => !names.has(a.name)), ...override.attributes], blocks };
}

function indexBlock(mod: ModuleConfig, b: Block, file: string, src: string) {
  switch (b.type) {
    case 'variable':
      if (b.labels[0]) mod.variables.set(b.labels[0], b);
      break;
    case 'locals':
      for (const a of b.body.attributes) mod.locals.set(a.name, { attr: a, file });
      break;
    case 'output':
      if (b.labels[0]) mod.outputs.set(b.labels[0], b);
      break;
    case 'resource':
    case 'data': {
      const [type, name] = b.labels;
      if (!type || !name) break;
      const mode = b.type === 'resource' ? 'managed' : 'data';
      (mode === 'managed' ? mod.resources : mod.data).set(`${type}.${name}`, { type, name, mode, block: b, file });
      break;
    }
    case 'module': {
      const name = b.labels[0];
      if (!name) break;
      const sourceStr = literalString(attr(b.body, 'source')?.expr);
      const local = sourceStr && (sourceStr.startsWith('./') || sourceStr.startsWith('../'));
      mod.moduleCalls.set(name, {
        name,
        block: b,
        file,
        source: sourceStr,
        localDir: local ? normalize(path.posix.join(mod.dir, sourceStr!)) : undefined,
        version: literalString(attr(b.body, 'version')?.expr),
      });
      break;
    }
    case 'moved': {
      const from = attr(b.body, 'from');
      const to = attr(b.body, 'to');
      if (from && to) mod.moved.push({ from: exprText(src, from.expr), to: exprText(src, to.expr) });
      break;
    }
    case 'removed': {
      const from = attr(b.body, 'from');
      const lifecycle = b.body.blocks.find((x) => x.type === 'lifecycle');
      const destroy = lifecycle ? attr(lifecycle.body, 'destroy') : undefined;
      const destroyFalse = destroy?.expr.kind === 'literal' && destroy.expr.value === false;
      if (from) mod.removed.push({ from: exprText(src, from.expr), destroy: !destroyFalse });
      break;
    }
    case 'import': {
      const to = attr(b.body, 'to');
      if (to) mod.imports.push({ to: exprText(src, to.expr) });
      break;
    }
    case 'provider': {
      if (b.labels[0] !== 'aws') break;
      const alias = literalString(attr(b.body, 'alias')?.expr);
      mod.providers.set(alias ? `aws.${alias}` : 'aws', b);
      const roleArn = literalString(b.body.blocks.find((x) => x.type === 'assume_role')?.body.attributes.find((a) => a.name === 'role_arn')?.expr);
      const acct = roleArn?.match(/^arn:aws[\w-]*:iam::(\d{12}):/)?.[1];
      if (acct) mod.providerAccounts.push(acct);
      const allowed = attr(b.body, 'allowed_account_ids')?.expr;
      if (allowed?.kind === 'tuple') for (const i of allowed.items) { const v = literalString(i); if (v) mod.providerAccounts.push(v); }
      break;
    }
    case 'terraform':
      if (b.body.blocks.some((x) => x.type === 'backend' || x.type === 'cloud')) mod.hasBackend = true;
      break;
  }
}

/** Local module directories this module calls, recursively (including itself). */
export function moduleClosure(source: FileSource, dir: string, seen = new Set<string>()): Set<string> {
  const d = normalize(dir);
  if (seen.has(d)) return seen;
  const mod = loadModule(source, d);
  if (!mod) return seen;
  seen.add(d);
  for (const call of mod.moduleCalls.values()) if (call.localDir) moduleClosure(source, call.localDir, seen);
  return seen;
}

/**
 * Root modules: directories with a backend or cloud block, Terragrunt directories, and directories with
 * resources that no other configuration calls as a module.
 */
export function discoverRoots(source: FileSource, under?: string): string[] {
  const prefix = under && normalize(under) !== '.' ? normalize(under) + '/' : undefined;
  const all = source.allFiles();
  const skip = (f: string) => /(^|\/)(\.terraform|\.claude|\.worktrees|node_modules)\//.test(f);
  const dirs = new Set<string>();
  const terragrunt = new Set<string>();
  for (const f of all) {
    if (skip(f) || (prefix && !f.startsWith(prefix))) continue;
    if (isConfigFile(f)) dirs.add(path.posix.dirname(f));
    if (f.endsWith('terragrunt.hcl')) terragrunt.add(path.posix.dirname(f));
  }
  const called = new Set<string>();
  for (const f of all) {
    if (skip(f) || !isConfigFile(f)) continue;
    for (const call of loadModule(source, path.posix.dirname(f))?.moduleCalls.values() ?? []) if (call.localDir) called.add(call.localDir);
  }
  return [...dirs]
    .filter((d) => {
      const mod = loadModule(source, d);
      if (!mod) return false;
      if (mod.hasBackend || terragrunt.has(d)) return true;
      return !called.has(d) && (mod.resources.size > 0 || mod.moduleCalls.size > 0 || mod.diagnostics.length > 0);
    })
    .sort();
}
