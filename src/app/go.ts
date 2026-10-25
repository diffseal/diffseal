import * as path from 'node:path';
import { COPY_OPERATIONS, RESOURCE_FIELDS, actionsFor, copySourceBucket, formatToGlob, serviceHint } from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead, ResourceRef } from './facts.js';
import { visibleInBlocks } from './scope.js';

/*
 * Go extraction for the AWS SDK (v2, and v1 package paths). It is lexical, not type-checked: it finds
 * `&svc.OperationInput{...}` literals, reads the resource field, and follows simple local data flow
 * (literals, fmt.Sprintf, env reads, local assignments). Anything else is reported as unresolved.
 */

export interface SourceFile {
  path: string;
  content: string;
}

const SDK_PACKAGE = /^github\.com\/aws\/aws-sdk-go(?:-v2)?\/service\/([a-z0-9]+)$/;

export function parseImports(src: string): Map<string, string> {
  const out = new Map<string, string>();
  const add = (alias: string | undefined, p: string) => {
    if (alias === '_' || alias === '.') return;
    const segs = p.split('/');
    let name = segs[segs.length - 1];
    if (/^v\d+$/.test(name) && segs.length > 1) name = segs[segs.length - 2];
    out.set(alias ?? name.replace(/[^A-Za-z0-9_]/g, ''), p);
  };
  for (const m of src.matchAll(/^import\s+(?:([A-Za-z_.]\w*)\s+)?"([^"]+)"/gm)) add(m[1], m[2]);
  for (const block of src.matchAll(/^import\s*\(([\s\S]*?)^\)/gm)) {
    for (const m of block[1].matchAll(/^\s*(?:([A-Za-z_.]\w*)\s+)?"([^"]+)"/gm)) add(m[1], m[2]);
  }
  return out;
}

/** Index of the matching closing brace, skipping strings, runes and comments. */
export function matchBrace(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'") {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
    } else if (c === '`') {
      i = src.indexOf('`', i + 1);
      if (i < 0) return src.length - 1;
    } else if (c === '/' && src[i + 1] === '/') {
      i = src.indexOf('\n', i);
      if (i < 0) return src.length - 1;
    } else if (c === '/' && src[i + 1] === '*') {
      i = src.indexOf('*/', i + 2) + 1;
      if (i <= 0) return src.length - 1;
    } else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return src.length - 1;
}

/** Split at top-level commas (outside (), [], {}, strings). */
export function splitTopLevel(s: string, sep = ','): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'") {
      for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++;
    } else if (c === '`') {
      const j = s.indexOf('`', i + 1);
      i = j < 0 ? s.length : j;
    } else if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === sep && depth === 0) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** The expression with string contents and everything inside brackets blanked, offsets kept: its top level. */
export function topLevelOnly(s: string): string {
  let out = '';
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < s.length && s[j] !== c) j += s[j] === '\\' ? 2 : 1;
      out += ' '.repeat(Math.min(j, s.length - 1) - i + 1);
      i = j;
    } else if ('([{'.includes(c)) {
      depth++;
      out += ' ';
    } else if (')]}'.includes(c)) {
      depth--;
      out += ' ';
    } else out += depth > 0 ? ' ' : c;
  }
  return out;
}

const lineAt = (src: string, offset: number) => src.slice(0, offset).split('\n').length;

function unquote(lit: string): string | undefined {
  if (/^"(?:[^"\\]|\\.)*"$/.test(lit)) {
    try {
      return JSON.parse(lit);
    } catch {
      return lit.slice(1, -1);
    }
  }
  if (/^`[^`]*`$/.test(lit)) return lit.slice(1, -1);
  return undefined;
}

// The whole expression: `os.Getenv("X") + "-y"` is not the env value.
// A default that is not a literal (`getEnv("TABLE", defaultTable)`, `envOr("B", cfg.Bucket)`) is not a
// known value, but the call is still the env read.
const ENV_CALL = /^(?:os\.Getenv|os\.LookupEnv|[\w.]*[Ee]nv[\w.]*)\(\s*(?:ctx\s*,\s*)?"([A-Za-z_][A-Za-z0-9_]*)"(?:\s*,\s*(?:"((?:[^"\\]|\\.)*)"|[\w.]+))?\s*\)$/;

/** Follow an expression to a literal, pattern or env var, looking backwards for local assignments. */
export function classifyGoExpr(expr: string, src: string, offset: number, depth = 0): ResourceRef {
  let e = expr.trim();
  for (let changed = true; changed; ) {
    changed = false;
    const m = e.match(/^(?:aws\.String|aws\.ToString|strings\.TrimSpace|string|new)\(([\s\S]*)\)$/) ?? e.match(/^&([\s\S]+)$/) ?? e.match(/^\(([\s\S]*)\)$/);
    if (m) {
      e = m[1].trim();
      changed = true;
    }
  }
  const lit = unquote(e);
  if (lit !== undefined) return { kind: 'literal', value: lit };
  const sprintf = e.match(/^fmt\.Sprintf\(\s*("(?:[^"\\]|\\.)*")/);
  if (sprintf) return { kind: 'pattern', glob: formatToGlob(unquote(sprintf[1]) ?? '') };
  const env = e.match(ENV_CALL);
  if (env) return env[2] ? { kind: 'env', name: env[1], fallback: env[2] } : { kind: 'env', name: env[1] };

  const parts = splitTopLevel(e, '+');
  if (parts.length > 1) {
    const pieces = parts.map((p) => classifyGoExpr(p, src, offset, depth + 1));
    if (pieces.some((p) => p.kind === 'literal')) {
      return { kind: 'pattern', glob: pieces.map((p) => (p.kind === 'literal' ? p.value : p.kind === 'pattern' ? p.glob : '*')).join('') };
    }
  }

  if (/^[A-Za-z_]\w*$/.test(e) && depth < 4) {
    const before = src.slice(0, offset);
    // Only assignments in blocks that enclose the use count, unless a function between them takes `e`.
    const visible = (m: RegExpMatchArray) => visibleInBlocks(src, (m.index ?? 0) + m[0].indexOf(e), offset, e);
    const all = [...before.matchAll(new RegExp(`(?:^|[\\s,(])${e}(?:\\s*,\\s*\\w+)?\\s*:?=(?!=)\\s*(\\S[^\\n]*)`, 'g'))];
    const assigns = all.filter(visible);
    const last = assigns[assigns.length - 1];
    // `table = name` inside an `if` after the visible assignment changes the variable on some paths only.
    const conditional = last && all.some((m) => (m.index ?? 0) > (last.index ?? 0) && !visible(m) && !/:=/.test(m[0]));
    if (conditional) return { kind: 'unresolved', text: e };
    // The value ends at the statement: `if t := os.Getenv("X"); t != "" {` assigns only os.Getenv("X").
    if (last) {
      // `ctx = trace.Start(ctx, ...)`: the text before the call ends inside its own assignment, so the
      // value may be blank; that is not a value.
      const value = splitTopLevel(last[1].replace(/\s*\/\/.*$/, ''), ';')[0];
      return value?.trim() ? classifyGoExpr(value, src, last.index ?? 0, depth + 1) : { kind: 'unresolved', text: e };
    }
    const decl = [...src.matchAll(new RegExp(`(?:const|var)\\s+${e}(?:\\s+\\w+)?\\s*=\\s*([^\\n]+)`, 'g'))].find(visible);
    if (decl) return classifyGoExpr(decl[1], src, decl.index ?? 0, depth + 1);
  }
  return { kind: 'unresolved', text: e };
}

interface SdkCall {
  service: string;
  operation: string;
  start: number;
  end: number;
  resourceExpr?: string;
  indexExpr?: string;
  copySourceExpr?: string;
}

function sdkCalls(src: string, imports: Map<string, string>): SdkCall[] {
  const out: SdkCall[] = [];
  for (const m of src.matchAll(/([A-Za-z_]\w*)\.([A-Z]\w*)Input\s*\{/g)) {
    const pkg = imports.get(m[1]);
    const svc = pkg?.match(SDK_PACKAGE)?.[1];
    if (!svc) continue;
    const open = m.index! + m[0].length - 1;
    const close = matchBrace(src, open);
    const fields = new Map<string, string>();
    for (const part of splitTopLevel(src.slice(open + 1, close))) {
      const f = part.match(/^([A-Z]\w*)\s*:\s*([\s\S]+)$/);
      if (f) fields.set(f[1], f[2].trim());
    }
    const field = (RESOURCE_FIELDS[svc] ?? []).find((f) => fields.has(f));
    out.push({ service: svc, operation: m[2], start: m.index!, end: close, resourceExpr: field ? fields.get(field) : undefined, indexExpr: fields.get('IndexName'), copySourceExpr: fields.get('CopySource') });
  }
  return out;
}

function inAdded(added: Set<number> | undefined, src: string, start: number, end: number): boolean {
  if (!added) return true;
  const a = lineAt(src, start);
  const b = lineAt(src, end);
  for (let l = a; l <= b; l++) if (added.has(l)) return true;
  return false;
}

/** The index name for a DynamoDB call, or '*' when it is not a literal. */
export function indexName(ref: ResourceRef): string {
  return ref.kind === 'literal' ? ref.value : '*';
}

export function envReadsGo(src: string, file: string, added?: Set<number>): EnvRead[] {
  const out: EnvRead[] = [];
  const patterns: Array<[RegExp, (m: RegExpMatchArray) => boolean]> = [
    [/os\.Getenv\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g, () => false],
    [/os\.LookupEnv\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g, () => true],
    [/\b[\w.]*[Ee]nv\.(\w+)\(\s*ctx\s*,\s*"([A-Za-z_][A-Za-z0-9_]*)"(\s*,)?/g, (m) => /OrElse|Default|Lookup|Optional/i.test(m[1]) || Boolean(m[3])],
    [/`[^`]*\benv:"([A-Za-z_][A-Za-z0-9_]*)[",][^`]*`/g, (m) => /envDefault:/.test(m[0])],
  ];
  for (const [re, hasDefault] of patterns) {
    for (const m of src.matchAll(re)) {
      const line = lineAt(src, m.index!);
      if (added && !added.has(line)) continue;
      const name = m.length > 3 && m[2] ? m[2] : m[1];
      out.push({ name, file, line, ...(hasDefault(m) ? { hasDefault: true } : {}) });
    }
  }
  return out;
}

export interface ExtractOptions {
  addedLines?: AddedLines;
  index?: GoIndex;
  /** Directory of the go.mod the files belong to, relative to their paths; `.` by default. */
  moduleDir?: string;
}

/**
 * Go source with line and block comments blanked out (offsets and newlines kept), so SDK calls and
 * env reads in comments are not extracted. Strings, raw strings and runes are left as they are.
 */
export function withoutGoComments(src: string): string {
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      const end = src.indexOf('\n', i);
      const j = end < 0 ? src.length : end;
      out += ' '.repeat(j - i);
      i = j - 1;
    } else if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const j = end < 0 ? src.length : end + 2;
      out += src.slice(i, j).replace(/[^\n]/g, ' ');
      i = j - 1;
    } else if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== c && (c === '`' || src[j] !== '\n')) j += c !== '`' && src[j] === '\\' ? 2 : 1;
      out += src.slice(i, Math.min(j + 1, src.length));
      i = j;
    } else out += c;
  }
  return out;
}

export function extractGo(files: SourceFile[], opts: ExtractOptions = {}): AppScan {
  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];
  for (const file of files) {
    const f = { ...file, content: withoutGoComments(file.content) };
    if (!f.path.endsWith('.go') || f.path.endsWith('_test.go')) continue;
    const added = opts.addedLines?.get(f.path);
    if (opts.addedLines && !added) continue;
    const imports = parseImports(f.content);
    envReads.push(...envReadsGo(f.content, f.path, added));

    const funcs = goFunctions(f.content);
    for (const call of sdkCalls(f.content, imports)) {
      if (!inAdded(added, f.content, call.start, call.end)) continue;
      const resource: ResourceRef = call.resourceExpr ? classifyGoExpr(call.resourceExpr, f.content, call.start) : { kind: 'unresolved', text: '(no resource field)' };
      const fn = funcs.find((x) => x.bodyStart < call.start && call.start < x.bodyEnd);
      const internal =
        resource.kind === 'unresolved' && fn !== undefined &&
        (fn.params.includes(resource.text) || (fn.receiverVar !== undefined && resource.text.startsWith(`${fn.receiverVar}.`)));
      facts.push({
        service: call.service,
        operation: call.operation,
        actions: actionsFor(call.service, call.operation),
        resource,
        file: f.path,
        line: lineAt(f.content, call.start),
        ...(internal ? { internal: true } : {}),
        ...(call.indexExpr ? { index: indexName(classifyGoExpr(call.indexExpr, f.content, call.start)) } : {}),
      });
      if (call.service === 's3' && COPY_OPERATIONS.has(call.operation)) {
        facts.push({
          service: 's3',
          operation: 'GetObject',
          actions: ['s3:GetObject'],
          resource: call.copySourceExpr ? copySourceBucket(classifyGoExpr(call.copySourceExpr, f.content, call.start), call.copySourceExpr) : { kind: 'unresolved', text: '(no CopySource)' },
          file: f.path,
          line: lineAt(f.content, call.start),
        });
      }
    }

    if (opts.index) {
      const dir = opts.moduleDir ?? '.';
      const ownPackage = opts.index.packageOf(dir === '.' ? f.path : f.path.slice(dir.length + 1));
      facts.push(...helperCalls(f, imports, opts.index, added, ownPackage));
    }
  }
  return { facts: dedupeFacts(facts), envReads: dedupeEnv(envReads) };
}

interface HelperCall {
  pkg: string;
  name: string;
  /** How the call is written, for the report: `pubsub.NewSNSPublisher`, or `getSecret` in the same package. */
  via: string;
  start: number;
  open: number;
}

/** Calls to helpers of this repository: package-qualified ones, and plain calls to functions of the file's own package. */
function helperCallSites(f: SourceFile, imports: Map<string, string>, index: GoIndex, ownPackage: string | undefined): HelperCall[] {
  const out: HelperCall[] = [];
  for (const m of f.content.matchAll(/\b([A-Za-z_]\w*)\.([A-Z]\w*)\s*(\[[^\]\n]*\])?\s*\(/g)) {
    const pkg = imports.get(m[1]);
    if (pkg && index.has(pkg)) out.push({ pkg, name: m[2], via: `${m[1]}.${m[2]}`, start: m.index!, open: m.index! + m[0].length - 1 });
  }
  if (ownPackage && index.has(ownPackage)) {
    for (const m of f.content.matchAll(/(^|[^.\w])([A-Za-z_]\w*)\s*\(/g)) {
      const start = m.index! + m[1].length;
      // `func getSecret(` and `func (r *T) getSecret(` define it; they do not call it.
      if (/\bfunc\s*(\([^)]*\)\s*)?$/.test(f.content.slice(f.content.lastIndexOf('\n', start) + 1, start))) continue;
      if (!index.opsFor(ownPackage, m[2]).length && !index.constructedType(ownPackage, m[2])) continue;
      out.push({ pkg: ownPackage, name: m[2], via: m[2], start, open: m.index! + m[0].length - 1 });
    }
  }
  return out;
}

function helperCalls(f: SourceFile, imports: Map<string, string>, index: GoIndex, added: Set<number> | undefined, ownPackage?: string): AccessFact[] {
  const out: AccessFact[] = [];
  const funcs = goFunctions(f.content);
  for (const call of helperCallSites(f, imports, index, ownPackage)) {
    const { pkg, open } = call;
    const close = matchParen(f.content, open);
    if (!inAdded(added, f.content, call.start, close)) continue;

    // For a constructor, keep the operations of the methods this file calls on the returned value.
    // If the value escapes (passed on, stored), the other methods' operations are only possible.
    let ops = index.opsFor(pkg, call.name).map((op) => ({ ...op, possible: false, fromType: false }));
    const type = index.constructedType(pkg, call.name);
    if (type) {
      const bound = f.content.slice(f.content.lastIndexOf('\n', call.start) + 1, call.start).match(/([A-Za-z_]\w*)(?:\s*,\s*\w+)?\s*:?=\s*$/)?.[1];
      const rest = f.content.slice(close);
      const called = bound ? [...rest.matchAll(new RegExp(`\\b${bound}\\.([A-Z]\\w*)\\s*\\(`, 'g'))].map((x) => x[1]) : [];
      const uses = bound ? [...rest.matchAll(new RegExp(`\\b${bound}\\b`, 'g'))].length : 0;
      const escapes = bound !== '_' && (!bound || uses > called.length);
      const certain = new Set(called.flatMap((meth) => index.methodOps(pkg, type, meth)).map((o) => `${o.service}:${o.operation}`));
      const own = new Set(ops.map((o) => `${o.service}:${o.operation}`));
      ops = [
        ...ops,
        ...index
          .typeOps(pkg, type)
          .filter((o) => !own.has(`${o.service}:${o.operation}`) && (certain.has(`${o.service}:${o.operation}`) || escapes))
          .map((o) => ({ ...o, possible: !certain.has(`${o.service}:${o.operation}`), fromType: true })),
      ];
    }
    if (!ops.length) continue;

    const rawArgs = splitTopLevel(f.content.slice(open + 1, close));
    const args = rawArgs.map((a) => classifyGoExpr(a, f.content, call.start));
    const resolvable = args.filter((a) => a.kind !== 'unresolved');
    const services = new Set(ops.map((o) => o.service));
    for (const op of ops) {
      // The helper's own parameter (or the constructor parameter stored in the field it uses) names the
      // resource. Without that, use the only resolvable argument, or one whose name points at the
      // service; anything ambiguous stays unresolved rather than guessed.
      // A method's parameter index means nothing at the constructor call; only fields the constructor sets do.
      const position = op.fromType ? (op.field ? index.ctorParam(pkg, call.name, op.field) : undefined) : op.param;
      const byPosition = position !== undefined && position < args.length ? args[position] : undefined;
      const fallback = op.fixed
        ? op.fixed
        : op.derived
        ? undefined
        : services.size === 1 && resolvable.length === 1
          ? resolvable[0]
          : resolvable.find((a) => serviceHint(a) === op.service);
      const found = byPosition ?? fallback;
      const resource = found && op.format && byPosition ? formatted(op.format, found) : (found ?? { kind: 'unresolved' as const, text: `arguments of ${call.via}` });
      // A helper passing its own parameter on to another helper: its callers name the resource.
      const fn = funcs.find((x) => x.bodyStart < call.start && call.start < x.bodyEnd);
      const internal = resource.kind === 'unresolved' && fn !== undefined && fn.params.includes(resource.text);
      out.push({
        service: op.service,
        operation: op.operation,
        actions: actionsFor(op.service, op.operation),
        resource,
        file: f.path,
        line: lineAt(f.content, call.start),
        via: call.via,
        viaPackage: pkg,
        ...(internal ? { internal: true } : {}),
        ...indexAt(op, rawArgs),
        ...(op.possible ? { possible: true } : {}),
      });
    }
  }
  return out;
}

/** A helper's `fmt.Sprintf(format, x)` with the call site's value for x. */
function formatted(format: string, value: ResourceRef): ResourceRef {
  const unescaped = format.replace(/%%/g, '%');
  if (value.kind === 'literal') return { kind: 'literal', value: unescaped.replace(/%[sv]/, value.value) };
  if (value.kind === 'pattern') return { kind: 'pattern', glob: unescaped.replace(/%[sv]/, value.glob) };
  return { kind: 'pattern', glob: unescaped.replace(/%[sv]/, '*') };
}

function matchParen(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'") {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
    } else if (c === '`') i = src.indexOf('`', i + 1);
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return i;
    if (i < 0) break;
  }
  return src.length - 1;
}

function dedupeFacts(fs: AccessFact[]): AccessFact[] {
  const seen = new Set<string>();
  return fs.filter((f) => {
    const k = `${f.file}:${f.line}:${f.operation}:${JSON.stringify(f.resource)}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

function dedupeEnv(es: EnvRead[]): EnvRead[] {
  const seen = new Set<string>();
  return es.filter((e) => {
    const k = `${e.file}:${e.line}:${e.name}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

interface Op {
  service: string;
  operation: string;
  /** Index of the function parameter that becomes the SDK resource field, when it is passed directly. */
  param?: number;
  /** Receiver field that becomes the resource (`p.topic`), for methods. */
  field?: string;
  /** The resource is `fmt.Sprintf(format, <param or field>)`: render it with the call site's value. */
  format?: string;
  /** The resource is an expression of the helper's inputs that could not be mapped: do not guess it at the call site. */
  derived?: boolean;
  /** DynamoDB IndexName the helper queries (`*` when not known), so callers need the index, not the table. */
  index?: string;
  /** IndexName is this parameter of the helper: each call site supplies it (nil means the table). */
  indexParam?: number;
  /** The resource is fixed in the helper's own body (a literal, an env var): every call site uses it. */
  fixed?: ResourceRef;
}

/**
 * Functions and types in this repository that wrap AWS SDK calls, so a call to
 * `pubsub.NewSNSPublisher(client, topic)` is known to publish to `topic`.
 */
export class GoIndex {
  /** Import path of the package a module-relative file belongs to. */
  packageOf(relPath: string): string {
    const dir = path.posix.dirname(relPath);
    return dir === '.' ? this.modulePath : `${this.modulePath}/${dir}`;
  }

  private readonly funcs = new Map<string, Op[]>();
  private readonly types = new Map<string, Op[]>();
  private readonly packages = new Set<string>();
  private readonly ctorFields = new Map<string, Map<string, number>>();

  constructor(readonly modulePath: string, files: SourceFile[]) {
    const calls = new Map<string, Callee[]>();
    for (const file of files) {
      const f = { ...file, content: withoutGoComments(file.content) };
      if (!f.path.endsWith('.go') || f.path.endsWith('_test.go')) continue;
      const dir = path.posix.dirname(f.path);
      const pkg = dir === '.' ? modulePath : `${modulePath}/${dir}`;
      this.packages.add(pkg);
      const imports = parseImports(f.content);
      for (const fn of goFunctions(f.content)) {
        const body = f.content.slice(fn.bodyStart, fn.bodyEnd);
        const ops: Op[] = sdkCalls(body, imports).map((c) => {
          let expr = unwrapGo(c.resourceExpr ?? '');
          // fmt.Sprintf("%s/clientCredentials", r.owner): one formatted input, rendered at the call site.
          const sprintf = expr.match(/^fmt\.Sprintf\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*([\w.]+)\s*\)$/);
          const format = sprintf && (sprintf[1].match(/%[sv]/g) ?? []).length === 1 && !/%[^sv%]/.test(sprintf[1]) ? sprintf[1] : undefined;
          if (format) expr = sprintf![2];
          const param = fn.params.indexOf(expr);
          const field = fn.receiverVar && expr.startsWith(`${fn.receiverVar}.`) ? expr.slice(fn.receiverVar.length + 1) : undefined;
          const mapped = param >= 0 || Boolean(field && /^\w+$/.test(field));
          const derived = !mapped && /\bfmt\.Sprintf\(|\+/.test(expr);
          const own = !mapped && !derived && c.resourceExpr ? classifyGoExpr(c.resourceExpr, f.content, fn.bodyStart + c.start) : undefined;
          const fixed = own && own.kind !== 'unresolved' ? own : undefined;
          // A resource the index cannot follow (a local from a struct field) is not guessed at the call site.
          const opaqueLocal = own?.kind === 'unresolved';
          return {
            service: c.service,
            operation: c.operation,
            ...(param >= 0 ? { param } : {}),
            ...(field && /^\w+$/.test(field) ? { field } : {}),
            ...(format && mapped ? { format } : {}),
            ...(derived || opaqueLocal ? { derived: true } : {}),
            ...(fixed ? { fixed } : {}),
            ...(c.indexExpr
              ? fn.params.includes(unwrapGo(c.indexExpr))
                ? { indexParam: fn.params.indexOf(unwrapGo(c.indexExpr)) }
                : { index: indexName(classifyGoExpr(c.indexExpr, f.content, fn.bodyStart + c.start)) }
              : {}),
          };
        });
        if (/^New[A-Z]/.test(fn.name)) {
          // Constructor: which parameter ends up in which struct field (`topic: topicARN` or `x.topic = topicARN`).
          const fields = new Map<string, number>();
          for (const m of body.matchAll(/(?:^|[{,\s.])(\w+)\s*(?::|=)\s*(\w+)\s*[,}\n]/g)) {
            const idx = fn.params.indexOf(m[2]);
            if (idx >= 0) fields.set(m[1], idx);
          }
          this.ctorFields.set(`${pkg}#${fn.name}`, fields);
        }
        const key = fn.receiver ? `${pkg}#${fn.receiver}.${fn.name}` : `${pkg}#${fn.name}`;
        this.funcs.set(key, ops);
        if (fn.receiver) this.types.set(`${pkg}#${fn.receiver}`, [...(this.types.get(`${pkg}#${fn.receiver}`) ?? []), ...ops]);
        const callees: Callee[] = [];
        const argsAt = (c: RegExpMatchArray) => {
          const open = c.index! + c[0].length - 1;
          return splitTopLevel(body.slice(open + 1, matchParen(body, open))).map((a) => unwrapGo(a));
        };
        const refsAt = (c: RegExpMatchArray) => argsAt(c).map((a) => classifyGoExpr(a, f.content, fn.bodyStart + c.index!));
        for (const c of body.matchAll(/\b([A-Za-z_]\w*)\.([A-Z]\w*)\s*(?:\[[^\]\n]*\])?\s*\(/g)) {
          const p = imports.get(c[1]);
          if (p?.startsWith(modulePath)) callees.push({ key: `${p}#${c[2]}`, args: argsAt(c), argRefs: refsAt(c), params: fn.params, receiverVar: fn.receiverVar });
        }
        // Any plain call: exported helpers are called without a qualifier inside their own package too.
        // Builtins and type conversions have no entry in the index, so they contribute nothing.
        for (const c of body.matchAll(/(?:^|[^.\w])([A-Za-z_]\w*)\s*\(/g)) callees.push({ key: `${pkg}#${c[1]}`, args: argsAt(c), argRefs: refsAt(c), params: fn.params, receiverVar: fn.receiverVar });
        if (fn.receiver && fn.receiverVar) {
          for (const c of body.matchAll(new RegExp(`\\b${fn.receiverVar}\\.([A-Za-z_]\\w*)\\s*\\(`, 'g'))) {
            callees.push({ key: `${pkg}#${fn.receiver}.${c[1]}`, args: argsAt(c), argRefs: refsAt(c), params: fn.params, sameReceiver: true, receiverVar: fn.receiverVar });
          }
        }
        calls.set(key, callees);
      }
    }
    // Pull in what same-repo callees do, a few levels deep.
    for (let round = 0; round < 3; round++) {
      for (const [key, callees] of calls) {
        const extra = callees.flatMap((c) => (this.funcs.get(c.key) ?? []).map((op) => remap(op, c)));
        if (extra.length) this.funcs.set(key, uniqueOps([...(this.funcs.get(key) ?? []), ...extra]));
      }
    }
    this.types.clear();
    for (const [key, ops] of this.funcs) {
      const m = key.match(/^(.*)#(\w+)\.\w+$/);
      if (m) this.types.set(`${m[1]}#${m[2]}`, uniqueOps([...(this.types.get(`${m[1]}#${m[2]}`) ?? []), ...ops]));
    }
  }

  has(pkg: string): boolean {
    return this.packages.has(pkg);
  }

  /** SDK operations the function `pkg.Name` performs itself (including same-repo callees). */
  opsFor(pkg: string, name: string): Op[] {
    return uniqueOps(this.funcs.get(`${pkg}#${name}`) ?? []);
  }

  /** For a constructor `NewX`, the type X it builds, if X has methods with SDK calls. */
  constructedType(pkg: string, name: string): string | undefined {
    if (!name.startsWith('New')) return undefined;
    const type = name.slice(3);
    return this.types.has(`${pkg}#${type}`) ? type : undefined;
  }

  typeOps(pkg: string, type: string): Op[] {
    return uniqueOps(this.types.get(`${pkg}#${type}`) ?? []);
  }

  /** Parameter index a constructor stores in a struct field. */
  ctorParam(pkg: string, ctor: string, field: string): number | undefined {
    return this.ctorFields.get(`${pkg}#${ctor}`)?.get(field);
  }

  methodOps(pkg: string, type: string, method: string): Op[] {
    return this.funcs.get(`${pkg}#${type}.${method}`) ?? [];
  }
}

/** A call from one helper to another, with the arguments as written, to map the callee's parameters back. */
interface Callee {
  key: string;
  args: string[];
  /** The arguments as the caller's body resolves them (an env read, a local holding a literal). */
  argRefs: ResourceRef[];
  /** Parameters of the calling function. */
  params: string[];
  /** A method called on the caller's own receiver: its receiver fields are the caller's. */
  sameReceiver?: boolean;
  /** The calling method's receiver variable, so `p.topic` passed on maps to the field `topic`. */
  receiverVar?: string;
}

/**
 * The callee's operation in terms of the caller: its resource parameter becomes the caller's parameter
 * passed in that position, or the caller's receiver field. Anything else (a call, a literal, a local)
 * leaves the resource to the caller's call site, which then cannot name it.
 */
function remap(op: Op, call: Callee): Op {
  const { param, field, indexParam, ...rest } = op;
  const out: Op = { ...rest };
  if (field !== undefined && call.sameReceiver) out.field = field;
  if (indexParam !== undefined) {
    const arg = call.args[indexParam];
    const p = arg === undefined ? -1 : call.params.indexOf(arg);
    if (p >= 0) out.indexParam = p;
    else if (arg !== 'nil') out.index = literalIndex(arg) ?? '*';
  }
  if (param !== undefined) {
    const arg = call.args[param];
    const p = arg === undefined ? -1 : call.params.indexOf(arg);
    const viaField = arg?.match(/^(\w+)\.(\w+)$/);
    const literal = arg?.match(/^"([^"\\]*)"$/)?.[1];
    if (p >= 0) out.param = p;
    else if (viaField && call.receiverVar && viaField[1] === call.receiverVar) out.field = viaField[2];
    // getParam(ctx, "/app/flags"): the inner helper's resource is fixed by this helper.
    else if (literal !== undefined) out.fixed = op.format ? { kind: 'literal', value: op.format.replace(/%[sv]/, literal) } : { kind: 'literal', value: literal };
    // publish(ctx, os.Getenv("ORDERS_TOPIC"), msg): fixed too, as this helper's body resolves it.
    else if (call.argRefs[param] && call.argRefs[param].kind !== 'unresolved') out.fixed = op.format ? formatted(op.format, call.argRefs[param]) : call.argRefs[param];
    // Anything else leaves the caller's arguments unrelated to the resource.
    else out.derived = true;
  }
  return out;
}

/** The index a call site passes: a literal, none for nil, or `*` when it cannot be read. */
function indexAt(op: Op, rawArgs: string[]): { index?: string } {
  if (op.indexParam === undefined) return op.index !== undefined ? { index: op.index } : {};
  const arg = rawArgs[op.indexParam]?.trim();
  if (arg === undefined || arg === 'nil') return {};
  return { index: literalIndex(arg) ?? '*' };
}

function literalIndex(arg: string | undefined): string | undefined {
  return arg ? unwrapGo(arg).match(/^"([^"\\]+)"$/)?.[1] : undefined;
}

function uniqueOps(ops: Op[]): Op[] {
  const seen = new Set<string>();
  return ops.filter((o) => {
    const k = `${o.service}:${o.operation}:${o.param ?? ''}:${o.field ?? ''}:${o.format ?? ''}:${o.derived ?? ''}:${o.index ?? ''}:${o.indexParam ?? ''}:${JSON.stringify(o.fixed ?? '')}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

interface GoFunc {
  name: string;
  receiver?: string;
  receiverVar?: string;
  params: string[];
  bodyStart: number;
  bodyEnd: number;
}

/** Strip aws.String(...), &x and parentheses around an expression. */
function unwrapGo(expr: string): string {
  let e = expr.trim();
  for (let changed = true; changed; ) {
    changed = false;
    // new(expr) is Go 1.26's pointer to a value, like aws.String(expr).
    const m = e.match(/^(?:aws\.String|aws\.ToString|string|new)\(([\s\S]*)\)$/) ?? e.match(/^&([\s\S]+)$/) ?? e.match(/^\(([\s\S]*)\)$/);
    if (m) {
      e = m[1].trim();
      changed = true;
    }
  }
  return e;
}

function matchParenGo(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')' && --depth === 0) return i;
  }
  return src.length - 1;
}

function goFunctions(src: string): GoFunc[] {
  const out: GoFunc[] = [];
  const re = /^func\s+(?:\(\s*(?:([A-Za-z_]\w*)\s+)?\*?\s*([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\(/gm;
  for (const m of src.matchAll(re)) {
    let i = m.index! + m[0].length - 1;
    let depth = 0;
    let body = -1;
    for (; i < src.length; i++) {
      const c = src[i];
      if (c === '(') depth++;
      else if (c === ')') depth--;
      else if (c === '{' && depth === 0) {
        const before = src.slice(Math.max(0, i - 10), i).trimEnd();
        if (/(interface|struct)$/.test(before)) {
          i = matchBrace(src, i);
          continue;
        }
        body = i;
        break;
      }
    }
    if (body < 0) continue;
    const paramsOpen = m.index! + m[0].length - 1;
    const paramsText = src.slice(paramsOpen + 1, matchParenGo(src, paramsOpen));
    const params = splitTopLevel(paramsText).map((p) => p.trim().split(/\s+/)[0]).filter((p) => /^[A-Za-z_]\w*$/.test(p));
    out.push({ name: m[3], receiver: m[2], receiverVar: m[1], params, bodyStart: body, bodyEnd: matchBrace(src, body) });
  }
  return out;
}
