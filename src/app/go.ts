import { ExtractionCache, extractionCache, fileIdentity } from './cache.js';
import { createHash } from 'node:crypto';
import { transactionFacts } from './transactions.js';
import * as path from 'node:path';
import {
  COPY_OPERATIONS,
  RESOURCE_FIELDS,
  actionsFor,
  conservativeFact,
  copySourceBucket,
  serviceHint,
} from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead, ResourceRef } from './facts.js';
import {
  syntax,
  clearSyntax,
  clearSyntaxExcept,
  children,
  field as nodeField,
  args as callArgs,
  callable,
  member,
  literal,
  unwrapped,
  expressionRef,
  isCall,
  type Node,
} from './syntax.js';

/** AWS input literals and same-repository helper summaries, read from Go syntax trees. */

export interface SourceFile {
  path: string;
  content: string;
  /** Git blob ID when reading a historical snapshot. */
  blobId?: string;
}

const SDK_PACKAGE = /^github\.com\/aws\/aws-sdk-go(?:-v2)?\/service\/([a-z0-9]+)$/;

export function parseImports(src: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of syntax('go', src).nodes) {
    if (n.type !== 'import_spec') continue;
    const p = literal(nodeField(n, 'path')),
      alias = nodeField(n, 'name')?.text;
    if (!p || alias === '_' || alias === '.') continue;
    const segments = p.split('/');
    let name = segments.at(-1)!;
    if (/^v\d+$/.test(name)) name = segments.at(-2)!;
    out.set(alias ?? name.replace(/[^A-Za-z0-9_]/g, ''), p);
  }
  return out;
}

const lineAt = (src: string, offset: number) => src.slice(0, offset).split('\n').length;

export function classifyGoExpr(expr: string, src: string, offset: number): ResourceRef {
  return expressionRef('go', expr, src, offset);
}

interface SdkCall {
  service: string;
  operation: string;
  start: number;
  end: number;
  resourceExpr?: string;
  indexExpr?: string;
  copySourceExpr?: string;
  node: Node;
}

function sdkCalls(src: string, imports: Map<string, string>): SdkCall[] {
  const s = syntax('go', src),
    out: SdkCall[] = [];
  for (const n of s.nodes) {
    if (n.type !== 'composite_literal') continue;
    const type = nodeField(n, 'type');
    if (type?.type !== 'qualified_type') continue;
    const pkg = imports.get(nodeField(type, 'package')?.text ?? ''),
      service = pkg?.match(SDK_PACKAGE)?.[1],
      name = nodeField(type, 'name')?.text;
    if (!service || !name?.endsWith('Input')) continue;
    const fields = s.fields(n),
      resource = (RESOURCE_FIELDS[service] ?? []).find((k) => fields.has(k));
    out.push({
      node: n,
      service,
      operation: name.slice(0, -5),
      start: n.startIndex,
      end: n.endIndex - 1,
      resourceExpr: resource ? fields.get(resource)?.text : undefined,
      indexExpr: fields.get('IndexName')?.text,
      copySourceExpr: fields.get('CopySource')?.text,
    });
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
  clearSyntax();
  const out = syntax('go', src).reads(file, added);
  clearSyntax();
  return out;
}

export interface ExtractOptions {
  addedLines?: AddedLines;
  index?: GoIndex;
  /** Directory of the go.mod the files belong to, relative to their paths; `.` by default. */
  moduleDir?: string;
}

export function extractGo(files: SourceFile[], opts: ExtractOptions = {}): AppScan {
  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];
  for (const file of files) {
    clearSyntax();
    const f = file;
    if (!f.path.endsWith('.go') || f.path.endsWith('_test.go')) continue;
    const added = opts.addedLines?.get(f.path);
    if (opts.addedLines && !added) continue;
    const imports = parseImports(f.content);
    envReads.push(...envReadsGo(f.content, f.path, added));

    const funcs = goFunctions(f.content);
    for (const call of sdkCalls(f.content, imports)) {
      if (!inAdded(added, f.content, call.start, call.end)) continue;
      const resource: ResourceRef = call.resourceExpr
        ? classifyGoExpr(call.resourceExpr, f.content, call.start)
        : { kind: 'unresolved', text: '(no resource field)' };
      const fn = funcs.find((x) => x.bodyStart < call.start && call.start < x.bodyEnd);
      const internal =
        resource.kind === 'unresolved' &&
        fn !== undefined &&
        (fn.params.includes(resource.text) ||
          (fn.receiverVar !== undefined && resource.text.startsWith(`${fn.receiverVar}.`)));
      const base: AccessFact = {
        service: call.service,
        operation: call.operation,
        actions: actionsFor(call.service, call.operation),
        resource,
        file: f.path,
        line: lineAt(f.content, call.start),
        ...(internal ? { internal: true } : {}),
        ...(call.indexExpr
          ? {
              index: indexName(classifyGoExpr(call.indexExpr, f.content, call.start)),
            }
          : {}),
      };
      const s = syntax('go', f.content);
      facts.push(...(transactionFacts(base, s.fields(call.node), s) ?? [base]));
      if (call.service === 's3' && COPY_OPERATIONS.has(call.operation)) {
        facts.push({
          service: 's3',
          operation: 'GetObject',
          actions: ['s3:GetObject'],
          resource: call.copySourceExpr
            ? copySourceBucket(classifyGoExpr(call.copySourceExpr, f.content, call.start), call.copySourceExpr)
            : { kind: 'unresolved', text: '(no CopySource)' },
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
  clearSyntax();
  return {
    facts: dedupeFacts(facts).map(conservativeFact),
    envReads: dedupeEnv(envReads),
  };
}

interface HelperCall {
  pkg: string;
  name: string;
  /** How the call is written, for the report: `pubsub.NewSNSPublisher`, or `getSecret` in the same package. */
  via: string;
  start: number;
  node: Node;
}

/** Calls to helpers of this repository: package-qualified ones, and plain calls to functions of the file's own package. */
function helperCallSites(
  f: SourceFile,
  imports: Map<string, string>,
  index: GoIndex,
  ownPackage: string | undefined,
): HelperCall[] {
  const out: HelperCall[] = [];
  for (const n of syntax('go', f.content).nodes) {
    if (!isCall(n)) continue;
    const fn = callable(n),
      m = member(fn);
    if (m) {
      const pkg = imports.get(m.object.text);
      if (pkg && index.has(pkg))
        out.push({
          pkg,
          name: m.name,
          via: m.object.text + '.' + m.name,
          start: n.startIndex,
          node: n,
        });
    } else if (
      fn &&
      ownPackage &&
      index.has(ownPackage) &&
      (index.opsFor(ownPackage, fn.text).length || index.constructedType(ownPackage, fn.text))
    )
      out.push({
        pkg: ownPackage,
        name: fn.text,
        via: fn.text,
        start: n.startIndex,
        node: n,
      });
  }
  return out;
}

function helperCalls(
  f: SourceFile,
  imports: Map<string, string>,
  index: GoIndex,
  added: Set<number> | undefined,
  ownPackage?: string,
): AccessFact[] {
  const out: AccessFact[] = [];
  const funcs = goFunctions(f.content);
  for (const call of helperCallSites(f, imports, index, ownPackage)) {
    const { pkg } = call;
    const close = call.node.endIndex - 1;
    if (!inAdded(added, f.content, call.start, close)) continue;

    // For a constructor, keep the operations of the methods this file calls on the returned value.
    // If the value escapes (passed on, stored), the other methods' operations are only possible.
    let ops = index.opsFor(pkg, call.name).map((op) => ({ ...op, possible: false, fromType: false }));
    const type = index.constructedType(pkg, call.name);
    if (type) {
      const s = syntax('go', f.content);
      const binding = s.bindings.find(
        (b) => b.value && b.value.startIndex <= call.start && b.value.endIndex >= call.node.endIndex,
      );
      const bound = binding?.name;
      const uses = bound
        ? s.nodes.filter(
            (n) =>
              n.type === 'identifier' &&
              n.text === bound &&
              n.startIndex > close &&
              s.binding(bound, n)?.target.id === binding?.target.id,
          )
        : [];
      const called = uses.flatMap((n) => {
        const m = member(n.parent ?? undefined);
        return m && m.object.id === n.id && isCall(n.parent?.parent ?? n) ? [m.name] : [];
      });
      const escapes = bound !== '_' && (!bound || !binding?.declaration || uses.length > called.length);
      const certain = new Set(
        called.flatMap((meth) => index.methodOps(pkg, type, meth)).map((o) => `${o.service}:${o.operation}`),
      );
      const own = new Set(ops.map((o) => `${o.service}:${o.operation}`));
      ops = [
        ...ops,
        ...index
          .typeOps(pkg, type)
          .filter(
            (o) => !own.has(`${o.service}:${o.operation}`) && (certain.has(`${o.service}:${o.operation}`) || escapes),
          )
          .map((o) => ({
            ...o,
            possible: !certain.has(`${o.service}:${o.operation}`),
            fromType: true,
          })),
      ];
    }
    if (!ops.length) continue;

    const rawArgs = callArgs(call.node).map((a) => a.text);
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
      const resource =
        found && op.format && byPosition
          ? formatted(op.format, found)
          : (found ?? {
              kind: 'unresolved' as const,
              text: `arguments of ${call.via}`,
            });
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
  /** Index of the function parameter that becomes the SDK resource field as nodeField, when it is passed directly. */
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

interface GoFileIndex {
  functions: Array<[string, Op[]]>;
  constructors: Array<[string, Array<[string, number]>]>;
  calls: Array<[string, Callee[]]>;
}
function indexFile(f: SourceFile, modulePath: string, pkg: string): GoFileIndex {
  const funcs = new Map<string, Op[]>(),
    ctors = new Map<string, Map<string, number>>(),
    calls = new Map<string, Callee[]>();
  try {
    const imports = parseImports(f.content);
    for (const fn of goFunctions(f.content)) {
      const body = f.content.slice(fn.bodyStart, fn.bodyEnd);
      const ops: Op[] = sdkCalls(body, imports).map((c) => {
        const parsed = syntax('go', body);
        const fields = parsed.fields(c.node);
        const resourceField = (RESOURCE_FIELDS[c.service] ?? []).find((name) => fields.has(name));
        let value = resourceField ? fields.get(resourceField) : undefined;
        let format: string | undefined;
        if (value && callable(value)?.text === 'fmt.Sprintf') {
          const args = callArgs(value),
            text = literal(args[0]);
          if (
            text !== undefined &&
            args.length === 2 &&
            (text.match(/%[sv]/g) ?? []).length === 1 &&
            !/%[^sv%]/.test(text)
          ) {
            format = text;
            value = unwrapped(args[1]);
          }
        }
        const expr = value?.text ?? '';
        const param = fn.params.indexOf(expr),
          m = member(value);
        const field = m && m.object.text === fn.receiverVar ? m.name : undefined;
        const mapped = param >= 0 || Boolean(field);
        const transaction =
          c.service === 'dynamodb' && ['TransactWriteItems', 'TransactGetItems'].includes(c.operation);
        const derived =
          transaction ||
          (!mapped &&
            value !== undefined &&
            (callable(value)?.text === 'fmt.Sprintf' || value.type === 'binary_expression'));
        const own =
          !mapped && !derived && c.resourceExpr
            ? classifyGoExpr(c.resourceExpr, f.content, fn.bodyStart + c.start)
            : undefined;
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
              : {
                  index: indexName(classifyGoExpr(c.indexExpr, f.content, fn.bodyStart + c.start)),
                }
            : {}),
        };
      });
      if (/^New[A-Z]/.test(fn.name)) {
        // Constructor: which parameter ends up in which struct field (`topic: topicARN` or `x.topic = topicARN`).
        const fields = new Map<string, number>();
        for (const n of syntax('go', body).nodes) {
          if (n.type === 'keyed_element') {
            const key = nodeField(n, 'key'),
              value = nodeField(n, 'value');
            const idx = fn.params.indexOf(value ? unwrapped(value).text : '');
            if (idx >= 0 && key) fields.set(unwrapped(key).text, idx);
          } else if (n.type === 'assignment_statement') {
            const left = nodeField(n, 'left')?.namedChildren[0],
              right = nodeField(n, 'right')?.namedChildren[0],
              m = member(left ?? undefined);
            const idx = fn.params.indexOf(right?.text ?? '');
            if (m && idx >= 0) fields.set(m.name, idx);
          }
        }
        ctors.set(`${pkg}#${fn.name}`, fields);
      }
      const key = fn.receiver ? `${pkg}#${fn.receiver}.${fn.name}` : `${pkg}#${fn.name}`;
      funcs.set(key, ops);
      const callees: Callee[] = [];
      for (const n of syntax('go', body).nodes) {
        if (!isCall(n)) continue;
        const target = callable(n),
          m = member(target),
          nodes = callArgs(n),
          args = nodes.map((a) => unwrapped(a).text),
          argRefs = nodes.map((a) => classifyGoExpr(a.text, f.content, fn.bodyStart + n.startIndex));
        const common = {
          args,
          argRefs,
          params: fn.params,
          receiverVar: fn.receiverVar,
        };
        if (m) {
          const p = imports.get(m.object.text);
          if (p?.startsWith(modulePath)) callees.push({ key: `${p}#${m.name}`, ...common });
          else if (fn.receiver && m.object.text === fn.receiverVar)
            callees.push({
              key: `${pkg}#${fn.receiver}.${m.name}`,
              sameReceiver: true,
              ...common,
            });
        } else if (target) callees.push({ key: `${pkg}#${target.text}`, ...common });
      }
      calls.set(key, callees);
      clearSyntaxExcept('go', f.content);
    }
    return { functions: [...funcs], constructors: [...ctors].map(([k, v]) => [k, [...v]]), calls: [...calls] };
  } finally {
    clearSyntax();
  }
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

  readonly cacheKey: string;

  constructor(
    readonly modulePath: string,
    files: SourceFile[],
    cache: ExtractionCache = extractionCache,
  ) {
    this.cacheKey = createHash('sha256')
      .update(JSON.stringify([modulePath, files.map((f) => [f.path, fileIdentity(f)])]))
      .digest('hex');
    const calls = new Map<string, Callee[]>();
    for (const f of files) {
      if (!f.path.endsWith('.go') || f.path.endsWith('_test.go')) continue;
      const pkg = this.packageOf(f.path);
      this.packages.add(pkg);
      const data = cache.memo('go-index', fileIdentity(f), [modulePath, pkg], () => indexFile(f, modulePath, pkg));
      for (const [key, ops] of data.functions) this.funcs.set(key, ops);
      for (const [key, fields] of data.constructors) this.ctorFields.set(key, new Map(fields));
      for (const [key, callees] of data.calls) calls.set(key, callees);
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
    else if (literal !== undefined)
      out.fixed = op.format
        ? { kind: 'literal', value: op.format.replace(/%[sv]/, literal) }
        : { kind: 'literal', value: literal };
    // publish(ctx, os.Getenv("ORDERS_TOPIC"), msg): fixed too, as this helper's body resolves it.
    else if (call.argRefs[param] && call.argRefs[param].kind !== 'unresolved')
      out.fixed = op.format ? formatted(op.format, call.argRefs[param]) : call.argRefs[param];
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

/** Unwrap only syntax nodes representing pointer and string conversion helpers. */
function unwrapGo(expr: string): string {
  const s = syntax('go', 'package p\nfunc f(){_ = ' + expr + '\n}');
  const n = s.bindings.find((b) => b.name === '_')?.value;
  return n ? unwrapped(n).text : expr.trim();
}

function goFunctions(src: string): GoFunc[] {
  const out: GoFunc[] = [];
  for (const n of syntax('go', src).nodes) {
    if (!['function_declaration', 'method_declaration'].includes(n.type)) continue;
    const body = nodeField(n, 'body'),
      name = nodeField(n, 'name');
    if (!body || !name) continue;
    const receiver = nodeField(n, 'receiver')?.namedChildren[0];
    let type = receiver && nodeField(receiver, 'type');
    while (type && ['pointer_type', 'generic_type'].includes(type.type))
      type = nodeField(type, 'type') ?? type.namedChildren[0];
    const params = children(nodeField(n, 'parameters')).flatMap((p) =>
      p
        .childrenForFieldName('name')
        .filter((n): n is Node => n !== null)
        .map((n) => n.text),
    );
    out.push({
      name: name.text,
      receiver: type?.text,
      receiverVar: receiver ? nodeField(receiver, 'name')?.text : undefined,
      params,
      bodyStart: body.startIndex,
      bodyEnd: body.endIndex - 1,
    });
  }
  return out;
}
