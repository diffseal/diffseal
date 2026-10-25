import { RESOURCE_FIELDS, actionsFor, copySourceBucket } from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead, ResourceRef } from './facts.js';
import { indexName, splitTopLevel, topLevelOnly, type SourceFile } from './go.js';
import { visibleInPython } from './scope.js';

/* Python extraction for boto3 clients and DynamoDB Table resources. */

const lineAt = (src: string, offset: number) => src.slice(0, offset).split('\n').length;

/**
 * Python source with `#` comments blanked out, and with string contents blanked too when `strings` is
 * set. Offsets and newlines are kept. `//` is integer division, not a comment.
 */
export function pythonCode(src: string, strings: boolean): string {
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '#') {
      const end = src.indexOf('\n', i);
      const j = end < 0 ? src.length : end;
      out += ' '.repeat(j - i);
      i = j - 1;
    } else if (c === '"' || c === "'") {
      const q = src.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + q.length;
      while (j < src.length && !src.startsWith(q, j) && (q.length === 3 || src[j] !== '\n')) j += src[j] === '\\' ? 2 : 1;
      const body = src.slice(i + q.length, Math.min(j, src.length));
      out += q + (strings ? body.replace(/[^\n]/g, ' ') : body) + (j < src.length && src.startsWith(q, j) ? q : '');
      i = j + (j < src.length && src.startsWith(q, j) ? q.length : 0) - 1;
    } else out += c;
  }
  return out;
}

let structureCache: { src?: string; out: string } = { out: '' };

/**
 * The source as Python's block structure sees it: comments and string contents blanked, and the
 * delimiters of triple-quoted strings too, so a docstring line at column 0 does not end a class or def.
 * Offsets and newlines are kept, so positions in it are positions in the source.
 */
export function pythonStructure(src: string): string {
  if (structureCache.src !== src) structureCache = { src, out: pythonCode(src, true).replace(/"""|'''/g, '   ') };
  return structureCache.out;
}

const BOTO_SERVICE: Record<string, string> = {
  stepfunctions: 'sfn',
  events: 'eventbridge',
  'iot-data': 'iotdataplane',
  'bedrock-runtime': 'bedrockruntime',
  'cognito-idp': 'cognitoidentityprovider',
  logs: 'cloudwatchlogs',
};

const TABLE_METHODS: Record<string, string> = {
  put_item: 'PutItem',
  get_item: 'GetItem',
  update_item: 'UpdateItem',
  delete_item: 'DeleteItem',
  query: 'Query',
  scan: 'Scan',
  batch_writer: 'BatchWriteItem',
};

/**
 * boto3's managed transfer helpers on an S3 client: they call GetObject, PutObject (or multipart
 * uploads, which need s3:PutObject too) under the hood, and `copy` also reads the source (handled with
 * CopySource below). `bucketArg` is the bucket's position when it is not passed by keyword.
 */
const S3_TRANSFER: Record<string, { op: string; actions: string[]; bucketArg: number }> = {
  upload_file: { op: 'PutObject', actions: ['s3:PutObject'], bucketArg: 1 },
  upload_fileobj: { op: 'PutObject', actions: ['s3:PutObject'], bucketArg: 1 },
  download_file: { op: 'GetObject', actions: ['s3:GetObject'], bucketArg: 0 },
  download_fileobj: { op: 'GetObject', actions: ['s3:GetObject'], bucketArg: 0 },
  copy: { op: 'Copy', actions: ['s3:PutObject'], bucketArg: 1 },
};

/** boto3 client methods that are not API operations: no IAM action, no fact. */
const CLIENT_HELPERS = new Set(['generate_presigned_url', 'generate_presigned_post', 'get_paginator', 'get_waiter', 'can_paginate', 'close']);

const pascal = (snake: string) => snake.split('_').map((s) => s[0]?.toUpperCase() + s.slice(1)).join('');

// The whole expression: `os.environ["X"] + "-y"` is not the env value.
const ENV = /^os\.(?:environ\[\s*['"]([A-Za-z_]\w*)['"]\s*\]|environ\.get\(\s*['"]([A-Za-z_]\w*)['"](?:\s*,\s*['"]([^'"]*)['"])?\s*\)|getenv\(\s*['"]([A-Za-z_]\w*)['"](?:\s*,\s*['"]([^'"]*)['"])?\s*\))$/;

export function classifyPyExpr(expr: string, src: string, offset: number, depth = 0): ResourceRef {
  const e = expr.trim();
  const env = e.match(ENV);
  if (env) {
    const fallback = env[3] ?? env[5];
    const name = env[1] ?? env[2] ?? env[4];
    return fallback !== undefined ? { kind: 'env', name, fallback } : { kind: 'env', name };
  }
  // `os.getenv("X") or "default"`: the env var, with the default when it is a literal. Any other `or`,
  // `and` or conditional may take either side, so it is not followed (and `+` is not split across it).
  const top = topLevelOnly(e);
  const or = top.search(/\sor\s/);
  if (or >= 0) {
    const left = classifyPyExpr(e.slice(0, or), src, offset, depth + 1);
    const right = classifyPyExpr(e.slice(or + top.slice(or).match(/\sor\s/)![0].length), src, offset, depth + 1);
    if (left.kind === 'env' && left.fallback === undefined) return right.kind === 'literal' ? { kind: 'env', name: left.name, fallback: right.value } : { kind: 'env', name: left.name };
    return { kind: 'unresolved', text: e };
  }
  if (/\s(and|if|else)\s|^not\s/.test(top)) return { kind: 'unresolved', text: e };
  const fstr = e.match(/^[fF](['"])([\s\S]*)\1$/);
  if (fstr) return { kind: 'pattern', glob: fstr[2].replace(/\{[^}]*\}/g, '*') };
  const str = e.match(/^(['"])((?:(?!\1)[^\\]|\\.)*)\1$/);
  if (str) return { kind: 'literal', value: str[2] };
  // `os.environ["X"] + "-y"`: the known text with `*` for the parts that are not known.
  const parts = splitTopLevel(e, '+');
  if (parts.length > 1) {
    const pieces = parts.map((p) => classifyPyExpr(p, src, offset, depth + 1));
    if (pieces.some((p) => p.kind === 'literal')) {
      return { kind: 'pattern', glob: pieces.map((p) => (p.kind === 'literal' ? p.value : p.kind === 'pattern' ? p.glob : '*')).join('') };
    }
    return { kind: 'unresolved', text: e };
  }
  if (/^[A-Za-z_]\w*$/.test(e) && depth < 4) {
    // `\s*` may start on an earlier blank line: the assignment is where its name starts.
    const structure = pythonStructure(src);
    const assigns = [...src.slice(0, offset).matchAll(new RegExp(`^\\s*${e}\\s*=\\s*(.+)$`, 'gm'))].filter((m) =>
      visibleInPython(structure, (m.index ?? 0) + m[0].search(/\S/), offset, e)
    );
    const last = assigns[assigns.length - 1];
    // `bucket = "secondary"` inside an `if`, `for`, `while` or `try` above the use, indented deeper than
    // it: some paths skip it, so the value at the use is not one value.
    if (last && indentAt(src, (last.index ?? 0) + last[0].search(/\S/)) > indentAt(src, offset)) return { kind: 'unresolved', text: e };
    if (last) return classifyPyExpr(last[1], src, last.index ?? 0, depth + 1);
  }
  return { kind: 'unresolved', text: e };
}

export function envReadsPython(src: string, file: string, added?: Set<number>): EnvRead[] {
  const out: EnvRead[] = [];
  // The key sits in a string, so the pattern runs on the source; a match counts only where `os.` is
  // code, not inside a docstring or message that mentions os.environ.
  const code = pythonCode(src, true);
  for (const m of src.matchAll(/os\.(?:environ\[\s*['"]([A-Za-z_]\w*)['"]\s*\]|environ\.get\(\s*['"]([A-Za-z_]\w*)['"](\s*,)?|getenv\(\s*['"]([A-Za-z_]\w*)['"](\s*,)?)/g)) {
    if (code.slice(m.index!, m.index! + 3) !== 'os.') continue;
    const line = lineAt(src, m.index!);
    if (added && !added.has(line)) continue;
    out.push({ name: m[1] ?? m[2] ?? m[4], file, line, ...(m[3] || m[5] ? { hasDefault: true } : {}) });
  }
  return out;
}

function matchParen(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')' && --depth === 0) return i;
  }
  return src.length - 1;
}

interface Binding {
  self: boolean;
  name: string;
  value: string;
  at: number;
}

export function extractPython(files: SourceFile[], opts: { addedLines?: AddedLines } = {}): AppScan {
  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];
  for (const file of files) {
    const added = opts.addedLines?.get(file.path);
    if (opts.addedLines && !added) continue;
    // Calls and env reads in comments are not code.
    const f = { ...file, content: pythonCode(file.content, false) };
    envReads.push(...envReadsPython(f.content, f.path, added));
    const code = pythonCode(file.content, true);
    // A binding is seen where Python scoping says it is: the last one above the use in an enclosing
    // def or the module. `self.x` attributes are shared by the class's methods, so the last one wins.
    const clients: Binding[] = [...f.content.matchAll(/^\s*(self\.)?(\w+)\s*=\s*boto3\.client\(\s*['"]([\w-]+)['"]/gm)].map((m) => ({
      self: Boolean(m[1]),
      name: m[2],
      value: BOTO_SERVICE[m[3]] ?? m[3],
      at: m.index! + m[0].indexOf(m[2]),
    }));
    const tables: Binding[] = [...f.content.matchAll(/^\s*(self\.)?(\w+)\s*=\s*[\w.()'"]*\.Table\((.+)\)\s*$/gm)].map((m) => ({
      self: Boolean(m[1]),
      name: m[2],
      value: m[3],
      at: m.index! + m[0].indexOf(m[2]),
    }));
    const st = pythonStructure(file.content);
    const classes = classIndex(st);
    const bound = (list: Binding[], self: boolean, name: string, use: number) => {
      if (self) {
        // self.x: set in a method or as a class attribute of the use's class, then of its bases in this file.
        const attrs = list.filter((b) => b.name === name && (b.self || inClassBody(st, b.at)));
        for (const cls of classChain(classes, enclosingClass(st, use))) {
          const own = attrs.filter((b) => enclosingClass(st, b.at) === cls);
          if (own.length) return own[own.length - 1].value;
        }
        // A mixin, or a base class from another file: only an unambiguous binding in this file counts.
        const values = new Set(attrs.map((b) => b.value));
        return values.size === 1 ? attrs[0].value : undefined;
      }
      const seen = list.filter(
        (b) =>
          b.name === name &&
          !b.self &&
          // A module-level name is looked up when the function runs, so it may be assigned below it.
          ((b.at < use && visibleInPython(st, b.at, use, name)) || (indentAt(st, b.at) === 0 && insideDef(st, use) && visibleInPython(st, b.at, use, name)))
      );
      return seen[seen.length - 1]?.value;
    };

    for (const m of code.matchAll(/\b(self\.)?(\w+)\.(\w+)\s*\(/g)) {
      const open = m.index! + m[0].length - 1;
      const close = matchParen(code, open);
      const line = lineAt(f.content, m.index!);
      if (added) {
        let hit = false;
        for (let l = line; l <= lineAt(f.content, close); l++) if (added.has(l)) hit = true;
        if (!hit) continue;
      }
      const args = splitTopLevel(f.content.slice(open + 1, close));
      const kwargs = new Map(args.map((a) => a.match(/^(\w+)\s*=\s*([\s\S]+)$/)).filter((x): x is RegExpMatchArray => Boolean(x)).map((x) => [x[1], x[2]]));
      const svc = bound(clients, Boolean(m[1]), m[2], m.index!);
      if (svc) {
        // Client helpers that are not API operations have no IAM action of their own.
        if (CLIENT_HELPERS.has(m[3])) continue;
        const transfer = svc === 's3' ? S3_TRANSFER[m[3]] : undefined;
        const op = transfer?.op ?? pascal(m[3]);
        const field = (RESOURCE_FIELDS[svc] ?? []).find((x) => kwargs.has(x));
        // upload_file(Filename, Bucket, Key) and friends usually pass the bucket by position.
        const positional = transfer && !kwargs.has('Bucket') ? args[transfer.bucketArg] : undefined;
        const resourceExpr = field ? kwargs.get(field)! : positional && !/^\w+\s*=/.test(positional) ? positional : undefined;
        facts.push({
          service: svc,
          operation: op,
          actions: transfer ? transfer.actions : actionsFor(svc, op),
          resource: resourceExpr ? classifyPyExpr(resourceExpr, f.content, m.index!) : { kind: 'unresolved', text: '(no resource argument)' },
          file: f.path,
          line,
          ...(kwargs.has('IndexName') ? { index: indexName(classifyPyExpr(kwargs.get('IndexName')!, f.content, m.index!)) } : {}),
        });
        if (svc === 's3' && (op === 'CopyObject' || op === 'Copy' || op === 'UploadPartCopy')) {
          // CopySource is usually {'Bucket': ..., 'Key': ...}.
          const src = kwargs.get('CopySource') ?? '';
          const bucket = src.match(/['"]Bucket['"]\s*:\s*([^,}]+)/)?.[1];
          facts.push({
            service: 's3',
            operation: 'GetObject',
            actions: ['s3:GetObject'],
            resource: bucket
              ? classifyPyExpr(bucket, f.content, m.index!)
              : src && !src.trim().startsWith('{')
                ? copySourceBucket(classifyPyExpr(src, f.content, m.index!), src)
                : { kind: 'unresolved', text: '(CopySource bucket not found)' },
            file: f.path,
            line,
          });
        }
        continue;
      }
      const table = bound(tables, Boolean(m[1]), m[2], m.index!);
      const op = TABLE_METHODS[m[3]];
      if (table && op) {
        facts.push({
          service: 'dynamodb',
          operation: op,
          actions: actionsFor('dynamodb', op),
          resource: classifyPyExpr(table, f.content, m.index!),
          file: f.path,
          line,
          ...(kwargs.has('IndexName') ? { index: indexName(classifyPyExpr(kwargs.get('IndexName')!, f.content, m.index!)) } : {}),
        });
      }
    }
  }
  return { facts, envReads };
}

function indentAt(src: string, pos: number): number {
  return src.slice(src.lastIndexOf('\n', pos - 1) + 1).match(/^[ \t]*/)![0].length;
}

/** The headers enclosing `pos` by indentation, innermost first: `class X:` or `def f(...)`. */
function enclosingHeaders(src: string, pos: number): Array<{ kind: 'class' | 'def'; line: number }> {
  const lines = src.slice(0, src.lastIndexOf('\n', pos - 1) + 1).split('\n');
  let indent = indentAt(src, pos);
  const out: Array<{ kind: 'class' | 'def'; line: number }> = [];
  for (let n = lines.length - 1; n >= 0 && indent > 0; n--) {
    const l = lines[n];
    if (!l.trim() || l.trim().startsWith('#')) continue;
    const i = l.match(/^[ \t]*/)![0].length;
    if (i >= indent) continue;
    indent = i;
    const h = l.match(/^\s*(?:async\s+)?(class|def)\b/);
    if (h) out.push({ kind: h[1] as 'class' | 'def', line: n });
  }
  return out;
}

/** Classes of the file by header line: their name and the names of their bases. */
function classIndex(structure: string): Map<number, { name: string; bases: string[] }> {
  const out = new Map<number, { name: string; bases: string[] }>();
  structure.split('\n').forEach((l, n) => {
    const m = l.match(/^\s*class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:/);
    if (!m) return;
    const bases = (m[2] ?? '')
      .split(',')
      .map((b) => b.trim().split('.').pop()!.split('[')[0])
      .filter((b) => /^\w+$/.test(b));
    out.set(n, { name: m[1], bases });
  });
  return out;
}

/** A class and its bases declared in the same file, nearest first, each once. */
function classChain(classes: Map<number, { name: string; bases: string[] }>, start: number | undefined): number[] {
  const out: number[] = [];
  const queue = start === undefined ? [] : [start];
  while (queue.length) {
    const line = queue.shift()!;
    if (out.includes(line)) continue;
    out.push(line);
    for (const base of classes.get(line)?.bases ?? []) {
      const found = [...classes].filter(([, c]) => c.name === base).map(([l]) => l);
      if (found.length === 1) queue.push(found[0]);
    }
  }
  return out;
}

const insideDef = (src: string, pos: number) => enclosingHeaders(src, pos).some((h) => h.kind === 'def');
const inClassBody = (src: string, pos: number) => enclosingHeaders(src, pos)[0]?.kind === 'class';
const enclosingClass = (src: string, pos: number) => enclosingHeaders(src, pos).find((h) => h.kind === 'class')?.line;

