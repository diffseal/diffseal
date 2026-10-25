import { COPY_OPERATIONS, DOCUMENT_CLIENT, RESOURCE_FIELDS, actionsFor, copySourceBucket } from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead, ResourceRef } from './facts.js';
import { indexName, matchBrace, splitTopLevel, topLevelOnly, type SourceFile } from './go.js';
import { visibleInBlocks } from './scope.js';

/*
 * TypeScript / JavaScript extraction: AWS SDK v3 `new XCommand({...})`, @aws-sdk/lib-dynamodb, and
 * SDK v2 `client.method({...})` calls, recognised by the resource field they carry.
 */

const lineAt = (src: string, offset: number) => src.slice(0, offset).split('\n').length;

/** Replace comments and string contents with spaces so patterns only match code. Offsets are kept. */
let masked: { src?: string; code: string } = { code: '' };

/** `codeOnly(src)`, cached for the file being classified: lookups come in runs over one file. */
function maskedCode(src: string): string {
  if (masked.src !== src) masked = { src, code: codeOnly(src) };
  return masked.code;
}

export function codeOnly(src: string, quotes = `'"\``): string {
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
    } else if (quotes.includes(c)) {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      out += c + src.slice(i + 1, j).replace(/[^\n]/g, ' ') + (j < src.length ? c : '');
      i = j;
    } else out += c;
  }
  return out;
}

/**
 * Source for finding env reads: comments and string contents become spaces, offsets are kept. Strings
 * are recognised for all three quote kinds, so `"https://x"` is not a comment. Two things stay: the key
 * of `process.env['X']`, and the code inside a template literal's `${...}`.
 */
export function envCode(src: string): string {
  let out = '';
  let i = 0;
  const masked = (s: string) => s.replace(/[^\n]/g, ' ');
  // Scan code until the end, or until the `}` that closes a template expression.
  const code = (inTemplate: boolean): void => {
    let depth = 0;
    while (i < src.length) {
      const c = src[i];
      if (c === '/' && src[i + 1] === '/') {
        const end = src.indexOf('\n', i);
        const j = end < 0 ? src.length : end;
        out += masked(src.slice(i, j));
        i = j;
      } else if (c === '/' && src[i + 1] === '*') {
        const end = src.indexOf('*/', i + 2);
        const j = end < 0 ? src.length : end + 2;
        out += masked(src.slice(i, j));
        i = j;
      } else if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
        const body = src.slice(i + 1, Math.min(j, src.length));
        out += c + (/process\.env\[\s*$/.test(out) ? body : masked(body)) + (src[j] === c ? c : '');
        i = src[j] === c ? j + 1 : j;
      } else if (c === '`') {
        out += c;
        i++;
        template();
      } else if (c === '{') {
        depth++;
        out += c;
        i++;
      } else if (c === '}') {
        if (inTemplate && depth === 0) return;
        depth--;
        out += c;
        i++;
      } else {
        out += c;
        i++;
      }
    }
  };
  // Inside a template literal: text is masked, `${ ... }` is code.
  const template = (): void => {
    while (i < src.length) {
      const c = src[i];
      if (c === '\\') {
        out += masked(src.slice(i, i + 2));
        i += 2;
      } else if (c === '`') {
        out += c;
        i++;
        return;
      } else if (c === '$' && src[i + 1] === '{') {
        out += '${';
        i += 2;
        code(true);
        if (src[i] === '}') {
          out += '}';
          i++;
        }
      } else {
        out += c === '\n' ? c : ' ';
        i++;
      }
    }
  };
  code(false);
  return out;
}

function packageService(pkg: string): string | undefined {
  const m = pkg.match(/^@aws-sdk\/client-([a-z0-9-]+)$/);
  if (m) return m[1].replace(/-/g, '');
  if (pkg === '@aws-sdk/lib-dynamodb') return 'dynamodb-doc';
  return undefined;
}

/** Local name -> the SDK package's service and the name the package exports it as (`X as Y`, `{ X: Y }`). */
function importedCommands(src: string): Map<string, { service: string; exported: string }> {
  const out = new Map<string, { service: string; exported: string }>();
  const re = /(?:import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*)['"]([^'"]+)['"]/g;
  for (const m of src.matchAll(re)) {
    const service = packageService(m[3]);
    if (!service) continue;
    for (const spec of (m[1] ?? m[2]).split(',')) {
      const parts = spec.trim().replace(/^type\s+/, '').split(/\s+as\s+|\s*:\s*/).map((p) => p.trim());
      const exported = parts[0];
      const local = parts[parts.length - 1];
      if (exported && local) out.set(local, { service, exported });
    }
  }
  return out;
}

// The whole expression: `process.env.BUCKET + "-private"` is not the env value.
const ENV = /^process\.env(?:\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])$/;

export function classifyTsExpr(expr: string, src: string, offset: number, depth = 0): ResourceRef {
  let e = expr.trim().replace(/!$/, '').replace(/\s+as\s+\w+$/, '');
  let fallbackValue: string | undefined;
  const fallback = e.match(/^([\s\S]+?)\s*(?:\?\?|\|\|)\s*([\s\S]+)$/);
  if (fallback && ENV.test(fallback[1].trim())) {
    e = fallback[1].trim();
    fallbackValue = fallback[2].trim().match(/^(['"`])([^'"`]*)\1$/)?.[2];
  }
  const env = e.match(ENV);
  if (env) return fallbackValue !== undefined ? { kind: 'env', name: env[1] ?? env[2], fallback: fallbackValue } : { kind: 'env', name: env[1] ?? env[2] };
  const str = e.match(/^(['"])((?:(?!\1)[^\\]|\\.)*)\1$/);
  if (str) return { kind: 'literal', value: str[2] };
  const tpl = e.match(/^`([\s\S]*)`$/);
  if (tpl) {
    if (!tpl[1].includes('${')) return { kind: 'literal', value: tpl[1] };
    return { kind: 'pattern', glob: tpl[1].replace(/\$\{[^}]*\}/g, '*') };
  }
  // `a ? b : c`, `a || b`, `a && b`: either side may be the value, so `+` cannot be split across them.
  if (/\?\?|\|\||&&|\?(?!\.)/.test(topLevelOnly(e))) return { kind: 'unresolved', text: e };
  // `process.env.BUCKET + "-private"`: the known text with `*` for the parts that are not known.
  const parts = splitTopLevel(e, '+');
  if (parts.length > 1) {
    const pieces = parts.map((p) => classifyTsExpr(p, src, offset, depth + 1));
    if (pieces.some((p) => p.kind === 'literal')) {
      return { kind: 'pattern', glob: pieces.map((p) => (p.kind === 'literal' ? p.value : p.kind === 'pattern' ? p.glob : '*')).join('') };
    }
    return { kind: 'unresolved', text: e };
  }
  if (/^[A-Za-z_$][\w$]*$/.test(e) && depth < 4) {
    // Declarations and plain reassignments (`bucket = x`, not `==`, `=>` or `.bucket =`) are found in
    // code with comments masked (offsets kept), so `// const bucket = "x"` does not count; the value
    // is then read from the original text.
    const before = maskedCode(src).slice(0, offset);
    const name = e.replace(/\$/g, '\\$');
    const all = [...before.matchAll(new RegExp(`(?:(?:const|let|var)\\s+${name}\\s*(?::[^=]+)?|(?<![\\w$.])${name}\\s*)=(?![=>])\\s*`, 'g'))];
    const at = (m: RegExpMatchArray) => (m.index ?? 0) + m[0].search(new RegExp(name));
    const assigns = all.filter((m) => visibleInBlocks(src, at(m), offset, e));
    const last = assigns[assigns.length - 1];
    // A reassignment the use cannot see (inside an `if` after the binding) changes it on some paths only.
    const conditional = last && all.some((m) => (m.index ?? 0) > (last.index ?? 0) && !/^(?:const|let|var)\b/.test(m[0]) && !visibleInBlocks(src, at(m), offset, e));
    if (conditional) return { kind: 'unresolved', text: e };
    const value = last && src.slice((last.index ?? 0) + last[0].length).match(/^[^;\n]+/)?.[0];
    if (last && value) return classifyTsExpr(value, src, last.index ?? 0, depth + 1);
  }
  return { kind: 'unresolved', text: e };
}

const FIELD_SERVICE: Array<[string, string]> = [
  ['Bucket', 's3'],
  ['QueueUrl', 'sqs'],
  ['TopicArn', 'sns'],
  ['TableName', 'dynamodb'],
  ['SecretId', 'secretsmanager'],
  ['StateMachineArn', 'sfn'],
  ['FunctionName', 'lambda'],
  ['StreamName', 'kinesis'],
  ['DeliveryStreamName', 'firehose'],
];

function fieldsOf(body: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const part of splitTopLevel(body)) {
    const f = part.match(/^['"]?([A-Za-z_]\w*)['"]?\s*:\s*([\s\S]+)$/);
    if (f) fields.set(f[1], f[2].trim());
    else if (/^[A-Z]\w*$/.test(part)) fields.set(part, part);
  }
  return fields;
}

export function envReadsTs(src: string, file: string, added?: Set<number>): EnvRead[] {
  const out: EnvRead[] = [];
  for (const m of src.matchAll(/process\.env(?:\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])(\s*(?:\?\?|\|\|))?/g)) {
    const line = lineAt(src, m.index!);
    if (added && !added.has(line)) continue;
    out.push({ name: m[1] ?? m[2], file, line, ...(m[3] ? { hasDefault: true } : {}) });
  }
  return out;
}

export function extractTs(files: SourceFile[], opts: { addedLines?: AddedLines } = {}): AppScan {
  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];
  for (const f of files) {
    const added = opts.addedLines?.get(f.path);
    if (opts.addedLines && !added) continue;
    const code = codeOnly(f.content);
    envReads.push(...envReadsTs(envCode(f.content), f.path, added));
    const commands = importedCommands(f.content);
    const inRange = (start: number, end: number) => {
      if (!added) return true;
      for (let l = lineAt(f.content, start); l <= lineAt(f.content, end); l++) if (added.has(l)) return true;
      return false;
    };
    const push = (service: string, op: string, start: number, end: number, body: string) => {
      if (!inRange(start, end)) return;
      const fields = fieldsOf(body);
      const field = (RESOURCE_FIELDS[service] ?? []).find((x) => fields.has(x));
      facts.push({
        service,
        operation: op,
        actions: actionsFor(service, op),
        resource: field ? classifyTsExpr(fields.get(field)!, f.content, start) : { kind: 'unresolved', text: '(no resource field)' },
        file: f.path,
        line: lineAt(f.content, start),
        ...(fields.has('IndexName') ? { index: indexName(classifyTsExpr(fields.get('IndexName')!, f.content, start)) } : {}),
      });
      if (service === 's3' && COPY_OPERATIONS.has(op)) {
        facts.push({
          service: 's3',
          operation: 'GetObject',
          actions: ['s3:GetObject'],
          resource: fields.has('CopySource') ? copySourceBucket(classifyTsExpr(fields.get('CopySource')!, f.content, start), fields.get('CopySource')!) : { kind: 'unresolved', text: '(no CopySource)' },
          file: f.path,
          line: lineAt(f.content, start),
        });
      }
    };

    for (const m of code.matchAll(/new\s+([A-Z]\w*)\s*\(\s*\{/g)) {
      const imported = commands.get(m[1]);
      // The operation comes from the exported name: `GetObjectCommand as Read` is still GetObject.
      const name = imported?.exported.match(/^([A-Z]\w*)Command$/)?.[1];
      if (!imported || !name) continue;
      const open = m.index! + m[0].length - 1;
      const close = matchBrace(f.content, open);
      const doc = imported.service === 'dynamodb-doc';
      const service = doc ? 'dynamodb' : imported.service;
      const op = doc ? DOCUMENT_CLIENT[name] ?? name : name;
      push(service, op, m.index!, close, f.content.slice(open + 1, close));
    }

    if (/require\(\s*['"]aws-sdk['"]\s*\)|from\s+['"]aws-sdk['"]/.test(f.content)) {
      for (const m of code.matchAll(/\.([a-z]\w*)\(\s*\{/g)) {
        const open = m.index! + m[0].length - 1;
        const close = matchBrace(f.content, open);
        const body = f.content.slice(open + 1, close);
        const fields = fieldsOf(body);
        const hit = FIELD_SERVICE.find(([field]) => fields.has(field));
        if (!hit) continue;
        const method = m[1];
        const op = DOCUMENT_CLIENT[method[0].toUpperCase() + method.slice(1)] && hit[1] === 'dynamodb' && /^(put|get|query|scan|update|delete|batchWrite|batchGet|transactWrite|transactGet)$/.test(method)
          ? DOCUMENT_CLIENT[method[0].toUpperCase() + method.slice(1)]
          : method[0].toUpperCase() + method.slice(1);
        push(hit[1], op, m.index!, close, body);
      }
    }
  }
  return { facts, envReads };
}
