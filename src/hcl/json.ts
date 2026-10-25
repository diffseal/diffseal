/** Terraform's JSON-to-HCL mapping. Configuration is parsed, never executed. */
import type { Body, Block, Expr, Range, ParseResult } from './ast.js';
import { parseHcl } from './parser.js';
import { resourceSchema } from '../terraform/schemaCatalog.js';
interface JsonNode {
  value: unknown;
  range: Range;
  items?: JsonNode[];
  properties?: Array<{ key: JsonNode; value: JsonNode }>;
}
const labels: Record<string, number> = {
  resource: 2,
  data: 2,
  provider: 1,
  variable: 1,
  output: 1,
  module: 1,
  check: 1,
  terraform: 0,
  locals: 0,
  moved: 0,
  removed: 0,
  import: 0,
};
const nested: Record<string, Record<string, number>> = {
  terraform: { backend: 1, cloud: 0, required_providers: 0 },
  provider: { assume_role: 0, assume_role_with_web_identity: 0, default_tags: 0, ignore_tags: 0 },
  lifecycle: { precondition: 0, postcondition: 0 },
  variable: { validation: 0 },
  check: { assert: 0 },
  dynamic: { content: 0 },
};
export function parseJsonConfig(source: string, file = ''): ParseResult {
  let at = 0;
  const lineStarts = [0];
  for (let i = 0; i < source.length; i++) if (source[i] === '\n') lineStarts.push(i + 1);
  const pos = (offset: number) => {
    let lo = 0,
      hi = lineStarts.length;
    while (lo + 1 < hi) {
      const mid = (lo + hi) >>> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid;
    }
    return { offset, line: lo + 1, col: offset - lineStarts[lo] + 1 };
  };
  const range = (a: number, b: number): Range => ({ start: pos(a), end: pos(b) });
  const skip = () => {
    while (/\s/.test(source[at] ?? '') && at < source.length) at++;
  };
  const string = (): JsonNode => {
    const start = at++;
    while (at < source.length) {
      if (source[at] === '\\') {
        at += 2;
        continue;
      }
      if (source[at++] === '"') return { value: JSON.parse(source.slice(start, at)), range: range(start, at) };
    }
    throw new Error('Unterminated JSON string');
  };
  const read = (): JsonNode => {
    skip();
    const start = at,
      c = source[at];
    if (c === '"') return string();
    if (c === '{') {
      at++;
      skip();
      const properties: Array<{ key: JsonNode; value: JsonNode }> = [],
        seen = new Set<string>();
      if (source[at] !== '}')
        for (;;) {
          skip();
          if (source[at] !== '"') throw new Error('Expected a JSON property name');
          const key = string();
          skip();
          if (source[at++] !== ':') throw new Error('Expected :');
          const value = read();
          const name = String(key.value);
          if (seen.has(name) && name !== '//') throw new Error('Duplicate JSON property ' + name);
          seen.add(name);
          properties.push({ key, value });
          skip();
          if (source[at] !== ',') break;
          at++;
        }
      if (source[at++] !== '}') throw new Error('Expected }');
      return { value: {}, properties, range: range(start, at) };
    }
    if (c === '[') {
      at++;
      skip();
      const items: JsonNode[] = [];
      if (source[at] !== ']')
        for (;;) {
          items.push(read());
          skip();
          if (source[at] !== ',') break;
          at++;
        }
      if (source[at++] !== ']') throw new Error('Expected ]');
      return { value: [], items, range: range(start, at) };
    }
    while (at < source.length && !/[\s,\]}]/.test(source[at])) at++;
    const raw = source.slice(start, at);
    if (!/^(?:null|true|false|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/.test(raw))
      throw new Error('Invalid JSON value');
    return { value: JSON.parse(raw), range: range(start, at) };
  };
  const diagnostics: ParseResult['diagnostics'] = [];
  const relocate = (expr: Expr, r: Range): Expr => {
    const visit = (v: unknown): void => {
      if (!v || typeof v !== 'object') return;
      if ('range' in v) (v as { range: Range }).range = r;
      for (const [k, x] of Object.entries(v))
        if (k !== 'range') {
          if (Array.isArray(x)) x.forEach(visit);
          else visit(x);
        }
    };
    visit(expr);
    return expr;
  };
  const expression = (node: JsonNode, mode: 'template' | 'literal' | 'reference' = 'template'): Expr => {
    const r = node.range;
    if (node.items) return { kind: 'tuple', items: node.items.map((n) => expression(n, mode)), range: r };
    if (node.properties)
      return {
        kind: 'object',
        items: node.properties.map((p) => ({
          key: { kind: 'literal', value: String(p.key.value), range: p.key.range },
          value: expression(p.value, mode),
        })),
        range: r,
      };
    if (typeof node.value === 'string' && mode !== 'literal') {
      const parsed = parseHcl(
        'value = ' + (mode === 'reference' ? node.value : JSON.stringify(node.value)) + '\n',
        file,
      );
      if (parsed.diagnostics.length || !parsed.body.attributes[0])
        throw new Error('Invalid Terraform expression in JSON string');
      return relocate(parsed.body.attributes[0].expr, r);
    }
    return { kind: 'literal', value: node.value as string | number | boolean | null, range: r };
  };
  const body = (node: JsonNode, type: string, resource?: string, prefix = '', literalContext = false): Body => {
    if (!node.properties) throw new Error('Expected a JSON block body object');
    const out: Body = { attributes: [], blocks: [], range: node.range };
    for (const { key, value } of node.properties) {
      const name = String(key.value);
      if (name === '//') continue;
      const schemaPath = prefix ? prefix + '.' + name : name;
      let count = nested[type]?.[name];
      if (['resource', 'data'].includes(type) || resource) {
        if (['lifecycle', 'connection'].includes(name) && !prefix) count = 0;
        if (['provisioner', 'dynamic'].includes(name)) count = 1;
        if (resourceSchema(resource ?? '')?.blocks[schemaPath] !== undefined) count = 0;
        if (
          resource === 'aws_iam_policy_document' &&
          ['statement', 'principals', 'not_principals', 'condition'].includes(name)
        )
          count = 0;
      }
      if (count !== undefined) {
        emit(name, value, count, [], out.blocks, resource, schemaPath, literalContext || type === 'terraform');
        continue;
      }
      let mode: 'template' | 'literal' | 'reference' = literalContext || type === 'terraform' ? 'literal' : 'template';
      if (
        (type === 'variable' && ['default', 'description'].includes(name)) ||
        (type === 'module' && ['source', 'version'].includes(name)) ||
        (type === 'provider' && ['alias', 'version'].includes(name)) ||
        (type === 'output' && ['description', 'sensitive'].includes(name)) ||
        (type === 'connection' && name === 'type')
      )
        mode = 'literal';
      if (
        (type === 'variable' && name === 'type') ||
        (['resource', 'data'].includes(type) && ['provider', 'depends_on'].includes(name)) ||
        (type === 'lifecycle' && ['ignore_changes', 'replace_triggered_by'].includes(name)) ||
        (type === 'dynamic' && name === 'iterator') ||
        (['moved', 'removed', 'import'].includes(type) && ['from', 'to'].includes(name))
      )
        mode = 'reference';
      let expr: Expr;
      if (type === 'module' && name === 'providers' && value.properties)
        expr = {
          kind: 'object',
          items: value.properties.map((p) => ({
            key: expression(p.key, 'literal'),
            value: expression(p.value, 'reference'),
          })),
          range: value.range,
        };
      else expr = expression(value, mode);
      out.attributes.push({ name, expr, range: { start: key.range.start, end: value.range.end } });
    }
    return out;
  };
  const emit = (
    type: string,
    node: JsonNode,
    count: number,
    names: string[],
    blocks: Block[],
    resource?: string,
    prefix = '',
    literalContext = false,
  ): void => {
    if (node.items) {
      for (const item of node.items) emit(type, item, count, names, blocks, resource, prefix, literalContext);
      return;
    }
    if (count) {
      if (!node.properties) throw new Error('Expected JSON block labels');
      for (const p of node.properties)
        if (p.key.value !== '//')
          emit(type, p.value, count - 1, [...names, String(p.key.value)], blocks, resource, prefix, literalContext);
      return;
    }
    const resourceType = ['resource', 'data'].includes(type) ? names[0] : resource;
    blocks.push({
      type,
      labels: names,
      body: body(node, type, resourceType, prefix, literalContext),
      range: node.range,
    });
  };
  try {
    const root = read();
    skip();
    if (at !== source.length) throw new Error('Unexpected text after JSON configuration');
    if (!root.properties) throw new Error('Configuration must be a JSON object');
    const result: Body = { attributes: [], blocks: [], range: root.range };
    for (const { key, value } of root.properties) {
      const type = String(key.value);
      if (type === '//') continue;
      if (labels[type] === undefined) throw new Error('Unsupported JSON configuration block ' + type);
      emit(type, value, labels[type], [], result.blocks);
    }
    return { body: result, diagnostics };
  } catch (e) {
    return {
      body: { attributes: [], blocks: [], range: range(0, source.length) },
      diagnostics: [
        {
          message: e instanceof Error ? e.message : String(e),
          range: range(Math.min(at, source.length), Math.min(at + 1, source.length)),
        },
      ],
    };
  }
}
