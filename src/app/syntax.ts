/** Small, conservative data-flow analysis over the three grammar trees. No source text is executed. */
import {
  parseCode,
  isValueNew,
  children,
  walk,
  field,
  ancestor,
  callArgs,
  type AppLanguage,
  type SyntaxNode as Node,
} from './parser.js';
import { formatToGlob } from './actions.js';
import type { ResourceRef, EnvRead } from './facts.js';
export { children, walk, field, ancestor, callArgs };
export type { Node };
const cache = new Map<string, Syntax>();
export function clearSyntax(): void {
  for (const s of cache.values()) s.tree.delete();
  cache.clear();
}
/** Retain only the enclosing file while one function's temporary trees are released. */
export function clearSyntaxExcept(language: AppLanguage, source: string): void {
  const keep = language + '\0' + source;
  for (const [key, s] of cache)
    if (key !== keep) {
      s.tree.delete();
      cache.delete(key);
    }
}
export function syntax(language: AppLanguage, source: string): Syntax {
  const key = language + '\0' + source;
  let s = cache.get(key);
  if (!s) {
    s = new Syntax(language, source);
    cache.set(key, s);
  }
  return s;
}
const functionTypes = new Set([
  'function_declaration',
  'function_expression',
  'arrow_function',
  'method_definition',
  'function_definition',
  'method_declaration',
  'func_literal',
]);
const scopeTypes = new Set([
  ...functionTypes,
  'source_file',
  'program',
  'module',
  'class_definition',
  'class_declaration',
]);
const isFunction = (n: Node) => functionTypes.has(n.type);
export const enclosingFunction = (n: Node) => ancestor(n, isFunction);
export const enclosingClass = (n: Node) =>
  ancestor(n, (n) => n.type === 'class_definition' || n.type === 'class_declaration');
export function literal(n: Node | undefined): string | undefined {
  if (!n) return;
  if (n.type === 'raw_string_literal') return n.text.slice(1, -1);
  if (n.type === 'interpreted_string_literal') {
    try {
      return JSON.parse(n.text);
    } catch {
      return;
    }
  }
  if (n.type === 'string') {
    if (children(n).some((c) => c.type === 'interpolation')) return;
    const start = children(n).find((c) => c.type === 'string_start')?.text;
    if (start && /[fb]/i.test(start)) return;
    const parts = children(n).filter((c) => ['string_content', 'string_fragment', 'escape_sequence'].includes(c.type));
    // Decode string escapes without evaluating application code.
    const text = parts.map((c) => c.text).join('');
    return text.replace(/\\(u\{[0-9a-f]+\}|u[0-9a-f]{4}|x[0-9a-f]{2}|[nrtbfv\\'"/])/gi, (_, e: string) => {
      const simple: Record<string, string> = {
        n: '\n',
        r: '\r',
        t: '\t',
        b: '\b',
        f: '\f',
        v: '\v',
      };
      if (e.startsWith('u{')) return String.fromCodePoint(parseInt(e.slice(2, -1), 16));
      if (e[0] === 'u' || e[0] === 'x') return String.fromCodePoint(parseInt(e.slice(1), 16));
      return simple[e] ?? e;
    });
  }
  if (n.type === 'template_string' && !children(n).some((c) => c.type === 'template_substitution'))
    return children(n)
      .map((c) => c.text)
      .join('');
}
export function member(n: Node | undefined): { object: Node; name: string } | undefined {
  if (!n) return;
  const object = field(n, 'object') ?? field(n, 'operand');
  const name = field(n, 'property') ?? field(n, 'attribute') ?? field(n, 'field');
  if (object && name && ['member_expression', 'attribute', 'selector_expression'].includes(n.type))
    return { object, name: name.text };
}
export function callable(n: Node): Node | undefined {
  let f = field(n, 'function') ?? field(n, 'constructor');
  if (n.type === 'type_conversion_expression') f = field(n, 'type');
  if (f?.type === 'generic_type') return field(f, 'type');
  if (f?.type === 'index_expression') return field(f, 'operand');
  if (f?.type === 'instantiation_expression') return children(f)[0];
  return f;
}
export function args(n: Node): Node[] {
  return n.type === 'type_conversion_expression' ? [field(n, 'operand')!].filter(Boolean) : callArgs(n);
}
export const isCall = (n: Node) =>
  ['call', 'call_expression', 'new_expression', 'type_conversion_expression'].includes(n.type);
export function unwrapped(n: Node): Node {
  for (let i = 0; i < 12; i++) {
    if (['parenthesized_expression', 'non_null_expression', 'as_expression', 'literal_element'].includes(n.type)) {
      n = children(n)[0] ?? n;
      continue;
    }
    if (n.type === 'unary_expression' && field(n, 'operator')?.text === '&') {
      n = field(n, 'operand')!;
      continue;
    }
    if (n.type === 'unary_expression' && n.children[0]?.text === '&') {
      n = field(n, 'operand')!;
      continue;
    }
    if (
      isCall(n) &&
      (isValueNew(n) ||
        ['aws.String', 'aws.ToString', 'strings.TrimSpace', 'string', 'new'].includes(callable(n)?.text ?? ''))
    ) {
      n = args(n)[0] ?? n;
      continue;
    }
    break;
  }
  return n;
}
interface Binding {
  name: string;
  target: Node;
  value?: Node;
  statement: Node;
  declaration: boolean;
  scope: Node;
}
export class Syntax {
  readonly tree;
  readonly nodes: Node[];
  readonly bindings: Binding[] = [];
  constructor(
    readonly language: AppLanguage,
    readonly source: string,
  ) {
    this.tree = parseCode(language, source);
    this.nodes = [...walk(this.tree.rootNode)];
    for (const n of this.nodes) {
      if (n.type === 'variable_declarator') this.bind(field(n, 'name'), field(n, 'value'), n, true);
      else if (
        ['assignment_expression', 'assignment', 'short_var_declaration', 'assignment_statement'].includes(n.type)
      ) {
        const l = field(n, 'left'),
          r = field(n, 'right');
        const ls = l?.type === 'expression_list' ? children(l) : l ? [l] : [];
        const rs = r?.type === 'expression_list' ? children(r) : r ? [r] : [];
        ls.forEach((target, i) =>
          this.bind(target, rs[i] ?? (rs.length === 1 ? rs[0] : undefined), n, n.type === 'short_var_declaration'),
        );
      } else if (['var_spec', 'const_spec'].includes(n.type)) {
        const names = n.childrenForFieldName('name').filter((n): n is Node => n !== null);
        const v = field(n, 'value');
        const values = v?.type === 'expression_list' ? children(v) : v ? [v] : [];
        names.forEach((name, i) => this.bind(name, values[i], n, true));
      }
    }
  }
  private scope(n: Node): Node {
    return (
      ancestor(
        n,
        (n) =>
          scopeTypes.has(n.type) ||
          (this.language !== 'python' &&
            ['block', 'statement_block', 'for_statement', 'if_statement'].includes(n.type)),
      ) ?? this.tree.rootNode
    );
  }
  private bind(target: Node | undefined, value: Node | undefined, statement: Node, declaration: boolean) {
    if (target)
      this.bindings.push({
        name: target.text,
        target,
        value,
        statement,
        declaration,
        scope: this.scope(statement),
      });
  }
  private contains(scope: Node, n: Node) {
    return scope.startIndex <= n.startIndex && scope.endIndex >= n.endIndex;
  }
  private parameterShadows(name: string, use: Node, binding: Binding): boolean {
    // A parameter of any function between the binding and the use shadows the outer name.
    for (let p: Node | undefined = use; p && p.id !== binding.scope.id; p = p.parent ?? undefined) {
      if (!isFunction(p)) continue;
      const params = field(p, 'parameters');
      if (params && [...walk(params)].some((c) => c.type === 'identifier' && c.text === name)) return true;
    }
    return false;
  }
  binding(name: string, use: Node): Binding | undefined {
    let possible = this.bindings.filter(
      (b) =>
        b.name === name &&
        this.contains(b.scope, use) &&
        !this.parameterShadows(name, use, b) &&
        (b.statement.startIndex < use.startIndex ||
          ((this.language === 'go' || this.language === 'python') &&
            ['source_file', 'module'].includes(b.scope.type) &&
            enclosingFunction(use))),
    );
    // Python binds a local throughout its function, including before its first assignment.
    if (this.language === 'python') {
      const fn = enclosingFunction(use);
      if (fn && this.bindings.some((b) => b.name === name && enclosingFunction(b.statement)?.id === fn.id))
        possible = possible.filter((b) => enclosingFunction(b.statement)?.id === fn.id);
    }
    possible.sort((a, b) => a.scope.startIndex - b.scope.startIndex || a.statement.startIndex - b.statement.startIndex);
    const last = possible.at(-1);
    if (!last) return;
    const conditional = this.bindings.some(
      (b) =>
        b.name === name &&
        b.statement.startIndex > last.statement.startIndex &&
        b.statement.startIndex < use.startIndex &&
        enclosingFunction(b.statement)?.id === enclosingFunction(use)?.id &&
        ((!b.declaration && !this.contains(b.scope, use)) ||
          (this.language === 'python' && this.conditional(b.statement, use))),
    );
    if (conditional || (this.language === 'python' && this.conditional(last.statement, use))) return;
    return last;
  }
  private conditional(statement: Node, use: Node): boolean {
    return Boolean(
      ancestor(
        statement,
        (n) =>
          [
            'if_statement',
            'for_statement',
            'while_statement',
            'try_statement',
            'with_statement',
            'match_statement',
          ].includes(n.type) && !this.contains(n, use),
      ),
    );
  }
  resolve(node: Node, depth = 0): Node {
    const n = unwrapped(node);
    if (depth > 10) return n;
    if (n.type === 'identifier') {
      const b = this.binding(n.text, n);
      if (b?.value) return this.resolve(b.value, depth + 1);
    }
    return n;
  }
  fields(node: Node | undefined): Map<string, Node> {
    const out = new Map<string, Node>();
    if (!node) return out;
    const n = this.resolve(node);
    const body = n.type === 'composite_literal' ? field(n, 'body') : n;
    for (const pair of children(body)) {
      if (['pair', 'keyed_element'].includes(pair.type)) {
        const key = field(pair, 'key'),
          value = field(pair, 'value');
        if (key && value) out.set(literal(key) ?? key.text, unwrapped(value));
      } else if (pair.type === 'shorthand_property_identifier') out.set(pair.text, pair);
    }
    return out;
  }
  env(n: Node): { name: string; fallback?: string; hasDefault?: boolean } | undefined {
    if (this.language === 'typescript' || this.language === 'tsx') {
      const m = member(n);
      if (m?.object.text === 'process.env') return { name: m.name };
      if (n.type === 'subscript_expression' && field(n, 'object')?.text === 'process.env') {
        const name = literal(field(n, 'index'));
        if (name !== undefined) return { name };
      }
    } else if (this.language === 'python') {
      if (n.type === 'subscript' && field(n, 'value')?.text === 'os.environ') {
        const name = literal(field(n, 'subscript'));
        if (name !== undefined) return { name };
      }
      if (isCall(n) && ['os.getenv', 'os.environ.get'].includes(callable(n)?.text ?? '')) {
        const a = args(n),
          name = literal(a[0]);
        if (name !== undefined)
          return {
            name,
            ...(a[1] ? { hasDefault: true } : {}),
            ...(literal(a[1]) !== undefined ? { fallback: literal(a[1]) } : {}),
          };
      }
    } else if (isCall(n)) {
      const fn = callable(n)?.text ?? '',
        a = args(n),
        normal = ['os.Getenv', 'os.LookupEnv'].includes(fn);
      if (normal || /env/i.test(fn)) {
        const at = normal ? 0 : a[0]?.text === 'ctx' ? 1 : 0,
          name = literal(a[at]);
        if (name !== undefined && /^[A-Za-z_]\w*$/.test(name))
          return {
            name,
            ...(fn === 'os.LookupEnv' || /OrElse|Default|Lookup|Optional/i.test(fn) || a[at + 1]
              ? { hasDefault: true }
              : {}),
            ...(literal(a[at + 1]) ? { fallback: literal(a[at + 1]) } : {}),
          };
      }
    }
  }
  ref(node: Node, depth = 0): ResourceRef {
    const n = unwrapped(node),
      unknown = (): ResourceRef => ({ kind: 'unresolved', text: n.text });
    if (depth > 12) return unknown();
    const env = this.env(n);
    if (env)
      return {
        kind: 'env',
        name: env.name,
        ...(env.fallback !== undefined ? { fallback: env.fallback } : {}),
      };
    const str = literal(n);
    if (str !== undefined) return { kind: 'literal', value: str };
    if (n.type === 'template_string' || (n.type === 'string' && children(n).some((c) => c.type === 'interpolation'))) {
      return {
        kind: 'pattern',
        glob: children(n)
          .filter((c) => !['string_start', 'string_end'].includes(c.type))
          .map((c) => (['interpolation', 'template_substitution'].includes(c.type) ? '*' : c.text))
          .join(''),
      };
    }
    if (isCall(n) && callable(n)?.text === 'fmt.Sprintf') {
      const f = literal(args(n)[0]);
      if (f !== undefined) return { kind: 'pattern', glob: formatToGlob(f) };
    }
    if (['binary_expression', 'binary_operator', 'boolean_operator'].includes(n.type)) {
      const left = field(n, 'left'),
        right = field(n, 'right'),
        op = field(n, 'operator')?.text ?? n.children.find((c) => c && !c.isNamed)?.text;
      if (left && right) {
        if (['??', '||', 'or'].includes(op ?? '')) {
          const a = this.ref(left, depth + 1),
            b = this.ref(right, depth + 1);
          if (a.kind === 'env')
            return {
              ...a,
              ...(b.kind === 'literal' ? { fallback: b.value } : {}),
            };
          return unknown();
        }
        if (op === '+') {
          const a = this.ref(left, depth + 1),
            b = this.ref(right, depth + 1);
          if (a.kind === 'literal' || b.kind === 'literal' || a.kind === 'pattern' || b.kind === 'pattern')
            return {
              kind: 'pattern',
              glob: [a, b].map((x) => (x.kind === 'literal' ? x.value : x.kind === 'pattern' ? x.glob : '*')).join(''),
            };
        }
      }
      return unknown();
    }
    if (n.type === 'identifier' || n.type === 'shorthand_property_identifier') {
      const binding = this.binding(n.text, n);
      if (binding?.value) return this.ref(binding.value, depth + 1);
    }
    const m = member(n);
    if (m && m.object.text !== 'self') {
      const value = this.fields(m.object).get(m.name);
      if (value) return this.ref(value, depth + 1);
    }
    return unknown();
  }
  reads(file: string, added?: Set<number>): EnvRead[] {
    let nodes = this.nodes.filter(
      (n) =>
        this.env(n) &&
        (this.language !== 'go' ||
          ['os.Getenv', 'os.LookupEnv'].includes(callable(n)?.text ?? '') ||
          Boolean(member(callable(n))?.object.text.match(/env$/i))),
    );
    if (this.language === 'go')
      nodes.sort((a, b) => {
        const rank = (n: Node) =>
          callable(n)?.text === 'os.Getenv' ? 0 : callable(n)?.text === 'os.LookupEnv' ? 1 : 2;
        return rank(a) - rank(b) || a.startIndex - b.startIndex;
      });
    const out: EnvRead[] = nodes.flatMap((n) => {
      const e = this.env(n)!,
        line = n.startPosition.row + 1;
      if (added && !added.has(line)) return [];
      const p = n.parent,
        op = p && field(p, 'operator')?.text;
      return [
        {
          name: e.name,
          file,
          line,
          ...(e.hasDefault || (p && ['??', '||', 'or'].includes(op ?? '') && field(p, 'left')?.id === n.id)
            ? { hasDefault: true as const }
            : {}),
        },
      ];
    });
    if (this.language === 'go')
      for (const n of this.nodes.filter((n) => n.type === 'field_declaration')) {
        const tag = field(n, 'tag'),
          m = tag?.text.match(/\benv:"([A-Za-z_]\w*)[",]/);
        if (!m) continue;
        const line = tag!.startPosition.row + 1;
        if (!added || added.has(line))
          out.push({
            name: m[1],
            file,
            line,
            ...(/envDefault:/.test(tag!.text) ? { hasDefault: true as const } : {}),
          });
      }
    return out;
  }
}
export function expressionRef(language: AppLanguage, expr: string, source: string, offset: number): ResourceRef {
  const s = syntax(language, source);
  const text = expr.trim();
  // Nodes are in source order. A resource expression normally follows the SDK call's start.
  // Avoid materializing the text of every subtree for every resource in a large source file.
  let low = 0,
    high = s.nodes.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (s.nodes[mid].startIndex < offset) low = mid + 1;
    else high = mid;
  }
  const matches = (n: Node) => n.endIndex - n.startIndex === text.length && n.text === text;
  for (let i = low; i < s.nodes.length; i++) if (matches(s.nodes[i])) return s.ref(s.nodes[i]);
  for (let i = low - 1; i >= 0; i--) if (matches(s.nodes[i])) return s.ref(s.nodes[i]);
  const prefix =
    language === 'go' ? 'package p\nfunc f(){_ = ' : language === 'python' ? '__value = ' : 'const __value = ';
  const parsed = syntax(language, prefix + expr + (language === 'go' ? '\n}' : ''));
  const value = parsed.bindings.find((b) => b.name === '__value' || b.name === '_')?.value;
  return value ? parsed.ref(value) : { kind: 'unresolved', text: expr.trim() };
}
export const inRange = (n: Node, added?: Set<number>): boolean =>
  !added ||
  Array.from({ length: n.endPosition.row - n.startPosition.row + 1 }, (_, i) => n.startPosition.row + i + 1).some((l) =>
    added.has(l),
  );
