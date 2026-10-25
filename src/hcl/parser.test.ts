import { describe, expect, test } from 'bun:test';
import type { Body, Expr, ObjectItem, ParseResult, TemplatePart } from './ast.js';
import { lex } from './lexer.js';
import { parseHcl } from './parser.js';

// ---------------------------------------------------------------------------------------------
// Helpers

/** Removes every `range` key so structural assertions stay readable. */
function strip<T>(value: T): T {
  return JSON.parse(JSON.stringify(value, (k, v) => (k === 'range' ? undefined : v)));
}

function parseOk(src: string): Body {
  const r = parseHcl(src);
  expect(r.diagnostics).toEqual([]);
  return r.body;
}

/** Parses `x = <src>` and returns the expression without ranges. */
function expr(src: string): Expr {
  const body = parseOk(`x = ${src}\n`);
  expect(body.attributes).toHaveLength(1);
  return strip(body.attributes[0]!.expr);
}

/** Parses `x = <src>` and returns the template parts without ranges. */
function parts(src: string): TemplatePart[] {
  const e = expr(src);
  if (e.kind !== 'template') throw new Error(`expected template, got ${e.kind}`);
  return e.parts;
}

const scope = (name: string): Expr => ({ kind: 'scope', name }) as Expr;
const lit = (value: string | number | boolean | null): Expr => ({ kind: 'literal', value }) as Expr;
const attr = (obj: Expr, name: string): Expr => ({ kind: 'getattr', obj, name }) as Expr;
const idx = (obj: Expr, key: Expr): Expr => ({ kind: 'index', obj, key }) as Expr;
const tmpl = (...p: TemplatePart[]): Expr => ({ kind: 'template', parts: p, heredoc: false }) as Expr;
const text = (value: string): TemplatePart => ({ kind: 'text', value });
const interp = (e: Expr): TemplatePart => ({ kind: 'interp', expr: e });
const str = (value: string): Expr => tmpl(text(value));
const anon: Expr = { kind: 'anon' } as Expr;
const path = (...names: string[]): Expr => names.slice(1).reduce<Expr>((e, n) => attr(e, n), scope(names[0]!));
const bin = (op: string, left: Expr, right: Expr): Expr => ({ kind: 'binary', op, left, right }) as Expr;

function srcAt(src: string, r: { start: { offset: number }; end: { offset: number } }): string {
  return src.slice(r.start.offset, r.end.offset);
}

// ---------------------------------------------------------------------------------------------

describe('body structure', () => {
  test('attributes and blocks with quoted labels', () => {
    const body = parseOk(`
region = "eu-west-1"

resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  tags = {
    Name = "x"
  }
}
`);
    expect(body.attributes.map((a) => a.name)).toEqual(['region']);
    expect(body.blocks).toHaveLength(1);
    const b = body.blocks[0]!;
    expect(b.type).toBe('resource');
    expect(b.labels).toEqual(['aws_s3_bucket', 'b']);
    expect(b.body.attributes.map((a) => a.name)).toEqual(['bucket', 'tags']);
  });

  test('zero labels, bare identifier labels, nested blocks', () => {
    const body = parseOk(`
terraform {
  backend s3 {
    bucket = "state"
  }
}
locals {}
`);
    expect(body.blocks.map((b) => [b.type, b.labels])).toEqual([
      ['terraform', []],
      ['locals', []],
    ]);
    const backend = body.blocks[0]!.body.blocks[0]!;
    expect(backend.type).toBe('backend');
    expect(backend.labels).toEqual(['s3']);
    expect(backend.body.attributes[0]!.name).toBe('bucket');
  });

  test('labels with escapes are unquoted', () => {
    const body = parseOk(`thing "a\\"b" "c\\u00e9" {}\n`);
    expect(body.blocks[0]!.labels).toEqual(['a"b', 'cé']);
  });

  test('one-line and empty blocks', () => {
    const body = parseOk(`
data "aws_ami" "x" {
  filter { name = "name" }
  filter {}
  lifecycle { ignore_changes = [tags] }
}
`);
    const inner = body.blocks[0]!.body.blocks;
    expect(inner.map((b) => b.type)).toEqual(['filter', 'filter', 'lifecycle']);
    expect(strip(inner[0]!.body.attributes)).toEqual([{ name: 'name', expr: str('name') }] as never);
    expect(inner[1]!.body.attributes).toEqual([]);
    expect(inner[1]!.body.blocks).toEqual([]);
    expect(strip(inner[2]!.body.attributes[0]!.expr)).toEqual({ kind: 'tuple', items: [scope('tags')] } as Expr);
  });

  test('newlines terminate attributes; two attributes on one line is an error', () => {
    const r = parseHcl('a = 1 b = 2\nc = 3\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(r.diagnostics[0]!.message).toContain('Missing newline');
    expect(r.diagnostics[0]!.range.start).toEqual({ offset: 6, line: 1, col: 7 });
    expect(r.body.attributes.map((a) => a.name)).toEqual(['a', 'c']);
  });

  test('file without trailing newline, CRLF line endings and a BOM', () => {
    expect(parseOk('a = 1').attributes).toHaveLength(1);
    const body = parseOk('﻿a = 1\r\nblock {\r\n  b = "x"\r\n}\r\n');
    expect(body.attributes[0]!.name).toBe('a');
    expect(body.blocks[0]!.body.attributes[0]!.name).toBe('b');
    expect(body.blocks[0]!.range.end).toEqual({ offset: 29, line: 4, col: 2 });
  });

  test('unicode identifiers and dashes in names', () => {
    const body = parseOk('my-attr = 1\nnaïve = 2\n');
    expect(body.attributes.map((a) => a.name)).toEqual(['my-attr', 'naïve']);
  });
});

describe('comments', () => {
  test('all three comment styles, between labels and brace, and inside expressions', () => {
    const body = parseOk(`
# hash comment
// slash comment
/* block
   comment */
resource "a" "b" /* between labels and brace */ {
  x = [ # trailing comment inside a tuple
    1, // another
    /* inline */ 2,
  ]
  y = { # comment after brace
    k = 1 # comment ends the item
    j = 2
  }
  z = 1 + /* mid-expression */ 2
}
`);
    const b = body.blocks[0]!;
    expect(b.labels).toEqual(['a', 'b']);
    const [x, y, z] = b.body.attributes.map((a) => strip(a.expr));
    expect(x).toEqual({ kind: 'tuple', items: [lit(1), lit(2)] } as Expr);
    expect(y).toEqual({
      kind: 'object',
      items: [
        { key: lit('k'), value: lit(1) },
        { key: lit('j'), value: lit(2) },
      ],
    } as Expr);
    expect(z).toEqual(bin('+', lit(1), lit(2)));
  });

  test('a comment marker inside a string is text', () => {
    expect(parts('"a # b // c /* d */"')).toEqual([text('a # b // c /* d */')]);
  });
});

describe('literals', () => {
  test('numbers', () => {
    expect(expr('42')).toEqual(lit(42));
    expect(expr('3.25')).toEqual(lit(3.25));
    expect(expr('1e3')).toEqual(lit(1000));
    expect(expr('2.5E-2')).toEqual(lit(0.025));
    expect(expr('-7')).toEqual({ kind: 'unary', op: '-', operand: lit(7) } as Expr);
  });

  test('true, false, null', () => {
    expect(expr('true')).toEqual(lit(true));
    expect(expr('false')).toEqual(lit(false));
    expect(expr('null')).toEqual(lit(null));
  });
});

describe('quoted templates', () => {
  test('plain and empty strings are one text part', () => {
    expect(expr('"hello"')).toEqual(str('hello'));
    expect(expr('""')).toEqual(str(''));
  });

  test('escapes', () => {
    expect(parts(String.raw`"a\nb\tc\"d\\eé\U0001F600\r"`)).toEqual([text('a\nb\tc"d\\eé😀\r')]);
  });

  test('literal $${ and %%{ escapes', () => {
    expect(parts('"$${not_interp} %%{not_directive} $ % $$"')).toEqual([
      text('${not_interp} %{not_directive} $ % $$'),
    ]);
  });

  test('interpolation', () => {
    expect(parts('"arn:aws:s3:::${var.bucket}/*"')).toEqual([
      text('arn:aws:s3:::'),
      interp(path('var', 'bucket')),
      text('/*'),
    ]);
    expect(parts('"${a}${b}"')).toEqual([interp(scope('a')), interp(scope('b'))]);
  });

  test('braces inside strings', () => {
    expect(parts('"}"')).toEqual([text('}')]);
    expect(parts('"${"{"}"')).toEqual([interp(str('{'))]);
    expect(parts('"{${x}}"')).toEqual([text('{'), interp(scope('x')), text('}')]);
    expect(parts('"${ {a = 1}.a }"')).toEqual([
      interp(attr({ kind: 'object', items: [{ key: lit('a'), value: lit(1) }] } as Expr, 'a')),
    ]);
  });

  test('if / else / endif directives', () => {
    expect(parts('"%{ if var.on }yes%{ else }no%{ endif }"')).toEqual([
      { kind: 'if', cond: path('var', 'on'), then: [text('yes')], else: [text('no')] },
    ]);
    expect(parts('"a%{if x}b%{endif}c"')).toEqual([
      text('a'),
      { kind: 'if', cond: scope('x'), then: [text('b')], else: [] },
      text('c'),
    ]);
  });

  test('for directives with one and two variables', () => {
    expect(parts('"%{ for x in xs }${x},%{ endfor }"')).toEqual([
      { kind: 'for', valVar: 'x', coll: scope('xs'), body: [interp(scope('x')), text(',')] },
    ]);
    expect(parts('"%{ for k, v in m }${k}=${v} %{ endfor }"')).toEqual([
      {
        kind: 'for',
        keyVar: 'k',
        valVar: 'v',
        coll: scope('m'),
        body: [interp(scope('k')), text('='), interp(scope('v')), text(' ')],
      },
    ]);
  });

  test('nested directives', () => {
    expect(parts('"%{for x in xs}%{if x}${x}%{endif}%{endfor}"')).toEqual([
      {
        kind: 'for',
        valVar: 'x',
        coll: scope('xs'),
        body: [{ kind: 'if', cond: scope('x'), then: [interp(scope('x'))], else: [] }],
      },
    ]);
  });

  test('strip markers trim whitespace in neighbouring text', () => {
    expect(parts('"a   ${~ x ~}   b"')).toEqual([text('a'), interp(scope('x')), text('b')]);
    expect(parts('"a   ${~ x }   b"')).toEqual([text('a'), interp(scope('x')), text('   b')]);
    expect(parts('"a   ${ x ~}   b"')).toEqual([text('a   '), interp(scope('x')), text('b')]);
    expect(parts('"x %{~ if c ~} y %{~ endif ~} z"')).toEqual([
      text('x'),
      { kind: 'if', cond: scope('c'), then: [text('y')], else: [] },
      text('z'),
    ]);
  });

  test('unbalanced directives are diagnostics', () => {
    expect(parseHcl('x = "%{ if a }b"\n').diagnostics[0]!.message).toContain('endif');
    expect(parseHcl('x = "%{ endfor }"\n').diagnostics[0]!.message).toContain('endfor');
    expect(parseHcl('x = "%{ while a }"\n').diagnostics[0]!.message).toContain('directive');
  });
});

describe('heredocs', () => {
  test('<<EOT keeps text verbatim, including the final newline', () => {
    const e = expr('<<EOT\n  hello\n    world\nEOT');
    expect(e).toEqual({ kind: 'template', heredoc: true, parts: [text('  hello\n    world\n')] } as Expr);
  });

  test('<<-EOT strips the smallest common indentation', () => {
    const body = parseOk('a {\n  x = <<-EOT\n    line1\n      indented\n\n    line3\n    EOT\n}\n');
    const e = strip(body.blocks[0]!.body.attributes[0]!.expr);
    expect(e).toEqual({ kind: 'template', heredoc: true, parts: [text('line1\n  indented\n\nline3\n')] } as Expr);
  });

  test('<<- with an interpolation at the start of a line counts as zero indent', () => {
    expect(parts('<<-EOT\n  a\n${b}\nEOT')).toEqual([text('  a\n'), interp(scope('b')), text('\n')]);
  });

  test('braces, ${jsonencode(x)} and any delimiter', () => {
    const src = 'policy = <<POLICY\n{\n  "a": ${jsonencode(x)},\n  "b": "}"\n}\nPOLICY\nnext = 1\n';
    const body = parseOk(src);
    expect(body.attributes.map((a) => a.name)).toEqual(['policy', 'next']);
    expect(strip(body.attributes[0]!.expr)).toEqual({
      kind: 'template',
      heredoc: true,
      parts: [
        text('{\n  "a": '),
        interp({ kind: 'call', name: 'jsonencode', args: [scope('x')], expandFinal: false } as Expr),
        text(',\n  "b": "}"\n}\n'),
      ],
    } as Expr);
  });

  test('escapes are literal in heredocs except $${ and %%{', () => {
    expect(parts('<<EOT\na\\nb $${x} %%{y} "q"\nEOT')).toEqual([text('a\\nb ${x} %{y} "q"\n')]);
  });

  test('directives and strip markers in heredocs', () => {
    expect(parts('<<EOT\n%{ for ip in ips ~}\nserver ${ip}\n%{ endfor ~}\nEOT')).toEqual([
      { kind: 'for', valVar: 'ip', coll: scope('ips'), body: [text('server '), interp(scope('ip')), text('\n')] },
    ]);
  });

  test('a line that merely starts with the delimiter does not close the heredoc', () => {
    expect(parts('<<EOT\nEOTX\n EOT more\nEOT')).toEqual([text('EOTX\n EOT more\n')]);
  });

  test('heredoc range spans from << to the closing delimiter', () => {
    const src = 'x = <<-EOT\n  a\n  EOT\n';
    const e = parseOk(src).attributes[0]!.expr;
    expect(srcAt(src, e.range)).toBe('<<-EOT\n  a\n  EOT');
  });

  test('heredoc inside a function call argument list', () => {
    const e = expr('trimspace(<<EOT\nhi\nEOT\n)');
    expect(e).toEqual({
      kind: 'call',
      name: 'trimspace',
      args: [{ kind: 'template', heredoc: true, parts: [text('hi\n')] } as Expr],
      expandFinal: false,
    } as Expr);
  });
});

describe('collections', () => {
  test('tuples: commas, trailing comma, multiline, nested', () => {
    expect(expr('[]')).toEqual({ kind: 'tuple', items: [] as Expr[] } as Expr);
    expect(expr('[a, b,]')).toEqual({ kind: 'tuple', items: [scope('a'), scope('b')] } as Expr);
    expect(expr('[\n  1,\n  [2, 3],\n\n]')).toEqual({
      kind: 'tuple',
      items: [lit(1), { kind: 'tuple', items: [lit(2), lit(3)] } as Expr],
    } as Expr);
  });

  test('a tuple missing a comma is a diagnostic', () => {
    expect(parseHcl('x = [1 2]\n').diagnostics[0]!.message).toContain('Missing item separator');
  });

  test('objects: all key forms and separators', () => {
    expect(expr('{ a = 1, "b" = 2, c: 3, (var.k) = 4 }')).toEqual({
      kind: 'object',
      items: [
        { key: lit('a'), value: lit(1) },
        { key: str('b'), value: lit(2) },
        { key: lit('c'), value: lit(3) },
        { key: { kind: 'paren', expr: path('var', 'k') } as Expr, value: lit(4) },
      ],
    } as Expr);
  });

  test('objects: newline separators, trailing comma, nesting, template keys', () => {
    expect(expr('{\n  a = 1\n  b = { c = [1,\n 2] },\n  "${k}" = 3\n}')).toEqual({
      kind: 'object',
      items: [
        { key: lit('a'), value: lit(1) },
        {
          key: lit('b'),
          value: {
            kind: 'object',
            items: [{ key: lit('c'), value: { kind: 'tuple', items: [lit(1), lit(2)] } as Expr }],
          } as Expr,
        },
        { key: tmpl(interp(scope('k'))), value: lit(3) },
      ],
    } as Expr);
    expect(expr('{}')).toEqual({ kind: 'object', items: [] as ObjectItem[] } as Expr);
  });

  test('keyword-named object keys stay literal keys', () => {
    expect(expr('{ for = 1, if = 2, null = 3 }')).toEqual({
      kind: 'object',
      items: [
        { key: lit('for'), value: lit(1) },
        { key: lit('if'), value: lit(2) },
        { key: lit('null'), value: lit(3) },
      ],
    } as Expr);
  });

  test('two object items on one line without a comma is a diagnostic', () => {
    expect(parseHcl('x = { a = 1 b = 2 }\n').diagnostics[0]!.message).toContain('Missing attribute separator');
  });
});

describe('traversals', () => {
  test('attribute, index and legacy index', () => {
    expect(expr('a.b.c')).toEqual(path('a', 'b', 'c'));
    expect(expr('a[0]')).toEqual(idx(scope('a'), lit(0)));
    expect(expr('a["k"].b')).toEqual(attr(idx(scope('a'), str('k')), 'b'));
    expect(expr('a.0')).toEqual(idx(scope('a'), lit(0)));
    expect(expr('a.0.b')).toEqual(attr(idx(scope('a'), lit(0)), 'b'));
    expect(expr('a.0.1')).toEqual(idx(idx(scope('a'), lit(0)), lit(1)));
    expect(expr('a[var.i + 1]')).toEqual(idx(scope('a'), bin('+', path('var', 'i'), lit(1))));
  });

  test('full splat applies every following step to each element', () => {
    expect(expr('a[*].b')).toEqual({ kind: 'splat', obj: scope('a'), each: attr(anon, 'b'), legacy: false } as Expr);
    expect(expr('a[*]')).toEqual({ kind: 'splat', obj: scope('a'), each: anon, legacy: false } as Expr);
    expect(expr('aws_instance.x[*].ebs[0].id')).toEqual({
      kind: 'splat',
      obj: path('aws_instance', 'x'),
      each: attr(idx(attr(anon, 'ebs'), lit(0)), 'id'),
      legacy: false,
    } as Expr);
  });

  test('legacy splat only takes attribute steps', () => {
    expect(expr('a.*.b.c')).toEqual({ kind: 'splat', obj: scope('a'), each: attr(attr(anon, 'b'), 'c'), legacy: true } as Expr);
    expect(expr('a.*.b[0]')).toEqual(
      idx({ kind: 'splat', obj: scope('a'), each: attr(anon, 'b'), legacy: true } as Expr, lit(0)),
    );
  });

  test('traversals on any term', () => {
    expect(expr('f(x).y')).toEqual(attr({ kind: 'call', name: 'f', args: [scope('x')], expandFinal: false } as Expr, 'y'));
    expect(expr('[1, 2][0]')).toEqual(idx({ kind: 'tuple', items: [lit(1), lit(2)] } as Expr, lit(0)));
    expect(expr('(a).b')).toEqual(attr({ kind: 'paren', expr: scope('a') } as Expr, 'b'));
  });

  test('splat ranges', () => {
    const src = 'x = one(aws_iam_role.r[*].arn)\n';
    const call = parseOk(src).attributes[0]!.expr;
    if (call.kind !== 'call') throw new Error('expected call');
    const splat = call.args[0]!;
    expect(srcAt(src, splat.range)).toBe('aws_iam_role.r[*].arn');
    if (splat.kind !== 'splat') throw new Error('expected splat');
    expect(srcAt(src, splat.each.range)).toBe('[*].arn');
  });
});

describe('function calls', () => {
  test('arguments, trailing commas, multiline, empty', () => {
    expect(expr('max(1, 2,)')).toEqual({ kind: 'call', name: 'max', args: [lit(1), lit(2)], expandFinal: false } as Expr);
    expect(expr('timestamp()')).toEqual({ kind: 'call', name: 'timestamp', args: [] as Expr[], expandFinal: false } as Expr);
    expect(expr('merge(\n  local.a,\n  {\n    b = 1\n  },\n)')).toEqual({
      kind: 'call',
      name: 'merge',
      args: [path('local', 'a'), { kind: 'object', items: [{ key: lit('b'), value: lit(1) }] } as Expr],
      expandFinal: false,
    } as Expr);
  });

  test('provider-namespaced functions', () => {
    expect(expr('provider::aws::arn_parse(var.arn).region')).toEqual(
      attr(
        { kind: 'call', name: 'provider::aws::arn_parse', args: [path('var', 'arn')], expandFinal: false } as Expr,
        'region',
      ),
    );
  });

  test('expanding the final argument', () => {
    expect(expr('max(list...)')).toEqual({ kind: 'call', name: 'max', args: [scope('list')], expandFinal: true } as Expr);
    expect(expr('f(a, b...)').kind).toBe('call');
    expect(parseHcl('x = f(a..., b)\n').diagnostics).toHaveLength(1);
  });

  test('concat with a for expression and a glob string', () => {
    const e = expr('concat([for s in data.x.y : s.arn], ["arn:aws:secretsmanager:*:*:secret:provider/*/api-credentials-??????"])');
    expect(e).toEqual({
      kind: 'call',
      name: 'concat',
      args: [
        {
          kind: 'for',
          valVar: 's',
          coll: path('data', 'x', 'y'),
          valExpr: path('s', 'arn'),
          grouping: false,
          isObject: false,
        } as Expr,
        { kind: 'tuple', items: [str('arn:aws:secretsmanager:*:*:secret:provider/*/api-credentials-??????')] } as Expr,
      ],
      expandFinal: false,
    } as Expr);
  });
});

describe('for expressions', () => {
  test('tuple for with index and condition', () => {
    expect(expr('[for x in xs : x]')).toEqual({
      kind: 'for',
      valVar: 'x',
      coll: scope('xs'),
      valExpr: scope('x'),
      grouping: false,
      isObject: false,
    } as Expr);
    expect(expr('[for i, x in xs : x if i > 0]')).toEqual({
      kind: 'for',
      keyVar: 'i',
      valVar: 'x',
      coll: scope('xs'),
      valExpr: scope('x'),
      cond: bin('>', scope('i'), lit(0)),
      grouping: false,
      isObject: false,
    } as Expr);
  });

  test('object for with grouping', () => {
    expect(expr('{for k, v in m : k => v}')).toEqual({
      kind: 'for',
      keyVar: 'k',
      valVar: 'v',
      coll: scope('m'),
      keyExpr: scope('k'),
      valExpr: scope('v'),
      grouping: false,
      isObject: true,
    } as Expr);
    expect(expr('{\n  for s in data.aws_subnet.public : s.availability_zone => s.id...\n}')).toMatchObject({
      kind: 'for',
      valVar: 's',
      grouping: true,
      isObject: true,
    });
  });

  test('multiline for with conditional value', () => {
    const e = expr('[\n  for k, v in var.m :\n    v.enabled ? k : null\n  if v != null\n]');
    expect(e).toMatchObject({ kind: 'for', keyVar: 'k', valVar: 'v', valExpr: { kind: 'conditional' } });
  });

  test('nested for expressions inside jsonencode objects', () => {
    const body = parseOk(`
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [
    for name, cfg in var.queues : {
      Effect   = "Allow"
      Action   = [for a in cfg.actions : "sqs:\${a}"]
      Resource = { for k, q in aws_sqs_queue.q : k => q.arn if k == name }
    }
  ]
})
`);
    const call = body.attributes[0]!.expr;
    expect(call).toMatchObject({ kind: 'call', name: 'jsonencode' });
    const obj = strip(call.kind === 'call' ? call.args[0]! : call);
    if (obj.kind !== 'object') throw new Error('expected object');
    const statement = obj.items[1]!.value;
    expect(statement).toMatchObject({ kind: 'for', keyVar: 'name', valVar: 'cfg', isObject: false });
    if (statement.kind !== 'for' || statement.valExpr.kind !== 'object') throw new Error('expected for/object');
    const [, action, resource] = statement.valExpr.items;
    expect(action!.value).toMatchObject({
      kind: 'for',
      valVar: 'a',
      valExpr: { kind: 'template', parts: [text('sqs:'), interp(scope('a'))] },
    });
    expect(resource!.value).toMatchObject({ kind: 'for', isObject: true, cond: { kind: 'binary', op: '==' } });
  });
});

describe('operators', () => {
  test('precedence from multiplication down to ||', () => {
    expect(expr('a || b && c == d < e + f * g')).toEqual(
      bin('||', scope('a'), bin('&&', scope('b'), bin('==', scope('c'), bin('<', scope('d'), bin('+', scope('e'), bin('*', scope('f'), scope('g'))))))),
    );
  });

  test('left associativity', () => {
    expect(expr('a - b - c')).toEqual(bin('-', bin('-', scope('a'), scope('b')), scope('c')));
    expect(expr('a / b % c')).toEqual(bin('%', bin('/', scope('a'), scope('b')), scope('c')));
  });

  test('all comparison and equality operators', () => {
    for (const op of ['<', '>', '<=', '>=', '==', '!=']) {
      expect(expr(`a ${op} b`)).toEqual(bin(op, scope('a'), scope('b')));
    }
  });

  test('unary binds tighter than binary and covers traversals', () => {
    expect(expr('!a.b && -c * 2')).toEqual(
      bin(
        '&&',
        { kind: 'unary', op: '!', operand: path('a', 'b') } as Expr,
        bin('*', { kind: 'unary', op: '-', operand: scope('c') } as Expr, lit(2)),
      ),
    );
    expect(expr('!!a')).toEqual({ kind: 'unary', op: '!', operand: { kind: 'unary', op: '!', operand: scope('a') } } as Expr);
  });

  test('conditional is lowest and right-associative', () => {
    expect(expr('a == 1 ? "x" : b ? 2 : 3')).toEqual({
      kind: 'conditional',
      cond: bin('==', scope('a'), lit(1)),
      then: str('x'),
      else: { kind: 'conditional', cond: scope('b'), then: lit(2), else: lit(3) } as Expr,
    } as Expr);
  });

  test('newlines are insignificant inside parentheses', () => {
    expect(expr('(\n  var.a\n  ? 1\n  : 2\n)')).toEqual({
      kind: 'paren',
      expr: { kind: 'conditional', cond: path('var', 'a'), then: lit(1), else: lit(2) } as Expr,
    } as Expr);
    expect(expr('(a +\n b)')).toEqual({ kind: 'paren', expr: bin('+', scope('a'), scope('b')) } as Expr);
  });

  test('an operator at the end of a line outside brackets is an error, as in Terraform', () => {
    const r = parseHcl('x = 1 +\n  2\ny = 3\n');
    expect(r.diagnostics.length).toBeGreaterThan(0);
    expect(r.body.attributes.map((a) => a.name)).toContain('y');
  });
});

describe('ranges', () => {
  const src = 'resource "aws_s3_bucket" "b" {\n  bucket = "x-${var.env}"\n  count  = 1\n}\n';

  test('block range spans type keyword to closing brace; body range spans the braces', () => {
    const b = parseOk(src).blocks[0]!;
    expect(b.range.start).toEqual({ offset: 0, line: 1, col: 1 });
    expect(b.range.end).toEqual({ offset: src.length - 1, line: 4, col: 2 });
    expect(srcAt(src, b.body.range)).toBe('{\n  bucket = "x-${var.env}"\n  count  = 1\n}');
  });

  test('attribute range spans name to end of expression', () => {
    const [bucket, count] = parseOk(src).blocks[0]!.body.attributes;
    expect(srcAt(src, bucket!.range)).toBe('bucket = "x-${var.env}"');
    expect(bucket!.range.start).toEqual({ offset: 33, line: 2, col: 3 });
    expect(srcAt(src, count!.range)).toBe('count  = 1');
  });

  test('expression ranges', () => {
    const t = parseOk(src).blocks[0]!.body.attributes[0]!.expr;
    expect(srcAt(src, t.range)).toBe('"x-${var.env}"');
    if (t.kind !== 'template' || t.parts[1]!.kind !== 'interp') throw new Error('expected template');
    const ref = t.parts[1]!.expr;
    expect(srcAt(src, ref.range)).toBe('var.env');
    expect(ref.range.start).toEqual({ offset: 47, line: 2, col: 17 });
    if (ref.kind !== 'getattr') throw new Error('expected getattr');
    expect(srcAt(src, ref.obj.range)).toBe('var');
  });

  test('ranges of calls, for expressions, objects and binary ops', () => {
    const s = 'x = merge({ a = 1 }, [for v in l : v * 2][0])\n';
    const call = parseOk(s).attributes[0]!.expr;
    expect(srcAt(s, call.range)).toBe('merge({ a = 1 }, [for v in l : v * 2][0])');
    if (call.kind !== 'call') throw new Error('expected call');
    expect(srcAt(s, call.args[0]!.range)).toBe('{ a = 1 }');
    const index = call.args[1]!;
    expect(srcAt(s, index.range)).toBe('[for v in l : v * 2][0]');
    if (index.kind !== 'index' || index.obj.kind !== 'for') throw new Error('expected index of for');
    expect(srcAt(s, index.obj.range)).toBe('[for v in l : v * 2]');
    expect(srcAt(s, index.obj.valExpr.range)).toBe('v * 2');
  });
});

describe('error recovery', () => {
  test('a bad attribute does not lose the rest of the file', () => {
    const src = `
resource "a" "b" {
  good1 = 1
  bad = [1, 2
  good2 = "ok"
}

resource "c" "d" {
  x = )
  y = 2
}
`;
    const r: ParseResult = parseHcl(src);
    expect(r.diagnostics.length).toBeGreaterThanOrEqual(2);
    expect(r.body.blocks.map((b) => b.labels)).toEqual([
      ['a', 'b'],
      ['c', 'd'],
    ]);
    expect(r.body.blocks[0]!.body.attributes.map((a) => a.name)).toEqual(['good1', 'good2']);
    expect(r.body.blocks[1]!.body.attributes.map((a) => a.name)).toEqual(['y']);
    for (const d of r.diagnostics) {
      expect(d.range.start.line).toBeGreaterThan(0);
      expect(d.range.start.col).toBeGreaterThan(0);
    }
  });

  test('diagnostic ranges point at the offending token', () => {
    const r = parseHcl('a {\n  x = ]\n}\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(r.diagnostics[0]!.range.start).toEqual({ offset: 10, line: 2, col: 7 });
    expect(r.diagnostics[0]!.message).toContain('Invalid expression');
  });

  test('unterminated string, heredoc and block comment', () => {
    const s1 = parseHcl('a = "abc\nb = 1\n');
    expect(s1.diagnostics[0]!.message).toContain('Unterminated template string');
    expect(s1.body.attributes.map((a) => a.name)).toEqual(['a', 'b']);

    const s2 = parseHcl('a = <<EOT\nnever closed\n');
    expect(s2.diagnostics[0]!.message).toContain('Unterminated heredoc');

    const s3 = parseHcl('a = 1\n/* open');
    expect(s3.diagnostics[0]!.message).toContain('block comment');
    expect(s3.body.attributes).toHaveLength(1);
  });

  test('an unclosed interpolation does not swallow the rest of the file', () => {
    const r = parseHcl('a = "${foo\nb = 1\nc {\n  d = 2\n}\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(r.body.attributes.map((a) => a.name)).toEqual(['b']);
    expect(r.body.blocks[0]!.body.attributes.map((a) => a.name)).toEqual(['d']);
  });

  test('a multi-line interpolation inside a quoted string is valid', () => {
    expect(parseOk('a = "x ${ var.y\n }"\nb = 1\n').attributes).toHaveLength(2);
  });

  test('unclosed block and stray closing brace', () => {
    const r = parseHcl('a {\n  x = 1\n');
    expect(r.diagnostics[0]!.message).toContain('Unclosed block');
    expect(r.body.blocks[0]!.body.attributes).toHaveLength(1);

    const r2 = parseHcl('}\nx = 1\n');
    expect(r2.diagnostics).toHaveLength(1);
    expect(r2.body.attributes).toHaveLength(1);
  });

  test('block header errors skip the block body', () => {
    const r = parseHcl('resource "a" 1 {\n  x = 1\n}\ny = 2\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(r.body.blocks).toHaveLength(0);
    expect(r.body.attributes.map((a) => a.name)).toEqual(['y']);
  });

  test('block opening brace on the next line is an error, as in Terraform', () => {
    const r = parseHcl('a "b"\n{\n  x = 1\n}\n');
    expect(r.diagnostics.length).toBeGreaterThan(0);
  });

  test('interpolated block labels are rejected', () => {
    expect(parseHcl('a "${b}" {}\n').diagnostics[0]!.message).toContain('label');
  });

  test('invalid escapes are reported but the string is kept', () => {
    const r = parseHcl('a = "x\\qy"\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(strip(r.body.attributes[0]!.expr)).toEqual(str('x\\qy'));
  });

  test('invalid characters', () => {
    const r = parseHcl('a = 1\nb = @\nc = 3\n');
    expect(r.diagnostics).toHaveLength(1);
    expect(r.body.attributes.map((a) => a.name)).toEqual(['a', 'c']);
  });

  test('never throws on arbitrary input', () => {
    const inputs = ['{', '}', '"', '${', '<<', '<<EOT', '[for', '{for x in', 'a = "${', 'a = "%{ if }"', 'a.b = 1', '= 1', 'a = [[[[[['];
    for (const s of inputs) {
      expect(() => parseHcl(s)).not.toThrow();
    }
    expect(() => parseHcl('x = ' + '('.repeat(20000) + '1' + ')'.repeat(20000))).not.toThrow();
  });
});

describe('lexer', () => {
  test('distinguishes template closers from braces', () => {
    const types = lex('a = "${ {b = 1} ~}"').tokens.map((t) => t.type);
    expect(types).toEqual([
      'ident',
      'eq',
      'oquote',
      'templateInterp',
      'lbrace',
      'ident',
      'eq',
      'number',
      'rbrace',
      'templateSeqEnd',
      'cquote',
      'eof',
    ]);
  });

  test('line comments keep their newline', () => {
    expect(lex('a # c\nb').tokens.map((t) => t.type)).toEqual(['ident', 'newline', 'ident', 'eof']);
  });
});
