/**
 * Recursive-descent parser for the HCL native syntax
 * (https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md), producing the AST in ./ast.ts.
 *
 * Newline handling follows hclsyntax: newlines terminate attributes and separate object items, and
 * are ignored inside parentheses, brackets, function arguments, for expressions and template
 * interpolations. The parser never throws: errors become diagnostics, and the body parser skips to
 * the next line (or the enclosing closing brace) and continues.
 */

import type {
  Attribute,
  BinaryOp,
  Block,
  Body,
  Expr,
  ForExpr,
  LiteralExpr,
  ObjectItem,
  ParseDiagnostic,
  ParseResult,
  Pos,
  Range,
  TemplateExpr,
  TemplatePart,
} from './ast.js';
import { lex, type Token, type TokenType } from './lexer.js';

export type { ParseResult, ParseDiagnostic } from './ast.js';

class ParseError extends Error {
  constructor(
    message: string,
    readonly range: Range,
  ) {
    super(message);
  }
}

/** Binary operator precedence levels, lowest first. */
const BINARY_LEVELS: ReadonlyArray<Partial<Record<TokenType, BinaryOp>>> = [
  { or: '||' },
  { and: '&&' },
  { eqeq: '==', neq: '!=' },
  { lt: '<', gt: '>', lte: '<=', gte: '>=' },
  { plus: '+', minus: '-' },
  { star: '*', slash: '/', percent: '%' },
];

const OPENER_CLOSER: Partial<Record<TokenType, TokenType>> = {
  lbrace: 'rbrace',
  lbrack: 'rbrack',
  lparen: 'rparen',
  oquote: 'cquote',
  oheredoc: 'cheredoc',
  templateInterp: 'templateSeqEnd',
  templateControl: 'templateSeqEnd',
};
const CLOSERS = new Set<TokenType>(['rbrace', 'rbrack', 'rparen', 'cquote', 'cheredoc', 'templateSeqEnd']);

const TOKEN_DESC: Partial<Record<TokenType, string>> = {
  newline: 'newline',
  eof: 'end of file',
  rbrace: '"}"',
  rbrack: '"]"',
  rparen: '")"',
  lbrace: '"{"',
  eq: '"="',
  colon: '":"',
  fatArrow: '"=>"',
  templateSeqEnd: '"}"',
  cquote: 'closing quote',
  cheredoc: 'heredoc end marker',
};

/** Flat template element before directives are nested. */
type TemplateItem =
  | { k: 'lit'; v: string }
  | { k: 'interp'; expr: Expr }
  | { k: 'if'; cond: Expr; range: Range }
  | { k: 'else'; range: Range }
  | { k: 'endif'; range: Range }
  | { k: 'for'; keyVar?: string; valVar: string; coll: Expr; range: Range }
  | { k: 'endfor'; range: Range };

class Parser {
  private readonly tokens: Token[];
  private pos = 0;
  /** Stack of "newlines are significant" flags. */
  private readonly nl: boolean[] = [true];
  private readonly diags: ParseDiagnostic[] = [];
  private readonly lineStarts: number[] = [0];

  constructor(private readonly src: string) {
    for (let i = 0; i < src.length; i++) {
      if (src.charCodeAt(i) === 10) this.lineStarts.push(i + 1);
    }
    const lexed = lex(src);
    this.tokens = lexed.tokens;
    for (const d of lexed.diagnostics) this.diags.push({ message: d.message, range: this.range(d.start, d.end) });
  }

  parseFile(): ParseResult {
    const body = this.parseBody(false);
    body.range = this.range(0, this.src.length);
    this.diags.sort((a, b) => a.range.start.offset - b.range.start.offset);
    return { body, diagnostics: this.diags };
  }

  // ---------------------------------------------------------------------------------------------
  // Positions

  private posAt(offset: number): Pos {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { offset, line: lo + 1, col: offset - this.lineStarts[lo]! + 1 };
  }

  private range(start: number, end: number): Range {
    return { start: this.posAt(start), end: this.posAt(end) };
  }

  private tokRange(t: Token): Range {
    return this.range(t.start, t.end);
  }

  private spanRange(start: Range, end: Range): Range {
    return { start: start.start, end: end.end };
  }

  private error(message: string, t: Token): ParseError {
    return new ParseError(message, this.tokRange(t));
  }

  private describe(t: Token): string {
    return TOKEN_DESC[t.type] ?? `"${t.text}"`;
  }

  // ---------------------------------------------------------------------------------------------
  // Token access

  private get significant(): boolean {
    return this.nl[this.nl.length - 1]!;
  }

  /** Current token, skipping newlines when they are insignificant in the current context. */
  private peek(): Token {
    if (!this.significant) {
      while (this.tokens[this.pos]!.type === 'newline') this.pos++;
    }
    return this.tokens[this.pos]!;
  }

  /** The token `k` positions after the current one, honouring newline significance. */
  private peekAt(k: number): Token {
    let i = this.pos;
    const skip = !this.significant;
    for (;;) {
      if (skip) while (this.tokens[i]!.type === 'newline') i++;
      if (k === 0 || this.tokens[i]!.type === 'eof') return this.tokens[i]!;
      i++;
      k--;
    }
  }

  private next(): Token {
    const t = this.peek();
    if (t.type !== 'eof') this.pos++;
    return t;
  }

  private expect(type: TokenType, what: string): Token {
    const t = this.peek();
    if (t.type !== type) throw this.error(`Expected ${what}, found ${this.describe(t)}`, t);
    return this.next();
  }

  private expectIdent(what: string): Token {
    return this.expect('ident', what);
  }

  private expectKeyword(word: string): Token {
    const t = this.peek();
    if (t.type !== 'ident' || t.text !== word) throw this.error(`Expected "${word}", found ${this.describe(t)}`, t);
    return this.next();
  }

  private skipNewlines(): void {
    while (this.tokens[this.pos]!.type === 'newline') this.pos++;
  }

  private withNewlines<T>(significant: boolean, fn: () => T): T {
    this.nl.push(significant);
    try {
      return fn();
    } finally {
      this.nl.pop();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Bodies

  private parseBody(inBlock: boolean): Body {
    const attributes: Attribute[] = [];
    const blocks: Block[] = [];
    const startTok = this.tokens[this.pos]!;

    for (;;) {
      const t = this.tokens[this.pos]!;
      if (t.type === 'newline') {
        this.pos++;
        continue;
      }
      if (t.type === 'eof') break;
      if (t.type === 'rbrace') {
        if (inBlock) break;
        this.diags.push({ message: 'Unexpected "}": no block is open here', range: this.tokRange(t) });
        this.pos++;
        continue;
      }

      const itemStart = this.pos;
      const nlDepth = this.nl.length;
      try {
        if (t.type !== 'ident') {
          throw this.error(`Argument or block definition required, found ${this.describe(t)}`, t);
        }
        const after = this.tokens[this.pos + 1]!;
        if (after.type === 'eq') {
          attributes.push(this.parseAttribute(inBlock));
        } else if (after.type === 'ident' || after.type === 'oquote' || after.type === 'lbrace') {
          blocks.push(this.parseBlock(inBlock));
        } else if (after.type === 'newline' || after.type === 'eof') {
          throw this.error(
            `Argument or block definition required: "${t.text}" must be followed by "=" or a block body`,
            t,
          );
        } else {
          throw this.error(
            `Expected "=" or a block label after "${t.text}", found ${this.describe(after)}`,
            after,
          );
        }
      } catch (e) {
        this.nl.length = nlDepth;
        this.diags.push(this.toDiagnostic(e, t));
        this.recover(itemStart);
      }
    }

    const endTok = this.tokens[this.pos]!;
    return { attributes, blocks, range: this.range(startTok.start, endTok.end) };
  }

  private toDiagnostic(e: unknown, at: Token): ParseDiagnostic {
    if (e instanceof ParseError) return { message: e.message, range: e.range };
    const reason = e instanceof RangeError ? 'expression nested too deeply' : String(e);
    return { message: `Internal parser error: ${reason}`, range: this.tokRange(at) };
  }

  /** After an attribute or block: a newline, end of file, or (in a block) the closing brace. */
  private endItem(inBlock: boolean, what: string): void {
    const t = this.tokens[this.pos]!;
    if (t.type === 'newline') {
      this.pos++;
      return;
    }
    if (t.type === 'eof' || (inBlock && t.type === 'rbrace')) return;
    this.diags.push({
      message: `Missing newline after ${what}: found ${this.describe(t)}; each argument or block must be on its own line`,
      range: this.tokRange(t),
    });
    this.recover(this.pos);
  }

  private parseAttribute(inBlock: boolean): Attribute {
    const name = this.next();
    this.next(); // '='
    const expr = this.parseExpression();
    const attr: Attribute = { name: name.text, expr, range: this.range(name.start, expr.range.end.offset) };
    this.endItem(inBlock, 'argument definition');
    return attr;
  }

  private parseBlock(inBlock: boolean): Block {
    const typeTok = this.next();
    const labels: string[] = [];
    for (;;) {
      const t = this.tokens[this.pos]!;
      if (t.type === 'lbrace') break;
      if (t.type === 'ident') {
        labels.push(t.text);
        this.pos++;
      } else if (t.type === 'oquote') {
        labels.push(this.parseLabel());
      } else if (t.type === 'newline' || t.type === 'eof') {
        throw this.error(
          'Invalid block definition: the opening "{" must be on the same line as the block type and labels',
          t,
        );
      } else {
        throw this.error(`Invalid block definition: expected a label or "{", found ${this.describe(t)}`, t);
      }
    }
    const open = this.tokens[this.pos++]!;
    const body = this.parseBody(true);
    const close = this.tokens[this.pos]!;
    let end: number;
    if (close.type === 'rbrace') {
      this.pos++;
      end = close.end;
    } else {
      this.diags.push({
        message: `Unclosed block "${typeTok.text}": missing "}" before end of file`,
        range: this.tokRange(open),
      });
      end = close.start;
    }
    body.range = this.range(open.start, end);
    const block: Block = { type: typeTok.text, labels, body, range: this.range(typeTok.start, end) };
    this.endItem(inBlock, 'block definition');
    return block;
  }

  private parseLabel(): string {
    const tmpl = this.parseQuotedTemplate();
    let value = '';
    for (const part of tmpl.parts) {
      if (part.kind !== 'text') {
        throw new ParseError('Invalid block label: template sequences are not allowed in labels', tmpl.range);
      }
      value += part.value;
    }
    return value;
  }

  /**
   * Skips tokens from `from` to the end of the broken item: the next newline outside any brackets, or
   * just before a `}` that closes the enclosing block. A newline inside unclosed brackets also ends
   * recovery when the next line looks like a sibling item (starts at or left of the item's column),
   * so one unclosed bracket or `${` does not swallow the rest of the file. Template text is never
   * tokenized as `ident =`, so this cannot fire inside a string or heredoc.
   */
  private recover(from: number): void {
    const startTok = this.tokens[from]!;
    const itemCol = this.posAt(startTok.start).col;
    const stack: TokenType[] = [];
    let i = from;
    for (;;) {
      const t = this.tokens[i]!;
      if (t.type === 'eof') break;
      const closer = OPENER_CLOSER[t.type];
      if (closer) {
        stack.push(closer);
        i++;
        continue;
      }
      if (CLOSERS.has(t.type)) {
        const idx = stack.lastIndexOf(t.type);
        if (idx === -1) {
          if (t.type === 'rbrace') break;
        } else {
          stack.length = idx;
        }
        i++;
        continue;
      }
      if (t.type === 'newline') {
        i++;
        if (stack.length === 0) break;
        const nextTok = this.tokens[i]!;
        const afterNext = this.tokens[i + 1]!;
        if (
          nextTok.type === 'ident' &&
          this.posAt(nextTok.start).col <= itemCol &&
          (afterNext.type === 'eq' || afterNext.type === 'oquote' || afterNext.type === 'lbrace')
        ) {
          break;
        }
        continue;
      }
      i++;
    }
    this.pos = Math.max(i, from);
  }

  // ---------------------------------------------------------------------------------------------
  // Expressions

  private parseExpression(): Expr {
    const cond = this.parseBinary(0);
    if (this.peek().type !== 'question') return cond;
    this.next();
    const then = this.parseExpression();
    this.expect('colon', '":" in conditional expression');
    const otherwise = this.parseExpression();
    return { kind: 'conditional', cond, then, else: otherwise, range: this.spanRange(cond.range, otherwise.range) };
  }

  private parseBinary(level: number): Expr {
    if (level === BINARY_LEVELS.length) return this.parseUnary();
    const ops = BINARY_LEVELS[level]!;
    let left = this.parseBinary(level + 1);
    for (;;) {
      const op = ops[this.peek().type];
      if (!op) return left;
      this.next();
      const right = this.parseBinary(level + 1);
      left = { kind: 'binary', op, left, right, range: this.spanRange(left.range, right.range) };
    }
  }

  private parseUnary(): Expr {
    const t = this.peek();
    if (t.type === 'bang' || t.type === 'minus') {
      this.next();
      const operand = this.parseUnary();
      return {
        kind: 'unary',
        op: t.type === 'bang' ? '!' : '-',
        operand,
        range: this.range(t.start, operand.range.end.offset),
      };
    }
    return this.parseTraversals(this.parseTerm());
  }

  private parseTerm(): Expr {
    const t = this.peek();
    switch (t.type) {
      case 'number':
        this.next();
        return { kind: 'literal', value: Number(t.text), range: this.tokRange(t) };
      case 'ident':
        return this.parseIdentTerm();
      case 'oquote':
        return this.parseQuotedTemplate();
      case 'oheredoc':
        return this.parseHeredoc();
      case 'lparen': {
        this.next();
        return this.withNewlines(false, () => {
          const expr = this.parseExpression();
          const close = this.expect('rparen', '")"');
          return { kind: 'paren', expr, range: this.range(t.start, close.end) };
        });
      }
      case 'lbrack':
        return this.parseTuple();
      case 'lbrace':
        return this.parseObject();
      default:
        throw this.error(`Invalid expression: expected the start of an expression, found ${this.describe(t)}`, t);
    }
  }

  private parseIdentTerm(): Expr {
    const t = this.next();
    if (t.text === 'true' || t.text === 'false') {
      return { kind: 'literal', value: t.text === 'true', range: this.tokRange(t) };
    }
    if (t.text === 'null') return { kind: 'literal', value: null, range: this.tokRange(t) };

    let name = t.text;
    let end = t.end;
    // Namespaced function name: provider::aws::arn_parse. The colons must be adjacent.
    for (;;) {
      const c1 = this.tokens[this.pos]!;
      const c2 = this.tokens[this.pos + 1]!;
      if (c1.type !== 'colon' || c2.type !== 'colon' || c1.start !== end || c2.start !== c1.end) break;
      this.pos += 2;
      const part = this.tokens[this.pos]!;
      if (part.type !== 'ident') throw this.error('Expected a name after "::"', part);
      this.pos++;
      name += '::' + part.text;
      end = part.end;
    }

    if (this.peek().type === 'lparen') return this.parseCall(name, t);
    if (name.includes('::')) {
      throw new ParseError(`Namespaced function "${name}" must be called with "(...)"`, this.range(t.start, end));
    }
    return { kind: 'scope', name, range: this.tokRange(t) };
  }

  private parseCall(name: string, nameTok: Token): Expr {
    this.next(); // '('
    return this.withNewlines(false, () => {
      const args: Expr[] = [];
      let expandFinal = false;
      while (this.peek().type !== 'rparen') {
        args.push(this.parseExpression());
        const t = this.peek();
        if (t.type === 'ellipsis') {
          this.next();
          expandFinal = true;
          if (this.peek().type === 'comma') this.next();
          if (this.peek().type !== 'rparen') {
            throw this.error('Expected ")" after "...": only the final argument can be expanded', this.peek());
          }
          break;
        }
        if (t.type === 'comma') {
          this.next();
          continue;
        }
        if (t.type !== 'rparen') {
          throw this.error(`Missing argument separator: expected "," or ")", found ${this.describe(t)}`, t);
        }
      }
      const close = this.next();
      return { kind: 'call', name, args, expandFinal, range: this.range(nameTok.start, close.end) };
    });
  }

  private parseTraversals(expr: Expr): Expr {
    for (;;) {
      const t = this.peek();
      if (t.type === 'dot') {
        this.next();
        const nt = this.peek();
        if (nt.type === 'ident') {
          this.next();
          expr = { kind: 'getattr', obj: expr, name: nt.text, range: this.range(expr.range.start.offset, nt.end) };
        } else if (nt.type === 'number') {
          this.next();
          expr = this.legacyIndex(expr, nt);
        } else if (nt.type === 'star') {
          this.next();
          expr = this.parseLegacySplat(expr, t, nt);
        } else {
          throw this.error(`Invalid attribute name: expected a name after ".", found ${this.describe(nt)}`, nt);
        }
      } else if (t.type === 'lbrack') {
        this.next();
        if (this.withNewlines(false, () => this.peek().type) === 'star') {
          const close = this.withNewlines(false, () => {
            this.next();
            return this.expect('rbrack', '"]" after "[*"');
          });
          const anon: Expr = { kind: 'anon', range: this.range(t.start, close.end) };
          // A full splat consumes every following traversal step, applied to each element.
          const each = this.parseTraversals(anon);
          return {
            kind: 'splat',
            obj: expr,
            each,
            legacy: false,
            range: this.range(expr.range.start.offset, each.range.end.offset),
          };
        }
        expr = this.withNewlines(false, () => {
          const key = this.parseExpression();
          const close = this.expect('rbrack', '"]" to close the index');
          return { kind: 'index', obj: expr, key, range: this.range(expr.range.start.offset, close.end) } as Expr;
        });
      } else {
        return expr;
      }
    }
  }

  /** `obj.0` or `obj.0.1` (the lexer reads `0.1` as one number). */
  private legacyIndex(expr: Expr, num: Token): Expr {
    if (!/^\d+(\.\d+)*$/.test(num.text)) {
      throw this.error(`Invalid legacy index "${num.text}": expected a whole number`, num);
    }
    let offset = num.start;
    for (const digits of num.text.split('.')) {
      const key: LiteralExpr = {
        kind: 'literal',
        value: Number(digits),
        range: this.range(offset, offset + digits.length),
      };
      expr = { kind: 'index', obj: expr, key, range: this.range(expr.range.start.offset, key.range.end.offset) };
      offset += digits.length + 1;
    }
    return expr;
  }

  /** `obj.*.a.b`: only attribute (and legacy numeric) steps apply to each element. */
  private parseLegacySplat(obj: Expr, dot: Token, star: Token): Expr {
    let each: Expr = { kind: 'anon', range: this.range(dot.start, star.end) };
    while (this.peek().type === 'dot') {
      const save = this.pos;
      this.next();
      const nt = this.peek();
      if (nt.type === 'ident') {
        this.next();
        each = { kind: 'getattr', obj: each, name: nt.text, range: this.range(each.range.start.offset, nt.end) };
      } else if (nt.type === 'number') {
        this.next();
        each = this.legacyIndex(each, nt);
      } else {
        this.pos = save;
        break;
      }
    }
    return { kind: 'splat', obj, each, legacy: true, range: this.range(obj.range.start.offset, each.range.end.offset) };
  }

  private isForStart(): boolean {
    const t = this.peek();
    return t.type === 'ident' && t.text === 'for' && this.peekAt(1).type === 'ident';
  }

  private parseTuple(): Expr {
    const open = this.next();
    return this.withNewlines(false, () => {
      if (this.isForStart()) return this.parseFor(open, false);
      const items: Expr[] = [];
      while (this.peek().type !== 'rbrack') {
        items.push(this.parseExpression());
        const t = this.peek();
        if (t.type === 'comma') {
          this.next();
          continue;
        }
        if (t.type !== 'rbrack') {
          throw this.error(`Missing item separator: expected "," or "]", found ${this.describe(t)}`, t);
        }
      }
      const close = this.next();
      return { kind: 'tuple', items, range: this.range(open.start, close.end) };
    });
  }

  private parseObject(): Expr {
    const open = this.next();
    this.skipNewlines();
    if (this.withNewlines(false, () => this.isForStart())) {
      return this.withNewlines(false, () => this.parseFor(open, true));
    }
    return this.withNewlines(true, () => {
      const items: ObjectItem[] = [];
      for (;;) {
        this.skipNewlines();
        if (this.peek().type === 'rbrace') break;
        const key = this.parseObjectKey();
        const sep = this.peek();
        if (sep.type !== 'eq' && sep.type !== 'colon') {
          throw this.error(`Missing key/value separator: expected "=" or ":", found ${this.describe(sep)}`, sep);
        }
        this.next();
        const value = this.parseExpression();
        items.push({ key, value });
        const t = this.peek();
        if (t.type === 'comma') {
          this.next();
        } else if (t.type !== 'newline' && t.type !== 'rbrace') {
          throw this.error(
            `Missing attribute separator: expected a newline or "," after an object item, found ${this.describe(t)}`,
            t,
          );
        }
      }
      const close = this.next();
      return { kind: 'object', items, range: this.range(open.start, close.end) };
    });
  }

  private parseObjectKey(): Expr {
    const t = this.peek();
    const after = this.tokens[this.pos + 1]!;
    const isNamespaceColon = after.type === 'colon' && this.tokens[this.pos + 2]!.type === 'colon';
    if (t.type === 'ident' && (after.type === 'eq' || (after.type === 'colon' && !isNamespaceColon))) {
      this.next();
      return { kind: 'literal', value: t.text, range: this.tokRange(t) };
    }
    return this.parseExpression();
  }

  /** Called with newlines already insignificant and the current token at `for`. */
  private parseFor(open: Token, isObject: boolean): ForExpr {
    this.next(); // 'for'
    const first = this.expectIdent('an iteration variable name after "for"');
    let keyVar: string | undefined;
    let valVar = first.text;
    if (this.peek().type === 'comma') {
      this.next();
      keyVar = first.text;
      valVar = this.expectIdent('a value variable name after ","').text;
    }
    this.expectKeyword('in');
    const coll = this.parseExpression();
    this.expect('colon', '":" after the for collection');
    let keyExpr: Expr | undefined;
    let valExpr: Expr;
    let grouping = false;
    if (isObject) {
      keyExpr = this.parseExpression();
      this.expect('fatArrow', '"=>" in object for expression');
      valExpr = this.parseExpression();
      if (this.peek().type === 'ellipsis') {
        this.next();
        grouping = true;
      }
    } else {
      valExpr = this.parseExpression();
    }
    let cond: Expr | undefined;
    const maybeIf = this.peek();
    if (maybeIf.type === 'ident' && maybeIf.text === 'if') {
      this.next();
      cond = this.parseExpression();
    }
    const close = this.expect(isObject ? 'rbrace' : 'rbrack', isObject ? '"}"' : '"]"');
    const result: ForExpr = {
      kind: 'for',
      valVar,
      coll,
      valExpr,
      grouping,
      isObject,
      range: this.range(open.start, close.end),
    };
    if (keyVar !== undefined) result.keyVar = keyVar;
    if (keyExpr !== undefined) result.keyExpr = keyExpr;
    if (cond !== undefined) result.cond = cond;
    return result;
  }

  // ---------------------------------------------------------------------------------------------
  // Templates

  private parseQuotedTemplate(): TemplateExpr {
    const open = this.tokens[this.pos++]!; // oquote
    const items = this.collectTemplateItems(false);
    const close = this.tokens[this.pos]!;
    if (close.type !== 'cquote') throw this.error('Unterminated template string', open);
    this.pos++;
    return { kind: 'template', parts: this.buildTemplate(items), heredoc: false, range: this.range(open.start, close.end) };
  }

  private parseHeredoc(): TemplateExpr {
    const open = this.tokens[this.pos++]!; // oheredoc
    const items = this.collectTemplateItems(true);
    const close = this.tokens[this.pos]!;
    if (close.type !== 'cheredoc') throw this.error(`Unterminated heredoc "${open.text}"`, open);
    this.pos++;
    if (open.flush) flushHeredoc(items);
    return { kind: 'template', parts: this.buildTemplate(items), heredoc: true, range: this.range(open.start, close.end) };
  }

  /**
   * Reads literal, interpolation and directive tokens up to the closing quote or heredoc marker.
   * Strip markers are applied here, token by token, exactly as hclsyntax does.
   */
  private collectTemplateItems(heredoc: boolean): TemplateItem[] {
    const items: TemplateItem[] = [];
    let trimNext = false;
    for (;;) {
      const t = this.tokens[this.pos]!;
      if (t.type === 'quotedLit' || t.type === 'stringLit') {
        this.pos++;
        let v = this.decodeLiteral(t, heredoc);
        if (trimNext) {
          v = v.replace(/^\s+/, '');
          trimNext = false;
        }
        items.push({ k: 'lit', v });
        continue;
      }
      if (t.type === 'templateInterp' || t.type === 'templateControl') {
        if (t.strip) {
          const prev = items[items.length - 1];
          if (prev?.k === 'lit') prev.v = prev.v.replace(/\s+$/, '');
        }
        this.pos++;
        const { item, end } = this.withNewlines(false, () => {
          const item = t.type === 'templateInterp' ? ({ k: 'interp', expr: this.parseExpression() } as TemplateItem) : this.parseDirective(t);
          const end = this.peek();
          if (end.type !== 'templateSeqEnd') {
            throw this.error(`Expected "}" to close the template sequence, found ${this.describe(end)}`, end);
          }
          this.next();
          return { item, end };
        });
        items.push(item);
        trimNext = end.strip === true;
        continue;
      }
      return items;
    }
  }

  private parseDirective(open: Token): TemplateItem {
    const kw = this.peek();
    if (kw.type !== 'ident') throw this.error('Expected a template directive keyword (if, else, endif, for, endfor)', kw);
    this.next();
    const directiveRange = (): Range => this.range(open.start, this.peek().end);
    switch (kw.text) {
      case 'if': {
        const cond = this.parseExpression();
        return { k: 'if', cond, range: directiveRange() };
      }
      case 'else':
        return { k: 'else', range: directiveRange() };
      case 'endif':
        return { k: 'endif', range: directiveRange() };
      case 'for': {
        const first = this.expectIdent('an iteration variable name after "for"');
        let keyVar: string | undefined;
        let valVar = first.text;
        if (this.peek().type === 'comma') {
          this.next();
          keyVar = first.text;
          valVar = this.expectIdent('a value variable name after ","').text;
        }
        this.expectKeyword('in');
        const coll = this.parseExpression();
        const item: Extract<TemplateItem, { k: 'for' }> = { k: 'for', valVar, coll, range: directiveRange() };
        if (keyVar !== undefined) item.keyVar = keyVar;
        return item;
      }
      case 'endfor':
        return { k: 'endfor', range: directiveRange() };
      default:
        throw this.error(`Invalid template directive "${kw.text}": expected if, else, endif, for or endfor`, kw);
    }
  }

  /** Nests if/for directives and normalises the text parts. */
  private buildTemplate(items: TemplateItem[]): TemplatePart[] {
    let i = 0;
    const seq = (stop: ReadonlySet<string>): TemplatePart[] => {
      const parts: TemplatePart[] = [];
      while (i < items.length) {
        const it = items[i]!;
        if (stop.has(it.k)) return parts;
        i++;
        switch (it.k) {
          case 'lit':
            parts.push({ kind: 'text', value: it.v });
            break;
          case 'interp':
            parts.push({ kind: 'interp', expr: it.expr });
            break;
          case 'if': {
            const then = seq(new Set(['else', 'endif']));
            let otherwise: TemplatePart[] = [];
            if (items[i]?.k === 'else') {
              i++;
              otherwise = seq(new Set(['endif']));
            }
            if (items[i]?.k !== 'endif') throw new ParseError('Missing %{ endif } for this %{ if }', it.range);
            i++;
            parts.push({ kind: 'if', cond: it.cond, then, else: otherwise });
            break;
          }
          case 'for': {
            const body = seq(new Set(['endfor']));
            if (items[i]?.k !== 'endfor') throw new ParseError('Missing %{ endfor } for this %{ for }', it.range);
            i++;
            const part: Extract<TemplatePart, { kind: 'for' }> = { kind: 'for', valVar: it.valVar, coll: it.coll, body };
            if (it.keyVar !== undefined) part.keyVar = it.keyVar;
            parts.push(part);
            break;
          }
          default: {
            const opener = it.k === 'else' || it.k === 'endif' ? 'if' : 'for';
            throw new ParseError(`Unexpected %{ ${it.k} }: no matching %{ ${opener} } is open`, it.range);
          }
        }
      }
      return parts;
    };
    const parts = normalizeParts(seq(new Set()));
    // An empty string or heredoc is still a template with one (empty) text part.
    return parts.length === 0 ? [{ kind: 'text', value: '' }] : parts;
  }

  /** Decodes a literal token's escapes; invalid escapes are reported and kept verbatim. */
  private decodeLiteral(t: Token, heredoc: boolean): string {
    const raw = t.text;
    let out = '';
    let i = 0;
    while (i < raw.length) {
      const c = raw[i]!;
      if ((c === '$' || c === '%') && raw[i + 1] === c && raw[i + 2] === '{') {
        out += c + '{';
        i += 3;
        continue;
      }
      if (c !== '\\' || heredoc) {
        out += c;
        i++;
        continue;
      }
      const e = raw[i + 1];
      const simple: Record<string, string> = { n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\' };
      if (e !== undefined && simple[e] !== undefined) {
        out += simple[e];
        i += 2;
        continue;
      }
      if (e === 'u' || e === 'U') {
        const len = e === 'u' ? 4 : 8;
        const hex = raw.slice(i + 2, i + 2 + len);
        const cp = /^[0-9a-fA-F]+$/.test(hex) && hex.length === len ? parseInt(hex, 16) : NaN;
        if (!Number.isNaN(cp) && cp <= 0x10ffff) {
          out += String.fromCodePoint(cp);
          i += 2 + len;
          continue;
        }
        this.diags.push({
          message: `Invalid escape sequence: \\${e} must be followed by ${len} hexadecimal digits of a valid code point`,
          range: this.range(t.start + i, t.start + Math.min(raw.length, i + 2 + len)),
        });
        out += raw.slice(i, i + 2);
        i += 2;
        continue;
      }
      this.diags.push({
        message: `Invalid escape sequence "\\${e ?? ''}": only \\n, \\r, \\t, \\", \\\\, \\uXXXX and \\UXXXXXXXX are allowed`,
        range: this.range(t.start + i, t.start + Math.min(raw.length, i + 2)),
      });
      out += raw.slice(i, i + 2);
      i += 2;
    }
    return out;
  }
}

/** Merges adjacent text parts and drops empty ones, recursively. */
function normalizeParts(parts: TemplatePart[]): TemplatePart[] {
  const out: TemplatePart[] = [];
  for (const p of parts) {
    if (p.kind === 'text') {
      if (p.value === '') continue;
      const last = out[out.length - 1];
      if (last?.kind === 'text') last.value += p.value;
      else out.push({ kind: 'text', value: p.value });
    } else if (p.kind === 'if') {
      out.push({ ...p, then: normalizeParts(p.then), else: normalizeParts(p.else) });
    } else if (p.kind === 'for') {
      out.push({ ...p, body: normalizeParts(p.body) });
    } else {
      out.push(p);
    }
  }
  return out;
}

/**
 * `<<-` heredocs: remove the smallest common leading whitespace from each line. Mirrors hclsyntax's
 * flushHeredocTemplateParts: whitespace-only lines are ignored for counting and left as they are,
 * and a line that starts with an interpolation or directive counts as zero indentation.
 */
function flushHeredoc(items: TemplateItem[]): void {
  let minSpaces = Infinity;
  let newline = true;
  const adjust: Array<{ k: 'lit'; v: string }> = [];
  for (const it of items) {
    if (newline) {
      newline = false;
      if (it.k === 'lit') {
        const trimmed = it.v.replace(/^\s+/, '');
        if (trimmed.length === 0 && it.v.endsWith('\n')) {
          // blank line: not counted
        } else {
          minSpaces = Math.min(minSpaces, [...it.v.slice(0, it.v.length - trimmed.length)].length);
          adjust.push(it);
        }
      } else {
        minSpaces = 0;
      }
    }
    if (it.k === 'lit' && it.v.endsWith('\n')) newline = true;
  }
  if (!Number.isFinite(minSpaces) || minSpaces === 0) return;
  for (const it of adjust) {
    it.v = [...it.v].slice(minSpaces).join('');
  }
}

/**
 * Parses HCL native syntax source. Never throws: syntax errors are returned as diagnostics alongside
 * a best-effort body containing everything that could be parsed.
 *
 * `filename` is accepted for API symmetry with other HCL tools; the AST ranges carry no file name, so
 * callers attach it to diagnostics themselves.
 */
export function parseHcl(src: string, filename?: string): ParseResult {
  void filename;
  try {
    return new Parser(src).parseFile();
  } catch (e) {
    const zero: Pos = { offset: 0, line: 1, col: 1 };
    const range: Range = { start: zero, end: zero };
    return {
      body: { attributes: [], blocks: [], range },
      diagnostics: [{ message: `Internal parser error: ${String(e)}`, range }],
    };
  }
}
