/**
 * AST for the HCL native syntax (https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md).
 * Every node carries a source range so findings can point at file:line and patches can edit in place.
 */

export interface Pos {
  /** 0-based byte offset into the source string (UTF-16 code unit index, as JS strings index). */
  offset: number;
  /** 1-based line. */
  line: number;
  /** 1-based column. */
  col: number;
}

export interface Range {
  start: Pos;
  end: Pos;
}

export interface Body {
  attributes: Attribute[];
  blocks: Block[];
  range: Range;
}

export interface Attribute {
  name: string;
  expr: Expr;
  range: Range;
}

export interface Block {
  type: string;
  /** Labels in order, unquoted. `resource "aws_s3_bucket" "b"` -> ["aws_s3_bucket", "b"]. */
  labels: string[];
  body: Body;
  range: Range;
}

export type Expr =
  | LiteralExpr
  | TemplateExpr
  | TupleExpr
  | ObjectExpr
  | ScopeExpr
  | GetAttrExpr
  | IndexExpr
  | SplatExpr
  | CallExpr
  | ForExpr
  | UnaryExpr
  | BinaryExpr
  | ConditionalExpr
  | ParenExpr
  | AnonSplatItemExpr;

interface Node {
  range: Range;
}

export interface LiteralExpr extends Node {
  kind: 'literal';
  /** Numbers are parsed as JS numbers. */
  value: string | number | boolean | null;
}

/** A quoted string or heredoc. A string with no interpolation is still a template with one string part. */
export interface TemplateExpr extends Node {
  kind: 'template';
  parts: TemplatePart[];
  /** True for `<<EOT` / `<<-EOT`. */
  heredoc: boolean;
}

export type TemplatePart =
  | { kind: 'text'; value: string }
  | { kind: 'interp'; expr: Expr }
  | { kind: 'if'; cond: Expr; then: TemplatePart[]; else: TemplatePart[] }
  | { kind: 'for'; keyVar?: string; valVar: string; coll: Expr; body: TemplatePart[] };

export interface TupleExpr extends Node {
  kind: 'tuple';
  items: Expr[];
}

export interface ObjectItem {
  /**
   * A bare identifier key (`name = 1`) is a literal string key, as in Terraform.
   * A quoted key is a template. A parenthesized key `(var.k) = 1` is a ParenExpr.
   */
  key: Expr;
  value: Expr;
}

export interface ObjectExpr extends Node {
  kind: 'object';
  items: ObjectItem[];
}

/** A root variable reference: `var`, `local`, `aws_s3_bucket`, `each`, `count`, `path`, a for-loop variable... */
export interface ScopeExpr extends Node {
  kind: 'scope';
  name: string;
}

export interface GetAttrExpr extends Node {
  kind: 'getattr';
  obj: Expr;
  name: string;
}

/** `obj[key]`, and also the legacy `obj.0` numeric attribute form (key is a number literal). */
export interface IndexExpr extends Node {
  kind: 'index';
  obj: Expr;
  key: Expr;
}

/**
 * `obj[*].a.b` or `obj.*.a.b`. `each` is the traversal applied to every element, written relative to an
 * AnonSplatItemExpr placeholder: `x[*].id` -> { obj: x, each: getattr(anon, "id") }.
 */
export interface SplatExpr extends Node {
  kind: 'splat';
  obj: Expr;
  each: Expr;
  /** True for the legacy attribute-only `.*` form. */
  legacy: boolean;
}

/** Placeholder for the current element inside SplatExpr.each. */
export interface AnonSplatItemExpr extends Node {
  kind: 'anon';
}

export interface CallExpr extends Node {
  kind: 'call';
  /** Function name, including any namespace: `provider::aws::arn_parse`. */
  name: string;
  args: Expr[];
  /** True when the final argument is followed by `...`. */
  expandFinal: boolean;
}

export interface ForExpr extends Node {
  kind: 'for';
  keyVar?: string;
  valVar: string;
  coll: Expr;
  /** Present for object-producing `{for ...}` expressions. */
  keyExpr?: Expr;
  valExpr: Expr;
  cond?: Expr;
  /** `...` after the value in an object for expression. */
  grouping: boolean;
  isObject: boolean;
}

export interface UnaryExpr extends Node {
  kind: 'unary';
  op: '!' | '-';
  operand: Expr;
}

export type BinaryOp = '*' | '/' | '%' | '+' | '-' | '<' | '>' | '<=' | '>=' | '==' | '!=' | '&&' | '||';

export interface BinaryExpr extends Node {
  kind: 'binary';
  op: BinaryOp;
  left: Expr;
  right: Expr;
}

export interface ConditionalExpr extends Node {
  kind: 'conditional';
  cond: Expr;
  then: Expr;
  else: Expr;
}

export interface ParenExpr extends Node {
  kind: 'paren';
  expr: Expr;
}

export interface ParseDiagnostic {
  message: string;
  range: Range;
}

export interface ParseResult {
  body: Body;
  /** Empty on success. The parser recovers where it can and still returns a partial body. */
  diagnostics: ParseDiagnostic[];
}
