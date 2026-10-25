/**
 * Tokenizer for the HCL native syntax.
 *
 * The lexer is mode-aware the same way HashiCorp's scanner is: it tracks a stack of contexts
 * (plain braces, template interpolations, quoted templates, heredocs) so a `}` inside a string is
 * literal text, a `}` that closes `${` becomes a templateSeqEnd, and a `{` in an expression opens a
 * brace. The parser therefore receives a flat, already-disambiguated token stream.
 *
 * Comments are dropped. A line comment stops before its newline, so the newline is still emitted
 * and keeps terminating attributes.
 */

export type TokenType =
  | 'ident'
  | 'number'
  | 'newline'
  | 'eof'
  | 'invalid'
  | 'lbrace'
  | 'rbrace'
  | 'lbrack'
  | 'rbrack'
  | 'lparen'
  | 'rparen'
  | 'comma'
  | 'dot'
  | 'ellipsis'
  | 'eq'
  | 'colon'
  | 'question'
  | 'fatArrow'
  | 'plus'
  | 'minus'
  | 'star'
  | 'slash'
  | 'percent'
  | 'bang'
  | 'eqeq'
  | 'neq'
  | 'lt'
  | 'gt'
  | 'lte'
  | 'gte'
  | 'and'
  | 'or'
  /** `"` opening a quoted template. */
  | 'oquote'
  /** `"` closing a quoted template (zero-width when the string is unterminated). */
  | 'cquote'
  /** Raw literal text inside a quoted template, escapes not yet decoded. */
  | 'quotedLit'
  /** `<<EOT` or `<<-EOT`; `text` is the delimiter, `flush` is set for `<<-`. */
  | 'oheredoc'
  /** The closing heredoc delimiter (zero-width when the heredoc is unterminated). */
  | 'cheredoc'
  /** Raw literal text inside a heredoc. Never spans more than one line; includes the trailing newline. */
  | 'stringLit'
  /** `${` or `${~` */
  | 'templateInterp'
  /** `%{` or `%{~` */
  | 'templateControl'
  /** `}` or `~}` closing an interpolation or directive. */
  | 'templateSeqEnd';

export interface Token {
  type: TokenType;
  /** 0-based start offset (inclusive). */
  start: number;
  /** 0-based end offset (exclusive). */
  end: number;
  /** Source text of the token. For `oheredoc` this is the delimiter identifier. */
  text: string;
  /** Strip marker: `${~`, `%{~` (strip left) or `~}` (strip right). */
  strip?: boolean;
  /** `<<-` indented heredoc. */
  flush?: boolean;
}

export interface LexDiagnostic {
  message: string;
  start: number;
  end: number;
}

export interface LexResult {
  tokens: Token[];
  diagnostics: LexDiagnostic[];
}

type Context =
  | { kind: 'brace' }
  | { kind: 'interp' }
  | { kind: 'quoted'; start: number }
  | { kind: 'heredoc'; delim: string; lineStart: boolean; start: number };

const IDENT_RE = /[\p{ID_Start}_][\p{ID_Continue}\-]*/uy;
const HEREDOC_RE = /<<(-?)([\p{ID_Start}_][\p{ID_Continue}\-]*)\r?\n/uy;
const ID_START_RE = /[\p{ID_Start}_]/u;

const SINGLE: Record<string, TokenType> = {
  '[': 'lbrack',
  ']': 'rbrack',
  '(': 'lparen',
  ')': 'rparen',
  ',': 'comma',
  '?': 'question',
  ':': 'colon',
  '+': 'plus',
  '-': 'minus',
  '*': 'star',
  '/': 'slash',
  '%': 'percent',
};

const DOUBLE: Record<string, TokenType> = {
  '==': 'eqeq',
  '!=': 'neq',
  '<=': 'lte',
  '>=': 'gte',
  '&&': 'and',
  '||': 'or',
  '=>': 'fatArrow',
};

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

export function lex(src: string): LexResult {
  const tokens: Token[] = [];
  const diagnostics: LexDiagnostic[] = [];
  const stack: Context[] = [];
  const n = src.length;
  let i = src.charCodeAt(0) === 0xfeff ? 1 : 0;

  const emit = (type: TokenType, start: number, end: number, extra?: Partial<Token>): void => {
    tokens.push({ type, start, end, text: src.slice(start, end), ...extra });
  };

  /** Emits `${`/`%{` (with optional `~`) at `i` and enters an interpolation context. */
  const openSequence = (): void => {
    const type: TokenType = src[i] === '$' ? 'templateInterp' : 'templateControl';
    const strip = src[i + 2] === '~';
    const end = i + (strip ? 3 : 2);
    emit(type, i, end, { strip });
    i = end;
    stack.push({ kind: 'interp' });
  };

  /** `$${` and `%%{` are escapes for literal `${` and `%{`. */
  const isEscapedSequence = (at: number): boolean =>
    (src[at] === '$' || src[at] === '%') && src[at + 1] === src[at] && src[at + 2] === '{';
  const isSequenceStart = (at: number): boolean =>
    (src[at] === '$' || src[at] === '%') && src[at + 1] === '{';

  for (;;) {
    const top = stack[stack.length - 1];

    if (top?.kind === 'quoted') {
      const start = i;
      while (i < n) {
        const c = src[i];
        if (c === '"' || c === '\n' || (c === '\r' && src[i + 1] === '\n')) break;
        if (c === '\\') {
          // An escape never swallows a line break: that is an unterminated string instead.
          i += src[i + 1] === '\n' || src[i + 1] === '\r' || i + 1 >= n ? 1 : 2;
          continue;
        }
        if (isEscapedSequence(i)) {
          i += 3;
          continue;
        }
        if (isSequenceStart(i)) break;
        i++;
      }
      if (i > start) emit('quotedLit', start, i);
      if (i >= n || src[i] === '\n' || src[i] === '\r') {
        diagnostics.push({
          message: 'Unterminated template string: a quoted string must be closed on the line it starts',
          start: top.start,
          end: i,
        });
        emit('cquote', i, i);
        stack.pop();
      } else if (src[i] === '"') {
        emit('cquote', i, i + 1);
        i++;
        stack.pop();
      } else {
        openSequence();
      }
      continue;
    }

    if (top?.kind === 'heredoc') {
      if (top.lineStart) {
        let j = i;
        while (src[j] === ' ' || src[j] === '\t') j++;
        if (src.startsWith(top.delim, j)) {
          let k = j + top.delim.length;
          while (src[k] === ' ' || src[k] === '\t') k++;
          if (k >= n || src[k] === '\n' || (src[k] === '\r' && src[k + 1] === '\n')) {
            emit('cheredoc', j, j + top.delim.length);
            i = j + top.delim.length;
            stack.pop();
            continue;
          }
        }
      }
      if (i >= n) {
        diagnostics.push({
          message: `Unterminated heredoc: missing closing delimiter "${top.delim}"`,
          start: top.start,
          end: n,
        });
        emit('cheredoc', n, n);
        stack.pop();
        continue;
      }
      const start = i;
      top.lineStart = false;
      while (i < n) {
        const c = src[i];
        if (c === '\n') {
          i++;
          top.lineStart = true;
          break;
        }
        if (isEscapedSequence(i)) {
          i += 3;
          continue;
        }
        if (isSequenceStart(i)) break;
        i++;
      }
      if (i > start) emit('stringLit', start, i);
      if (!top.lineStart && i < n) openSequence();
      continue;
    }

    if (i >= n) break;
    const c = src[i]!;

    if (c === ' ' || c === '\t' || c === '\f' || c === '\v') {
      i++;
      continue;
    }
    if (c === '\n') {
      emit('newline', i, i + 1);
      i++;
      continue;
    }
    if (c === '\r') {
      if (src[i + 1] === '\n') {
        emit('newline', i, i + 2);
        i += 2;
      } else {
        i++;
      }
      continue;
    }
    if (c === '#' || (c === '/' && src[i + 1] === '/')) {
      while (i < n && src[i] !== '\n' && !(src[i] === '\r' && src[i + 1] === '\n')) i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const close = src.indexOf('*/', i + 2);
      if (close < 0) {
        diagnostics.push({ message: 'Unterminated block comment', start: i, end: n });
        i = n;
      } else {
        i = close + 2;
      }
      continue;
    }
    if (c === '"') {
      emit('oquote', i, i + 1);
      stack.push({ kind: 'quoted', start: i });
      i++;
      continue;
    }
    if (c === '<' && src[i + 1] === '<') {
      HEREDOC_RE.lastIndex = i;
      const m = HEREDOC_RE.exec(src);
      if (m) {
        const flush = m[1] === '-';
        const delim = m[2]!;
        const tokEnd = i + 2 + (flush ? 1 : 0) + delim.length;
        tokens.push({ type: 'oheredoc', start: i, end: tokEnd, text: delim, flush });
        stack.push({ kind: 'heredoc', delim, lineStart: true, start: i });
        i += m[0].length;
        continue;
      }
    }
    if (isDigit(c)) {
      const start = i;
      while (isDigit(src[i])) i++;
      if (src[i] === '.' && isDigit(src[i + 1])) {
        i++;
        while (isDigit(src[i])) i++;
      }
      if (
        (src[i] === 'e' || src[i] === 'E') &&
        (isDigit(src[i + 1]) || ((src[i + 1] === '+' || src[i + 1] === '-') && isDigit(src[i + 2])))
      ) {
        i += 2;
        while (isDigit(src[i])) i++;
      }
      emit('number', start, i);
      continue;
    }
    if (ID_START_RE.test(c) || (c >= '\ud800' && c <= '\udbff')) {
      IDENT_RE.lastIndex = i;
      const m = IDENT_RE.exec(src);
      if (m) {
        emit('ident', i, i + m[0].length);
        i += m[0].length;
        continue;
      }
    }
    if (c === '{') {
      emit('lbrace', i, i + 1);
      stack.push({ kind: 'brace' });
      i++;
      continue;
    }
    if (c === '}') {
      if (top?.kind === 'interp') {
        emit('templateSeqEnd', i, i + 1, { strip: false });
        stack.pop();
      } else {
        emit('rbrace', i, i + 1);
        if (top?.kind === 'brace') stack.pop();
      }
      i++;
      continue;
    }
    if (c === '~' && src[i + 1] === '}' && top?.kind === 'interp') {
      emit('templateSeqEnd', i, i + 2, { strip: true });
      stack.pop();
      i += 2;
      continue;
    }
    if (c === '.') {
      if (src[i + 1] === '.' && src[i + 2] === '.') {
        emit('ellipsis', i, i + 3);
        i += 3;
      } else {
        emit('dot', i, i + 1);
        i++;
      }
      continue;
    }
    const two = src.slice(i, i + 2);
    const double = DOUBLE[two];
    if (double) {
      emit(double, i, i + 2);
      i += 2;
      continue;
    }
    if (c === '=') {
      emit('eq', i, i + 1);
      i++;
      continue;
    }
    if (c === '!') {
      emit('bang', i, i + 1);
      i++;
      continue;
    }
    if (c === '<') {
      emit('lt', i, i + 1);
      i++;
      continue;
    }
    if (c === '>') {
      emit('gt', i, i + 1);
      i++;
      continue;
    }
    const single = SINGLE[c];
    if (single) {
      emit(single, i, i + 1);
      i++;
      continue;
    }
    // Unknown character: one code point.
    const cp = src.codePointAt(i)!;
    const width = cp > 0xffff ? 2 : 1;
    emit('invalid', i, i + width);
    i += width;
  }

  emit('eof', n, n);
  return { tokens, diagnostics };
}
