/*
 * Which assignments a use can see. Resolving `bucket` to the last `bucket = ...` above it in the file
 * is wrong when that assignment sits in another function, or when a function between them takes
 * `bucket` as a parameter. These helpers keep the lookup inside the scopes that enclose the use.
 */

/** Braces, parens and quotes only count in code: comments and string contents are blanked, offsets kept. */
function braceCode(src: string): string {
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
      while (j < src.length && src[j] !== c) j += src[j] === '\\' && c !== '`' ? 2 : 1;
      out += c + src.slice(i + 1, j).replace(/[^\n]/g, ' ') + (j < src.length ? c : '');
      i = j;
    } else out += c;
  }
  return out;
}

let cached: { src?: string; code: string } = { code: '' };

/** Offsets of the `{` of every block that encloses `pos`, outermost first. */
function openBlocks(code: string, pos: number): number[] {
  const stack: number[] = [];
  for (let i = 0; i < pos && i < code.length; i++) {
    if (code[i] === '{') stack.push(i);
    else if (code[i] === '}') stack.pop();
  }
  return stack;
}

const NOT_A_FUNCTION = /^\s*(?:\}\s*)?(?:if|else|while|switch|return|do|try)\b/;

/** Names a block declares in the parentheses before its `{`: function parameters, `for`/`catch` bindings. */
function blockParams(code: string, brace: number): string[] {
  const start = Math.max(code.lastIndexOf(';', brace - 1), code.lastIndexOf('{', brace - 1), code.lastIndexOf('}', brace - 1)) + 1;
  const header = code.slice(start, brace);
  if (NOT_A_FUNCTION.test(header)) return [];
  const names: string[] = [];
  let depth = 0;
  let group = '';
  for (const c of header) {
    if (c === '(') {
      if (depth++ === 0) {
        group = '';
        continue;
      }
    } else if (c === ')') {
      if (--depth === 0) {
        for (const piece of group.split(',')) {
          const m = piece.match(/^[\s.{[]*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)/);
          if (m) names.push(m[1]);
        }
        continue;
      }
    }
    if (depth > 0) group += c;
  }
  return names;
}

/**
 * Whether an assignment to `name` at offset `at` is the binding seen at offset `use` in a brace
 * language (Go, TypeScript): every block enclosing the assignment also encloses the use, and no block
 * in between declares `name` as a parameter.
 */
export function visibleInBlocks(src: string, at: number, use: number, name: string): boolean {
  // Lookups come in runs over one file: mask it once.
  if (cached.src !== src) cached = { src, code: braceCode(src) };
  const code = cached.code;
  const outer = openBlocks(code, at);
  const inner = openBlocks(code, use);
  if (outer.length > inner.length || outer.some((b, i) => inner[i] !== b)) return false;
  return !inner.slice(outer.length).some((b) => blockParams(code, b).includes(name));
}

interface PyDef {
  line: number;
  params: string[];
}

/** The `def`s enclosing the line at `pos`, outermost first, found by indentation. */
function pyDefs(src: string, pos: number): PyDef[] {
  const end = src.indexOf('\n', pos);
  const lines = src.slice(0, end < 0 ? src.length : end).split('\n');
  const indentOf = (l: string) => l.match(/^\s*/)![0].length;
  let indent = indentOf(lines[lines.length - 1]);
  const defs: PyDef[] = [];
  for (let n = lines.length - 2; n >= 0; n--) {
    const l = lines[n];
    if (!l.trim() || l.trim().startsWith('#')) continue;
    const i = indentOf(l);
    if (i >= indent) continue;
    indent = i;
    const def = l.match(/^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/);
    if (def) {
      const params = def[1].split(',').map((p) => p.trim().replace(/^\*+/, '').match(/^([A-Za-z_]\w*)/)?.[1]).filter((p): p is string => Boolean(p));
      defs.unshift({ line: n, params });
    }
    if (indent === 0) break;
  }
  return defs;
}

/** Python: an assignment is seen at the use when its enclosing defs also enclose the use, unshadowed by a parameter. */
export function visibleInPython(src: string, at: number, use: number, name: string): boolean {
  const outer = pyDefs(src, at);
  const inner = pyDefs(src, use);
  if (outer.length > inner.length || outer.some((d, i) => inner[i].line !== d.line)) return false;
  return !inner.slice(outer.length).some((d) => d.params.includes(name));
}
