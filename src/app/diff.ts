import type { AddedLines } from './facts.js';

/** Added line numbers per file from a `git diff -U0` patch. */
export function parseAddedLines(patch: string): AddedLines {
  const out: AddedLines = new Map();
  let file: string | undefined;
  for (const line of patch.split('\n')) {
    if (line.startsWith('+++ ')) {
      let p = line.slice(4).replace(/\t$/, '');
      // Paths with special characters are C-quoted: +++ "b/caf\303\251.go"
      if (p.startsWith('"') && p.endsWith('"')) p = unquoteC(p.slice(1, -1));
      file = p === '/dev/null' ? undefined : p.replace(/^b\//, '');
      continue;
    }
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (hunk && file) {
      const start = Number(hunk[1]);
      const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
      const set = out.get(file) ?? new Set<number>();
      for (let i = 0; i < count; i++) set.add(start + i);
      out.set(file, set);
    }
  }
  return out;
}

function unquoteC(s: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '\\') {
      bytes.push(...Buffer.from(s[i], 'utf8'));
      continue;
    }
    const n = s[++i];
    if (/[0-7]/.test(n)) {
      bytes.push(parseInt(s.slice(i, i + 3), 8));
      i += 2;
    } else bytes.push(({ n: 10, t: 9, '"': 34, '\\': 92 } as Record<string, number>)[n] ?? n.charCodeAt(0));
  }
  return Buffer.from(bytes).toString('utf8');
}
