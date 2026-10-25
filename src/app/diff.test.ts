import { expect, test } from 'bun:test';
import { parseAddedLines } from './diff.js';

test('parseAddedLines reads -U0 hunks, including single-line and pure-deletion hunks', () => {
  const patch = [
    'diff --git a/x.go b/x.go',
    '--- a/x.go',
    '+++ b/x.go',
    '@@ -3,0 +4,2 @@ func a() {',
    '+one',
    '+two',
    '@@ -10 +12 @@',
    '-old',
    '+new',
    '@@ -20,2 +21,0 @@',
    '-gone',
    '-gone',
    'diff --git a/y.go b/y.go',
    '--- a/y.go',
    '+++ /dev/null',
  ].join('\n');
  expect([...parseAddedLines(patch).get('x.go')!]).toEqual([4, 5, 12]);
  expect(parseAddedLines(patch).has('y.go')).toBe(false);
});

test('parseAddedLines reads C-quoted paths', () => {
  const patch = ['+++ "b/caf\\303\\251.go"', '@@ -0,0 +1,2 @@', '+a', '+b'].join('\n');
  expect([...parseAddedLines(patch).get('café.go')!]).toEqual([1, 2]);
});
