import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// The Action runs the committed bundle, so it must match the source. Run `bun run build` after changes.
test('dist/action.js is built from the current source', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-dist-'));
  const root = path.resolve(import.meta.dirname, '..');
  const r = spawnSync('bun', ['build', 'src/action.ts', '--target=node', '--minify-syntax', '--minify-whitespace', '--outdir', out], { cwd: root, encoding: 'utf8' });
  expect(r.status).toBe(0);
  const fresh = fs.readFileSync(path.join(out, 'action.js'), 'utf8');
  const committed = fs.readFileSync(path.join(root, 'dist', 'action.js'), 'utf8');
  fs.rmSync(out, { recursive: true, force: true });
  expect(committed === fresh).toBe(true);
}, 30_000);
