import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// The Action runs the committed bundle, so it must match the source. Run `bun run build` after changes.
test('dist/action.js is built from the current source', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-dist-'));
  const root = path.resolve(import.meta.dirname, '..');
  const r = spawnSync(
    'bun',
    ['build', 'src/action.ts', '--target=node', '--minify-syntax', '--minify-whitespace', '--outdir', out],
    { cwd: root, encoding: 'utf8' },
  );
  expect(r.status).toBe(0);
  const fresh = fs.readFileSync(path.join(out, 'action.js'), 'utf8');
  const committed = fs.readFileSync(path.join(root, 'dist', 'action.js'), 'utf8');
  expect(committed === fresh).toBe(true);
  // Bun's file loader emits hash-named WASMs next to the JavaScript entry point.
  const assets = fs.readdirSync(out).filter((f) => f.endsWith('.wasm'));
  expect(assets.length).toBe(8);
  for (const asset of assets)
    expect(fs.readFileSync(path.join(root, 'dist', asset)).equals(fs.readFileSync(path.join(out, asset)))).toBe(true);
  // This directory has no node_modules. Disable network access before loading the Action.
  fs.writeFileSync(path.join(out, 'plan.json'), JSON.stringify({ format_version: '1.2', resource_changes: [] }));
  const isolated = spawnSync(
    'node',
    [
      '--import',
      'data:text/javascript,globalThis.fetch=()=>{throw new Error("network forbidden")}',
      path.join(out, 'action.js'),
    ],
    {
      cwd: out,
      encoding: 'utf8',
      env: {
        ...process.env,
        INPUT_MODE: 'plan',
        'INPUT_PLAN-JSON': 'plan.json',
        INPUT_COMMENT: 'false',
        GITHUB_WORKSPACE: out,
        GITHUB_OUTPUT: path.join(out, 'outputs'),
        GITHUB_STEP_SUMMARY: path.join(out, 'summary'),
      },
    },
  );
  expect(isolated.stderr).not.toContain('network forbidden');
  expect(isolated.status).toBe(0);
  expect(fs.readFileSync(path.join(out, 'outputs'), 'utf8')).toContain('gate=pass');
  fs.rmSync(out, { recursive: true, force: true });
}, 30_000);
