import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { gunzipSync } from 'node:zlib';

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
  const assets = fs.readdirSync(out).filter((f) => /\.wasm-[^.]+\.gz$/.test(f));
  expect(assets.length).toBe(8);
  for (const asset of assets) {
    expect(gunzipSync(fs.readFileSync(path.join(out, asset))).subarray(0, 4).toString()).toBe("\0asm");
    expect(fs.readFileSync(path.join(root, 'dist', asset)).equals(fs.readFileSync(path.join(out, asset)))).toBe(true);
  }
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

test('dist/cli.js bundles the offline key list and verifies without dependencies or network', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-cli-dist-'));
  try {
    const built = spawnSync('bun', ['build', 'src/cli.ts', '--target=node', '--minify-syntax', '--minify-whitespace', '--outdir', out], { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' });
    expect(built.status).toBe(0);
    expect(fs.readFileSync(path.join(out, 'cli.js')).equals(fs.readFileSync(path.resolve(import.meta.dirname, '../dist/cli.js')))).toBe(true);
    const pack = path.join(out, 'pack'); fs.mkdirSync(pack);
    const metadata = '{"schema":"terratrust.evidence-pack/v1","since":"2026-10-01","until":"2027-01-01"}\n';
    fs.writeFileSync(path.join(pack, 'pack.json'), metadata);
    const { createHash } = require('node:crypto');
    fs.writeFileSync(path.join(pack, 'MANIFEST.sha256'), `${createHash('sha256').update(metadata).digest('hex')}  pack.json\n`);
    const r = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw new Error("network forbidden")}', path.join(out, 'cli.js'), 'verify', pack, '--allow-unsigned', '--json'], { cwd: out, encoding: 'utf8' });
    expect(r.status).toBe(0); expect(JSON.parse(r.stdout)).toMatchObject({ ok: true, failures: [], files: 1 });
    expect(r.stderr).toContain('Keys: bundled with this version'); expect(r.stderr).not.toContain('network forbidden');
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});
