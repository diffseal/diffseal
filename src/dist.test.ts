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
  // The bundle is one file: no parser assets are emitted or committed next to it.
  expect(fs.readdirSync(out)).toEqual(['action.js']);
  expect(fs.readdirSync(path.join(root, 'dist')).sort()).toEqual(['action.js', 'cli.js', 'mcp.js']);
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
    expect(fs.readFileSync(path.join(out, 'cli.js'), 'utf8').startsWith('#!/usr/bin/env node\n')).toBe(true);
    const { version } = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    for (const flag of ['--version', '-v']) {
      const result = spawnSync('node', [path.join(out, 'cli.js'), flag], { cwd: out, encoding: 'utf8' });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(version);
    }
    const help = spawnSync('node', [path.join(out, 'cli.js'), 'verify', '--help'], { cwd: out, encoding: 'utf8' });
    expect(help.status).toBe(0);
    expect(help.stdout).toContain('diffseal verify <folder>');
    const pack = path.join(out, 'pack'); fs.mkdirSync(pack);
    const metadata = '{"schema":"diffseal.evidence-pack/v1","since":"2026-10-01","until":"2027-01-01"}\n';
    fs.writeFileSync(path.join(pack, 'pack.json'), metadata);
    const { createHash } = require('node:crypto');
    fs.writeFileSync(path.join(pack, 'MANIFEST.sha256'), `${createHash('sha256').update(metadata).digest('hex')}  pack.json\n`);
    const r = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw new Error("network forbidden")}', path.join(out, 'cli.js'), 'verify', pack, '--allow-unsigned', '--json'], { cwd: out, encoding: 'utf8' });
    expect(r.status).toBe(0); expect(JSON.parse(r.stdout)).toMatchObject({ ok: true, failures: [], files: 1 });
    expect(r.stderr).toContain('Keys: bundled with this version'); expect(r.stderr).not.toContain('network forbidden');
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});

test('dist/mcp.js starts and lists its tools without dependencies or network', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-mcp-dist-'));
  try {
    const built = spawnSync('bun', ['build', 'src/mcp.ts', '--target=node', '--minify-syntax', '--minify-whitespace', '--outdir', out], { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' });
    expect(built.status).toBe(0);
    const bundle = fs.readFileSync(path.join(out, 'mcp.js'), 'utf8');
    expect(bundle === fs.readFileSync(new URL('../dist/mcp.js', import.meta.url), 'utf8')).toBe(true);
    expect(bundle.startsWith('#!/usr/bin/env node\n')).toBe(true);
    const messages = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'package-test', version: '1.0.0' } } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    ];
    const result = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw new Error("network forbidden")}', path.join(out, 'mcp.js')], {
      cwd: out, encoding: 'utf8', input: messages.map((message) => JSON.stringify(message)).join('\n') + '\n', timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain('network forbidden');
    const replies = result.stdout.trim().split('\n').map((line) => JSON.parse(line));
    expect(replies.find((reply) => reply.id === 1).result.serverInfo.name).toBe('diffseal');
    expect(replies.find((reply) => reply.id === 2).result.tools.map((tool: { name: string }) => tool.name).sort()).toEqual(['diffseal_replay_commit', 'diffseal_review_plan']);
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});
