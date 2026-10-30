import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// The application code check was removed. Old workflows and scripts fail with one plain line.
const root = path.resolve(import.meta.dirname, '..');

test('the Action fails mode: app with one clear line and writes no report', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-removed-'));
  try {
    const summary = path.join(dir, 'summary.md'), output = path.join(dir, 'outputs');
    const r = spawnSync('node', [path.join(root, 'dist/action.js')], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_WORKSPACE: dir, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary, GITHUB_EVENT_PATH: '', INPUT_MODE: 'app', INPUT_COMMENT: 'false', INPUT_ADVISORY: 'true' },
    });
    expect(r.status).toBe(1);
    expect(r.stderr.trim().split('\n')).toEqual(['mode: app was removed in the next release; Diffseal reviews Terraform only']);
    expect(r.stdout).toBe('');
    expect(fs.existsSync(summary)).toBe(false);
    expect(fs.existsSync(output)).toBe(false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}, 30_000);

test('the CLI fails check-app with one clear line', () => {
  for (const args of [['check-app', '--app', '.', '--worktree'], ['check-app']]) {
    const r = spawnSync('bun', [path.join(root, 'src/cli.ts'), ...args], { cwd: root, encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr.trim().split('\n')).toEqual(['check-app was removed in the next release; Diffseal reviews Terraform only']);
    expect(r.stdout).toBe('');
  }
});

test('help lists no application code check', () => {
  const r = spawnSync('bun', [path.join(root, 'src/cli.ts'), '--help'], { cwd: root, encoding: 'utf8' });
  expect(r.status).toBe(0);
  expect(r.stdout).not.toContain('check-app');
  expect(r.stdout).not.toMatch(/application|SDK call/i);
});
