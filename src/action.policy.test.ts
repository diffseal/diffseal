import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// The heading is the verdict, so it must match the gate the Action outputs (review of the redesign).
test('in plan mode, a policy file changed by the pull request raises the heading and the callout, not only the output', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-policy-'));
  try {
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
      if (r.status) throw Error(r.stderr);
      return r.stdout.trim();
    };
    git('init', '-q');
    fs.writeFileSync(path.join(dir, 'policy.json'), '{}');
    fs.writeFileSync(path.join(dir, 'plan.json'), JSON.stringify({ format_version: '1.2', resource_changes: [] }));
    git('add', '.');
    git('commit', '-qm', 'base');
    const base = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(dir, 'policy.json'), '{"blockOn":[]}');
    git('commit', '-qam', 'relax policy');
    const summary = path.join(dir, 'summary.md'), output = path.join(dir, 'outputs');
    const r = spawnSync('bun', [path.resolve(import.meta.dirname, 'action.ts')], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_WORKSPACE: dir, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary, GITHUB_EVENT_PATH: '', INPUT_MODE: 'plan', 'INPUT_PLAN-JSON': 'plan.json', INPUT_POLICY: 'policy.json', INPUT_BASE: base, INPUT_COMMENT: 'false', INPUT_ADVISORY: 'true' },
    });
    expect(r.status).toBe(0);
    expect(fs.readFileSync(output, 'utf8')).toContain('gate=review');
    const md = fs.readFileSync(summary, 'utf8');
    expect(md.split('\n')[0]).toBe('## TerraTrust: REVIEW');
    expect(md).toContain('> - policy.json changed in this pull request.');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}, 30_000);
