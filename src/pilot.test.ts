import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { parse } from 'yaml';

test('the vendored pilot workflow and isolated package review all three demo scenarios', () => {
  const root = path.resolve(import.meta.dirname, '..'), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-pilot-'));
  try {
    const out = path.join(dir, 'pilot');
    const packed = spawnSync('bun', [path.join(root, 'scripts/prepare-pilot.ts'), out], { encoding: 'utf8' });
    expect(packed.status).toBe(0);
    expect(fs.readFileSync(path.join(out, 'VERSION'), 'utf8').trim()).toBe('0.4.1-beta');
    const workflow = parse(fs.readFileSync(path.join(out, '.github/workflows/terratrust.yml'), 'utf8'));
    const step = workflow.jobs.terratrust.steps.find((s: { uses?: string }) => s.uses === './.github/actions/terratrust');
    expect(step['continue-on-error']).toBe(true);
    expect(step.with).toEqual({ mode: 'pr', advisory: 'true', strict: 'false' });
    const tool = path.join(out, '.github/actions/terratrust');
    expect(fs.readdirSync(path.join(tool, 'dist')).filter((name) => /\.wasm(?:-[^.]+\.gz)?$/.test(name)).length).toBe(8);
    expect(fs.existsSync(path.join(tool, 'LICENSE'))).toBe(true);
    expect(fs.existsSync(path.join(tool, 'dist/licenses/web-tree-sitter.LICENSE'))).toBe(true);
    const fixture = JSON.parse(fs.readFileSync(path.join(root, 'fixtures/demo/snapshots.fixture'), 'utf8'));
    for (const scenario of fixture.heads) {
      const repo = path.join(dir, scenario.name); fs.mkdirSync(repo);
      const git = (args: string[]) => {
        const r = spawnSync('git', ['-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
        if (r.status) throw Error(r.stderr); return r.stdout.trim();
      };
      const write = (files: Record<string, string>) => { for (const [file, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(repo, file)), { recursive: true }); fs.writeFileSync(path.join(repo, file), text); } };
      git(['init', '-q']); write(fixture.base); git(['add', '.']); git(['commit', '-qm', 'base']);
      const base = git(['rev-parse', 'HEAD']);
      for (const file of Object.keys(fixture.base)) if (!(file in scenario.files)) fs.rmSync(path.join(repo, file));
      write(scenario.files); git(['add', '.']); git(['commit', '-qm', scenario.name]);
      const output = path.join(dir, scenario.name + '.outputs'), summary = path.join(dir, scenario.name + '.md');
      const r = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw Error("network forbidden")}', path.join(tool, 'dist/action.js')], { cwd: repo, encoding: 'utf8', env: { ...process.env, GITHUB_WORKSPACE: repo, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary, GITHUB_EVENT_PATH: '', INPUT_MODE: step.with.mode, INPUT_ADVISORY: step.with.advisory, INPUT_STRICT: step.with.strict, INPUT_BASE: base, INPUT_COMMENT: 'false', INPUT_POLICY: '', INPUT_ROOTS_UNDER: 'infra/envs/prod' } });
      expect(r.status).toBe(0); // Advisory mode preserves a BLOCK report without failing the job.
      expect(fs.readFileSync(output, 'utf8')).toContain(`gate=${scenario.gate}`);
      const markdown = fs.readFileSync(summary, 'utf8'); expect(markdown).toContain(scenario.finding); expect(markdown).toContain('0.4.1-beta');
      if (scenario.name === 'missing-iam-permission') expect(markdown).toContain('statement {');
      expect(r.stderr).not.toContain('network forbidden');
    }
    expect(spawnSync('bun', [path.join(root, 'scripts/prepare-pilot.ts'), out], { encoding: 'utf8' }).status).toBe(1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}, 30_000);
