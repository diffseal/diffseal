import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

type Step = { name?: string; uses?: string; with?: Record<string, unknown>; run?: string; env?: Record<string, string> };
type Workflow = {
  on: Record<string, unknown>;
  permissions: Record<string, string>;
  jobs: Record<string, { permissions?: Record<string, string>; steps: Step[] }>;
};
function workflow(name: string): Workflow {
  return Bun.YAML.parse(readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), 'utf8')) as Workflow;
}

test('CI checks pull requests and main with read-only permissions and a frozen toolchain', () => {
  const ci = workflow('ci');
  expect(Object.keys(ci.on).sort()).toEqual(['pull_request', 'push']);
  expect(ci.on.push).toEqual({ branches: ['main'] });
  expect(ci.permissions).toEqual({ contents: 'read' });
  const steps = ci.jobs.check.steps;
  for (const step of steps.filter((s) => s.uses)) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  expect(steps.find((s) => s.uses?.startsWith('oven-sh/setup-bun@'))?.with?.['bun-version']).toBe('1.4.4');
  const runs = steps.map((s) => s.run ?? '').join('\n');
  for (const command of [
    'bun install --frozen-lockfile',
    'bun run typecheck',
    'bun test',
    'bun run build',
    'git diff --exit-code -- dist/',
  ])
    expect(runs).toContain(command);
});

test('tag releases validate the build before publishing with tag notes', () => {
  const release = workflow('release');
  expect(release.on).toEqual({ push: { tags: ['v*'] } });
  expect(release.permissions).toEqual({ contents: 'write' });
  const steps = release.jobs.release.steps;
  for (const step of steps.filter((s) => s.uses)) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  expect(steps.find((s) => s.uses?.startsWith('oven-sh/setup-bun@'))?.with?.['bun-version']).toBe('1.4.4');
  const runs = steps.map((s) => s.run ?? '').join('\n');
  expect(runs.indexOf('bun test')).toBeLessThan(runs.indexOf('gh release create'));
  expect(runs).toContain('git diff --exit-code -- dist/');
  expect(runs).toContain('--notes-from-tag');
  expect(runs).toContain('--verify-tag');
  expect(runs).toContain('tar -czf');
});

test('npm publishing follows the GitHub release with trusted publishing and no stored token', () => {
  const release = workflow('release');
  expect(release.permissions).not.toHaveProperty('id-token');
  expect(release.jobs.release.permissions).toEqual({ contents: 'write', 'id-token': 'write' });
  const steps = release.jobs.release.steps;
  const setup = steps.findIndex((step) => step.uses?.startsWith('actions/setup-node@'));
  const publish = steps.findIndex((step) => step.name === 'Publish to npm');
  expect(setup).toBeGreaterThan(steps.findIndex((step) => step.run?.includes('gh release create')));
  expect(publish).toBeGreaterThan(setup);
  expect(steps[setup].uses).toMatch(/^actions\/setup-node@[a-f0-9]{40}$/);
  expect(steps[setup].with).toEqual({ 'node-version': '24', 'registry-url': 'https://registry.npmjs.org', 'package-manager-cache': false });
  expect(steps[publish].env).toBeUndefined();
  expect(JSON.stringify(release)).not.toContain('NPM_TOKEN');
  expect(steps[publish].run).toContain('npm publish --access public');
});

test('npm publishing skips a version already on npm, selects beta for prereleases and propagates failures', () => {
  const script = workflow('release').jobs.release.steps.find((step) => step.name === 'Publish to npm')!.run!;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-publish-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ version: '1.0.0' }));
    // A fake npm: `view` succeeds only when NPM_PUBLISHED is set; `install` is a no-op; `publish` records its arguments.
    fs.writeFileSync(path.join(dir, 'npm'), '#!/bin/bash\ncase "$1" in\n  view) [[ -n "$NPM_PUBLISHED" ]] && echo 1.0.0 && exit 0; exit 1 ;;\n  install) exit 0 ;;\n  publish) printf "%s\\n" "$@" > "$NPM_ARGS"; exit "${NPM_EXIT:-0}" ;;\nesac\n', { mode: 0o755 });
    const argsFile = path.join(dir, 'args');
    const run = (tag: string, published = '', exit = '0') => spawnSync('bash', ['-e', '-c', script], {
      cwd: dir,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}`, GITHUB_REF_NAME: tag, NPM_ARGS: argsFile, NPM_EXIT: exit, NPM_PUBLISHED: published },
    });
    const skipped = run('v1.0.0', 'yes');
    expect(skipped.status).toBe(0);
    expect(skipped.stdout).toContain('already on npm; publishing is skipped');
    expect(fs.existsSync(argsFile)).toBe(false);
    expect(run('v1.0.0').status).toBe(0);
    expect(fs.readFileSync(argsFile, 'utf8').trim().split('\n')).toEqual(['publish', '--access', 'public']);
    expect(run('v1.0.0-beta').status).toBe(0);
    expect(fs.readFileSync(argsFile, 'utf8').trim().split('\n')).toEqual(['publish', '--access', 'public', '--tag', 'beta']);
    expect(run('v1.0.0', '', '1').status).not.toBe(0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('trusted upload workflow has no analysis inputs and uses base Git settings and the release Action', () => {
  const w = workflow('upload');
  // The only input says how long the report artifact is kept; nothing the caller passes reaches the analysis.
  expect(Object.keys(w.on)).toEqual(['workflow_call']);
  expect(Object.keys((w.on.workflow_call as { inputs: object }).inputs)).toEqual(['retention-days']);
  expect(w.permissions).toEqual({ contents: 'read', 'pull-requests': 'write', 'id-token': 'write' });
  const steps = w.jobs.upload.steps;
  expect(steps[0].uses).toMatch(/^actions\/checkout@[a-f0-9]{40}$/);
  expect(steps[0].with).toEqual({ 'fetch-depth': 0, 'persist-credentials': false });
  // The trusted workflow runs the Action from its own release, never an older one.
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  expect(steps[2].uses).toBe(`diffseal/diffseal@v${version}`);
  expect(steps[2].with).toMatchObject({ mode: 'pr', upload: 'true', advisory: 'true', 'report-artifact': 'true' });
  const text = readFileSync(new URL('../.github/workflows/upload.yml', import.meta.url), 'utf8');
  expect(text).toContain('github.event.pull_request.base.sha || github.sha');
  expect(text).toContain("['show', `${rev}:${file}`]");
  expect(text).toContain("['.diffseal.json', '.terratrust.json']");
  expect(text.replaceAll('inputs.retention-days', '')).not.toContain('inputs.');
  expect(text).not.toContain('readFileSync');
});

test('trusted upload workflow keeps the full report of a review as an artifact, without wider permissions', () => {
  const w = workflow('upload');
  expect((w.on.workflow_call as { inputs: Record<string, unknown> }).inputs['retention-days']).toMatchObject({ type: 'number', required: false, default: 90 });
  // Artifacts are uploaded with the runner's own token; the job gets no permission for them.
  expect(w.permissions).toEqual({ contents: 'read', 'pull-requests': 'write', 'id-token': 'write' });
  expect(w.jobs.upload.permissions).toBeUndefined();
  const steps = w.jobs.upload.steps as Array<Step & { id?: string; if?: string; 'continue-on-error'?: boolean }>;
  const review = steps.findIndex((s) => s.uses?.startsWith('diffseal/diffseal@'));
  const keep = steps.findIndex((s) => s.uses?.startsWith('actions/upload-artifact@'));
  expect(steps[review].id).toBe('diffseal');
  expect(keep).toBe(review + 1);
  const step = steps[keep];
  expect(step.uses).toMatch(/^actions\/upload-artifact@[a-f0-9]{40}$/);
  const text = readFileSync(new URL('../.github/workflows/upload.yml', import.meta.url), 'utf8');
  expect(text).toMatch(new RegExp(`uses: ${step.uses!.replace('/', '\\/')} # v\\d+\\.\\d+\\.\\d+\\n`));
  // Only after a review ran, also when it failed the step, but not when the run is cancelled.
  expect(step.if).toBe("${{ !cancelled() && steps.diffseal.outputs.report-dir != '' }}");
  expect(step.with).toEqual({
    name: '${{ steps.diffseal.outputs.artifact-name }}',
    path: '${{ steps.diffseal.outputs.report-dir }}',
    'retention-days': '${{ inputs.retention-days }}',
    'if-no-files-found': 'error',
    overwrite: true,
  });
  // A failed artifact upload warns; like a failed evidence upload, it does not fail the advisory job.
  expect(step['continue-on-error']).toBe(true);
});

test('the Action declares the report input and outputs the workflow uses', () => {
  const action = Bun.YAML.parse(readFileSync(new URL('../action.yml', import.meta.url), 'utf8')) as { inputs: Record<string, { default?: string }>; outputs: Record<string, unknown> };
  expect(action.inputs['report-artifact']?.default).toBe('false');
  expect(Object.keys(action.outputs)).toEqual(expect.arrayContaining(['report-dir', 'artifact-name']));
});

test('trusted settings ignore the working tree and reject output injection', async () => {
  const fs = await import('node:fs'), os = await import('node:os'), path = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-trusted-settings-'));
  const git = (...args: string[]) => {
    const r = spawnSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw new Error(r.stderr); return r.stdout.trim();
  };
  try {
    git('init', '-q');
    fs.writeFileSync(path.join(dir, '.diffseal.json'), JSON.stringify({ replay: { rootsUnder: 'infra', policyFile: 'policy.json', moduleCache: 'cache' } }));
    git('add', '.'); git('commit', '-qm', 'trusted settings'); const rev = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(dir, '.diffseal.json'), JSON.stringify({ replay: { rootsUnder: 'empty', policyFile: 'weakened.json' } }));
    const run = workflow('upload').jobs.upload.steps[1].run!;
    const script = run.slice(run.indexOf("<<'NODE'\n") + "<<'NODE'\n".length, run.lastIndexOf('NODE'));
    const output = path.join(dir, 'outputs');
    const execute = (revision: string) => spawnSync('node', ['--input-type=module', '-e', script], { cwd: dir, encoding: 'utf8', env: { ...process.env, SETTINGS_REV: revision, GITHUB_OUTPUT: output } });
    expect(execute(rev).status).toBe(0);
    expect(fs.readFileSync(output, 'utf8')).toBe('roots-under=infra\npolicy=policy.json\nmodule-cache=cache\n');
    fs.writeFileSync(path.join(dir, '.diffseal.json'), JSON.stringify({ replay: { rootsUnder: 'infra\npolicy=weakened' } }));
    git('add', '.diffseal.json'); git('commit', '-qm', 'invalid settings');
    const invalid = execute(git('rev-parse', 'HEAD')); expect(invalid.status).toBe(1); expect(invalid.stderr).toContain('Invalid replay.rootsUnder');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
