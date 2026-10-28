import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

type Workflow = {
  on: Record<string, unknown>;
  permissions: Record<string, string>;
  jobs: Record<string, { steps: Array<{ uses?: string; with?: Record<string, unknown>; run?: string }> }>;
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
  expect(steps.find((s) => s.uses?.startsWith('oven-sh/setup-bun@'))?.with?.['bun-version']).toBe('1.3.14');
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
  expect(steps.find((s) => s.uses?.startsWith('oven-sh/setup-bun@'))?.with?.['bun-version']).toBe('1.3.14');
  const runs = steps.map((s) => s.run ?? '').join('\n');
  expect(runs.indexOf('bun test')).toBeLessThan(runs.indexOf('gh release create'));
  expect(runs).toContain('git diff --exit-code -- dist/');
  expect(runs).toContain('--notes-from-tag');
  expect(runs).toContain('--verify-tag');
  expect(runs).toContain('tar -czf');
});

test('trusted upload workflow has no analysis inputs and uses base Git settings and the release Action', () => {
  const w = workflow('upload');
  expect(w.on).toEqual({ workflow_call: null });
  expect(w.permissions).toEqual({ contents: 'read', 'pull-requests': 'write', 'id-token': 'write' });
  const steps = w.jobs.upload.steps;
  expect(steps[0].uses).toMatch(/^actions\/checkout@[a-f0-9]{40}$/);
  expect(steps[0].with).toEqual({ 'fetch-depth': 0, 'persist-credentials': false });
  expect(steps[2].uses).toBe('diffseal/diffseal@v0.4.1-beta');
  expect(steps[2].with).toMatchObject({ mode: 'pr', upload: 'true', advisory: 'true' });
  const text = readFileSync(new URL('../.github/workflows/upload.yml', import.meta.url), 'utf8');
  expect(text).toContain('github.event.pull_request.base.sha || github.sha');
  expect(text).toContain("['show', `${rev}:.diffseal.json`]");
  expect(text).not.toContain('inputs.');
  expect(text).not.toContain('readFileSync');
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
