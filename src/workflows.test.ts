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
