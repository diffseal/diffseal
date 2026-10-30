import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { actionExitCode, eventBase, needsBase, pullRequestBase, readPolicy } from './inputs.js';

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-action-'));
  const git = (...args: string[]) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' }).stdout.trim();
  git('init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(dir, 'policy.json'), '{"blockOn":["CRITICAL"]}');
  git('add', '-A');
  git('commit', '-qm', 'base');
  return { dir, git };
}

describe('Action inputs (round 3)', () => {
  test('a pull request checked out at its head is compared with where it branched, not HEAD^1', () => {
    const { dir, git } = repo();
    const fork = git('rev-parse', 'HEAD');
    git('checkout', '-qb', 'feature');
    for (const n of [1, 2]) {
      fs.writeFileSync(path.join(dir, `f${n}.txt`), String(n));
      git('add', '-A');
      git('commit', '-qm', `c${n}`);
    }
    git('checkout', '-q', 'main');
    fs.writeFileSync(path.join(dir, 'later.txt'), 'x');
    git('add', '-A');
    git('commit', '-qm', 'later on main');
    const baseSha = git('rev-parse', 'HEAD');
    git('checkout', '-q', 'feature');
    expect(pullRequestBase(dir, '', baseSha)).toBe(fork);
    expect(pullRequestBase(dir, 'HEAD~1', baseSha)).toBe(git('rev-parse', 'HEAD~1'));
    expect(pullRequestBase(dir, '', undefined)).toBeUndefined();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('a base commit missing from a shallow checkout gives an error that says how to fix it (round 4)', () => {
    const { dir } = repo();
    expect(() => pullRequestBase(dir, '', 'f'.repeat(40))).toThrow(/fetch-depth: 0/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('the base comes from a pull request or a merge queue event (round 5)', () => {
    expect(eventBase({ pull_request: { base: { sha: 'a'.repeat(40) } } })).toBe('a'.repeat(40));
    expect(eventBase({ merge_group: { base_sha: 'b'.repeat(40) } })).toBe('b'.repeat(40));
    expect(eventBase({ push: {} })).toBeUndefined();
  });

  test('plan mode without a policy file needs no base, so a shallow checkout works (round 4)', () => {
    expect(needsBase('plan', '')).toBe(false);
    expect(needsBase('plan', 'policy.json')).toBe(true);
    expect(needsBase('pr', '')).toBe(true);
  });

  test('a policy file outside the workspace is an error, not silently no policy', () => {
    const { dir, git } = repo();
    expect(() => readPolicy(dir, '../elsewhere/policy.json', git('rev-parse', 'HEAD'))).toThrow(/inside the repository/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('the policy comes from the base, and a change to it is reported', () => {
    const { dir, git } = repo();
    const base = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(dir, 'policy.json'), '{"blockOn":[]}');
    const r = readPolicy(dir, 'policy.json', base);
    expect(r.policy.blockOn).toEqual(['CRITICAL']);
    expect(r.changed).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('advisory mode never fails the job, even on BLOCK', () => {
    expect(actionExitCode('pass', { strict: false, advisory: false })).toBe(0);
    expect(actionExitCode('review', { strict: false, advisory: false })).toBe(0);
    expect(actionExitCode('review', { strict: true, advisory: false })).toBe(2);
    expect(actionExitCode('block', { strict: false, advisory: false })).toBe(2);
    expect(actionExitCode('block', { strict: false, advisory: true })).toBe(0);
    expect(actionExitCode('review', { strict: true, advisory: true })).toBe(0);
  });
});
