import { describe, expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { assertOutsideRepo, protectedRoots } from './output.js';

describe('assertOutsideRepo', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-out-'));
  const repo = path.join(tmp, 'repo');
  const out = path.join(tmp, 'out');
  fs.mkdirSync(repo);
  fs.mkdirSync(out);

  test('allows a path outside the repository', () => {
    expect(() => assertOutsideRepo(path.join(out, 'r.md'), [repo])).not.toThrow();
  });

  test('refuses a path inside the repository, even one that does not exist yet', () => {
    expect(() => assertOutsideRepo(path.join(repo, 'dry-runs', 'r.md'), [repo])).toThrow(/only reads/);
  });

  test('refuses a symlink that points into the repository', () => {
    const link = path.join(tmp, 'sneaky');
    fs.symlinkSync(repo, link);
    expect(() => assertOutsideRepo(path.join(link, 'r.md'), [repo])).toThrow(/only reads/);
  });

  test('refuses a differently cased path on a case-insensitive file system', () => {
    if (!fs.existsSync(path.join(tmp, 'REPO'))) return; // case-sensitive file system: nothing to test
    expect(() => assertOutsideRepo(path.join(tmp, 'REPO', 'r.md'), [repo])).toThrow(/only reads/);
  });

  test('protects the whole git work tree when given a subdirectory of it', () => {
    const top = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-top-'));
    spawnSync('git', ['-C', top, 'init', '-q']);
    fs.mkdirSync(path.join(top, 'infra'));
    expect(() => assertOutsideRepo(path.join(top, 'dry-runs', 'r.md'), protectedRoots([path.join(top, 'infra')]))).toThrow(/only reads/);
  });
});
