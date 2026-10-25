import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateRoot } from './expand.js';
import { spawnSync } from 'node:child_process';
import { FsSource, GitSource, normalize } from './source.js';

test('normalize keeps dot-directories and strips only a leading ./', () => {
  expect(normalize('.sage/aws.go')).toBe('.sage/aws.go');
  expect(normalize('./infra/x.tf')).toBe('infra/x.tf');
  expect(normalize('infra/envs/../modules/')).toBe('infra/modules');
  expect(normalize('.')).toBe('.');
});

test('file() cannot read outside the analyzed repository, also through a symlink (round 2)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-fs-'));
  fs.mkdirSync(path.join(tmp, 'repo/r'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'secret.txt'), 'top secret');
  fs.symlinkSync(path.join(tmp, 'secret.txt'), path.join(tmp, 'repo/r/link.txt'));
  fs.writeFileSync(
    path.join(tmp, 'repo/r/main.tf'),
    'terraform {\n  backend "s3" {}\n}\nresource "aws_sqs_queue" "q" {\n  name = file("../../secret.txt")\n  tags = { t = file("${path.module}/link.txt") }\n}\n',
  );
  const ev = evaluateRoot(new FsSource(path.join(tmp, 'repo')), 'r');
  expect(JSON.stringify(ev.instances[0].attrs)).not.toContain('top secret');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('GitSource exposes immutable blob IDs across commits without reading the worktree', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-blobs-'));
  const run = (args: string[]) => {
    const r = spawnSync('git', ['-C', dir, '-c', 'core.hooksPath=/dev/null', ...args], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(r.stderr);
    return r.stdout.trim();
  };
  try {
    run(['init', '-q']);
    run(['config', 'user.name', 'Test']);
    run(['config', 'user.email', 'test@example.invalid']);
    fs.writeFileSync(path.join(dir, 'a.ts'), 'const x="one";');
    fs.writeFileSync(path.join(dir, 'b.ts'), 'const y="stable";');
    run(['add', '.']);
    run(['commit', '-qm', 'first']);
    const first = new GitSource(dir, 'HEAD');
    fs.writeFileSync(path.join(dir, 'a.ts'), 'const x="two";');
    run(['add', '.']);
    run(['commit', '-qm', 'second']);
    const second = new GitSource(dir, 'HEAD');
    expect(first.blobId('a.ts')).toMatch(/^[a-f0-9]{40}$/);
    expect(second.blobId('a.ts')).not.toBe(first.blobId('a.ts'));
    expect(second.blobId('b.ts')).toBe(first.blobId('b.ts'));
    expect(first.readFile('a.ts')).toBe('const x="one";');
    expect(second.blobId('missing')).toBeUndefined();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
