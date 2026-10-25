import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateRoot } from './expand.js';
import { FsSource, normalize } from './source.js';

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
    'terraform {\n  backend "s3" {}\n}\nresource "aws_sqs_queue" "q" {\n  name = file("../../secret.txt")\n  tags = { t = file("${path.module}/link.txt") }\n}\n'
  );
  const ev = evaluateRoot(new FsSource(path.join(tmp, 'repo')), 'r');
  expect(JSON.stringify(ev.instances[0].attrs)).not.toContain('top secret');
  fs.rmSync(tmp, { recursive: true, force: true });
});
