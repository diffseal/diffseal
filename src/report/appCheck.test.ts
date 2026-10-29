import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { checkApp } from '../app/checkApp.js';
import { renderAppCheck } from './appCheck.js';

test('the check-app report names the infrastructure repository without its local path', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-infra-name-'));
  try {
    fs.writeFileSync(path.join(dir, 'main.tf'), 'resource "aws_iam_role" "r" {\n  name = "r"\n  assume_role_policy = "{}"\n}\n');
    for (const args of [['init', '-q'], ['add', '-A'], ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-qm', 'init']]) {
      const run = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
      if (run.status) throw new Error(run.stderr);
    }
    const report = renderAppCheck(await checkApp({ app: dir, rev: 'HEAD' }));
    expect(report).toContain(`Infrastructure: ${path.basename(dir)}@`);
    expect(report).not.toContain(path.dirname(dir));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
