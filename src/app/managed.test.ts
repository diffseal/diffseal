import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

test('the isolated Node Action parses C sharp and reports its missing S3 permission without network', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-managed-action-')),
    repo = path.join(dir, 'repo'),
    bin = path.join(dir, 'bin');
  fs.mkdirSync(repo);
  fs.mkdirSync(bin);
  const git = (args: string[]) => {
    const r = spawnSync(
      'git',
      [
        '-C',
        repo,
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'user.name=Test',
        '-c',
        'user.email=test@example.invalid',
        ...args,
      ],
      { encoding: 'utf8' },
    );
    if (r.status) throw new Error(r.stderr);
    return r.stdout.trim();
  };
  const write = (name: string, text: string) => {
    const file = path.join(repo, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  };
  try {
    const dist = path.resolve(import.meta.dirname, '../../dist');
    for (const file of fs.readdirSync(dist).filter((f) => f === 'action.js' || f.endsWith('.wasm')))
      fs.copyFileSync(path.join(dist, file), path.join(bin, file));
    git(['init', '-q']);
    write(
      'infra/prod/main.tf',
      `terraform {
 backend "s3" {}
}
resource "aws_iam_role" "r" {
 name="worker"
 assume_role_policy="{}"
}
resource "aws_iam_role_policy" "p" {
 role=aws_iam_role.r.name
 policy=jsonencode({Statement=[{Effect="Allow",Action="s3:PutObject",Resource="arn:aws:s3:::reports/*"}]})
}
resource "aws_lambda_function" "f" {
 function_name="worker"
 role=aws_iam_role.r.arn
 environment {
  variables={DATA_BUCKET="reports"}
 }
}
`,
    );
    write('Worker.cs', 'class Worker {}\n');
    git(['add', '.']);
    git(['commit', '-qm', 'base']);
    const base = git(['rev-parse', 'HEAD']);
    const fixture = JSON.parse(
      fs.readFileSync(path.resolve(import.meta.dirname, '../../fixtures/app/languages.json'), 'utf8'),
    );
    const c = fixture.cases.find(
      (c: { name: string }) => c.name === 'C sharp SDK requests map BucketName and async operation names',
    );
    write('Worker.cs', c.files['Worker.cs']);
    git(['add', '.']);
    git(['commit', '-qm', 'add SDK call']);
    const output = path.join(dir, 'output'),
      summary = path.join(dir, 'summary');
    const r = spawnSync(
      'node',
      [
        '--import',
        'data:text/javascript,globalThis.fetch=()=>{throw new Error("network forbidden")}',
        path.join(bin, 'action.js'),
      ],
      {
        cwd: repo,
        encoding: 'utf8',
        env: {
          ...process.env,
          GITHUB_WORKSPACE: repo,
          GITHUB_OUTPUT: output,
          GITHUB_STEP_SUMMARY: summary,
          GITHUB_EVENT_PATH: '',
          INPUT_MODE: 'pr',
          INPUT_BASE: base,
          INPUT_COMMENT: 'false',
          INPUT_ADVISORY: 'false',
          INPUT_STRICT: 'false',
          INPUT_POLICY: '',
          INPUT_ROOTS_UNDER: 'infra',
        },
      },
    );
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('network forbidden');
    expect(fs.readFileSync(output, 'utf8')).toContain('gate=review');
    const text = fs.readFileSync(summary, 'utf8');
    expect(text).toContain('NOT GRANTED');
    expect(text).toContain('s3:GetObject');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}, 30000);
