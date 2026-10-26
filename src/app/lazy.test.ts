import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

test('a Terraform-only Action never opens a parser WASM or accesses the network', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-lazy-'));
  try {
    const dist = path.resolve(import.meta.dirname, '../../dist');
    fs.copyFileSync(path.join(dist, 'action.js'), path.join(dir, 'action.js'));
    // Intentionally ship no WASMs. A Terraform-only run must not need even the parser runtime.
    fs.writeFileSync(path.join(dir, 'plan.json'), JSON.stringify({ format_version: '1.2', resource_changes: [] }));
    const result = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw Error("network forbidden")}', path.join(dir, 'action.js')], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, INPUT_MODE: 'plan', 'INPUT_PLAN-JSON': 'plan.json', INPUT_COMMENT: 'false', INPUT_POLICY: '', GITHUB_EVENT_PATH: '', GITHUB_WORKSPACE: dir, GITHUB_OUTPUT: path.join(dir, 'outputs') },
    });
    expect(result.status).toBe(0);
    expect(fs.readFileSync(path.join(dir, 'outputs'), 'utf8')).toContain('gate=pass');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('offline Action parser assets take less than two megabytes on disk', () => {
  const dist = path.resolve(import.meta.dirname, '../../dist');
  const assets = fs.readdirSync(dist).filter((file) => /\.wasm(?:-[^.]+\.gz)?$/.test(file));
  expect(assets.length).toBe(8);
  expect(assets.reduce((size, file) => size + fs.statSync(path.join(dist, file)).size, 0)).toBeLessThan(2_000_000);
});

const managed = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../fixtures/app/languages.json'), 'utf8')).cases;
const examples: Array<{ language: string; files: Record<string, string>; asset: string }> = [
  { language: 'go', asset: 'go', files: { 'go.mod': 'module example.invalid/app\n', 'main.go': 'package main\nimport("context";"github.com/aws/aws-sdk-go-v2/service/s3")\nfunc main(){client:=s3.NewFromConfig(cfg);client.GetObject(context.Background(), &s3.GetObjectInput{Bucket:aws.String("reports")})}\n' } },
  { language: 'typescript', asset: 'typescript', files: { 'app.ts': 'import {GetObjectCommand} from "@aws-sdk/client-s3"; new GetObjectCommand({Bucket:"reports"});\n' } },
  { language: 'tsx', asset: 'tsx', files: { 'app.tsx': 'import {GetObjectCommand} from "@aws-sdk/client-s3"; new GetObjectCommand({Bucket:"reports"}); const view=<div/>;\n' } },
  { language: 'python', asset: 'python', files: { 'app.py': 'import boto3\nc=boto3.client("s3")\nc.get_object(Bucket="reports",Key="x")\n' } },
  ...['java', 'kotlin', 'c_sharp'].map((asset, i) => ({ language: asset, asset, files: managed[i].files })),
];
for (const example of examples) test(`the ${example.language} Action uses only its grammar and the runtime`, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-one-language-'));
  const repo = path.join(dir, 'repo'), bin = path.join(dir, 'bin');
  fs.mkdirSync(repo); fs.mkdirSync(bin);
  const git = (args: string[]) => {
    const r = spawnSync('git', ['-C', repo, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw Error(r.stderr);
  };
  try {
    const dist = path.resolve(import.meta.dirname, '../../dist');
    for (const file of fs.readdirSync(dist).filter((f) => f === 'action.js' || f.startsWith('tree-sitter.wasm-') || f.startsWith(`tree-sitter-${example.asset}.wasm-`))) fs.copyFileSync(path.join(dist, file), path.join(bin, file));
    git(['init', '-q']); fs.writeFileSync(path.join(repo, 'empty.txt'), 'base'); git(['add', '.']); git(['commit', '-qm', 'base']);
    for (const [name, content] of Object.entries(example.files)) fs.writeFileSync(path.join(repo, name), content);
    git(['add', '.']); git(['commit', '-qm', 'add application']);
    const result = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw Error("network forbidden")}', path.join(bin, 'action.js')], { cwd: repo, encoding: 'utf8', env: { ...process.env, INPUT_MODE: 'pr', INPUT_BASE: 'HEAD^', INPUT_COMMENT: 'false', INPUT_ADVISORY: 'true', INPUT_STRICT: 'false', INPUT_POLICY: '', GITHUB_EVENT_PATH: '', GITHUB_WORKSPACE: repo, GITHUB_OUTPUT: path.join(dir, 'outputs'), GITHUB_STEP_SUMMARY: path.join(dir, 'summary') } });
    expect(result.status).toBe(0);
    expect(fs.readFileSync(path.join(dir, 'summary'), 'utf8')).toContain('s3:GetObject');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
