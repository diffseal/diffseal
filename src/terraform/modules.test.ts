import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { evaluateRoot } from './expand.js';
import { FsSource } from './source.js';
const fixture = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../fixtures/modules/public.fixture'), 'utf8'));
const cli = path.resolve(import.meta.dirname, '../cli.ts');
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-modules-'));
  const repo = path.join(dir, 'root'), remote = path.join(dir, 'remote'), cache = path.join(dir, 'cache');
  fs.mkdirSync(repo); fs.mkdirSync(remote);
  const git = (args: string[]) => {
    const r = spawnSync('git', ['-C', remote, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw Error(r.stderr); return r.stdout.trim();
  };
  git(['init', '-q']); fs.writeFileSync(path.join(remote, 'main.tf'), fixture.module); git(['add', '.']); git(['commit', '-qm', 'module']); git(['tag', 'v1.2.0']);
  const source = 'git::' + pathToFileURL(remote).href + '?ref=v1.2.0';
  const write = (source: string, version = '') => fs.writeFileSync(path.join(repo, 'main.tf'), fixture.root.replace('SOURCE', JSON.stringify(source)).replace('VERSION', version ? `version=${JSON.stringify(version)}` : ''));
  const run = async (...args: string[]) => {
    const p = Bun.spawn(['bun', cli, ...args], { stdout: 'pipe', stderr: 'pipe' });
    const [exit, stdout, stderr] = await Promise.all([p.exited, new Response(p.stdout).text(), new Response(p.stderr).text()]);
    return { exit, stdout, stderr };
  };
  return { dir, repo, remote, cache, git, source, write, run };
}
test('modules fetch pins a git ref and the evaluator reads only verified cached contents', async () => {
  const f = setup();
  try {
    f.write(f.source);
    const r = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(r.exit).toBe(0);
    const lock = JSON.parse(fs.readFileSync(path.join(f.repo, 'terratrust.modules.lock.json'), 'utf8'));
    expect(lock.modules[0].commit).toBe(f.git(['rev-parse', 'HEAD']));
    expect(lock.modules[0].sha256).toMatch(/^[a-f0-9]{64}$/);
    const result = evaluateRoot(new FsSource(f.repo, f.cache), '.');
    expect(result.instances.map((r) => r.address)).toContain('module.bucket.aws_s3_bucket.this');
    expect(result.instances.find((r) => r.address.endsWith('aws_s3_bucket.this'))?.attrs.bucket).toBe('logs');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('modules fetch follows registry discovery and selects an exact matching version', async () => {
  const f = setup(), calls: string[] = [];
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
    const url = new URL(req.url); calls.push(url.pathname);
    if (url.pathname === '/.well-known/terraform.json') return Response.json({ 'modules.v1': '/v1/modules/' });
    if (url.pathname.endsWith('/versions')) return Response.json({ modules: [{ versions: [{ version: '1.2.0' }, { version: '1.9.0' }, { version: '2.0.0' }] }] });
    if (url.pathname.endsWith('/1.2.0/download')) return new Response(null, { status: 204, headers: { 'X-Terraform-Get': f.source } });
    return new Response('unexpected', { status: 500 });
  } });
  try {
    const source = `127.0.0.1:${server.port}/example/bucket/aws`;
    f.write(source, '~> 1.2.0');
    const result = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(result.exit).toBe(0);
    const lock = JSON.parse(fs.readFileSync(path.join(f.repo, 'terratrust.modules.lock.json'), 'utf8'));
    expect(lock.modules[0].source).toBe(source);
    expect(lock.modules[0].version).toBe('1.2.0');
    expect(calls).toEqual(['/.well-known/terraform.json', '/v1/modules/example/bucket/aws/versions', '/v1/modules/example/bucket/aws/1.2.0/download']);
    server.stop(true);
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances[0].attrs.bucket).toBe('logs');
  } finally { server.stop(true); fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('registry tarballs are verified and remain readable after the registry stops', async () => {
  const f = setup(), archive = path.join(f.dir, 'bundle.tgz');
  expect(spawnSync('tar', ['-czf', archive, '-C', f.remote, 'main.tf']).status).toBe(0);
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/.well-known/terraform.json') return Response.json({ 'modules.v1': '/v1/modules/' });
    if (url.pathname.endsWith('/versions')) return Response.json({ modules: [{ versions: [{ version: '1.2.0' }] }] });
    if (url.pathname.endsWith('/download')) return new Response(null, { status: 204, headers: { 'X-Terraform-Get': '/bundle.tgz?archive=tar.gz' } });
    if (url.pathname === '/bundle.tgz') return new Response(Bun.file(archive));
    return new Response('unexpected', { status: 500 });
  } });
  try {
    f.write(`127.0.0.1:${server.port}/example/bucket/aws`, '= 1.2.0');
    const result = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(result.exit).toBe(0);
    server.stop(true);
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances[0].attrs.bucket).toBe('logs');
  } finally { server.stop(true); fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('modules fetch locks external dependencies reached through local child modules', async () => {
  const f = setup();
  try {
    fs.mkdirSync(path.join(f.remote, 'child'));
    fs.writeFileSync(path.join(f.remote, 'child/main.tf'), `module "inner" {\n source=${JSON.stringify(f.source)}\n name="nested"\n}\n`);
    fs.appendFileSync(path.join(f.remote, 'main.tf'), 'module "child" { source="./child" }\n');
    f.git(['add', '.']); f.git(['commit', '-qm', 'parent']); f.git(['tag', 'parent']);
    f.write(f.source.replace('v1.2.0', 'parent'));
    const result = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(result.exit).toBe(0);
    const lock = JSON.parse(fs.readFileSync(path.join(f.repo, 'terratrust.modules.lock.json'), 'utf8'));
    expect(lock.modules.length).toBe(2);
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances.map((i) => i.attrs.bucket)).toEqual(['logs', 'nested']);
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('replay expands locked modules offline and uses each commit own lock', async () => {
  const f = setup();
  const rootGit = (args: string[]) => {
    const r = spawnSync('git', ['-C', f.repo, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw Error(r.stderr); return r.stdout.trim();
  };
  try {
    f.write(f.source); expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    rootGit(['init', '-q']); rootGit(['add', '.']); rootGit(['commit', '-qm', 'base']);
    const root = path.join(f.repo, 'main.tf'); fs.writeFileSync(root, fs.readFileSync(root, 'utf8').replace('name="logs"', 'name="logs-next"'));
    rootGit(['add', '.']); rootGit(['commit', '-qm', 'change module input']);
    const out = path.join(f.dir, 'replay');
    const result = await f.run('replay', '--repo', f.repo, '--commit', 'HEAD', '--module-cache', f.cache, '--out-dir', out);
    expect(result.exit).toBe(0);
    const report = JSON.parse(fs.readFileSync(path.join(out, rootGit(['rev-parse', '--short=9', 'HEAD']) + '.json'), 'utf8'));
    expect(JSON.stringify(report)).toContain('module.bucket.aws_s3_bucket.this');
    expect(JSON.stringify(report)).not.toContain('terraform_module_call');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('adding cache visibility never claims resources were created or destroyed', async () => {
  const { compareEvaluations } = await import('./compare.js');
  const f = setup();
  try {
    f.write(f.source); expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    const opaque = evaluateRoot(new FsSource(f.repo), '.'), known = evaluateRoot(new FsSource(f.repo, f.cache), '.');
    expect(compareEvaluations(known, known).map((change) => change.action)).toEqual(['no-op']);
    for (const changes of [compareEvaluations(opaque, known), compareEvaluations(known, opaque)]) {
      expect(changes.map((c) => c.action)).toEqual(['update']);
      expect(changes[0].confidence).toBe('unknown');
    }
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('fetch reuses an existing lock when a git branch advances', async () => {
  const f = setup();
  try {
    f.write(f.source.replace('?ref=v1.2.0', ''));
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    const lockFile = path.join(f.repo, 'terratrust.modules.lock.json'), before = fs.readFileSync(lockFile, 'utf8');
    fs.appendFileSync(path.join(f.remote, 'main.tf'), '\n# branch advanced\n'); f.git(['add', '.']); f.git(['commit', '-qm', 'advance']);
    fs.rmSync(f.cache, { recursive: true, force: true });
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    expect(fs.readFileSync(lockFile, 'utf8')).toBe(before);
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances[0].attrs.bucket).toBe('logs');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('missing caches and changed constraints stay opaque, while tampering fails closed', async () => {
  const f = setup();
  try {
    f.write(f.source); expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    expect(evaluateRoot(new FsSource(f.repo, path.join(f.dir, 'absent')), '.').instances[0].type).toBe('terraform_module_call');
    const lock = JSON.parse(fs.readFileSync(path.join(f.repo, 'terratrust.modules.lock.json'), 'utf8'));
    fs.writeFileSync(path.join(f.cache, 'objects', lock.modules[0].sha256 + '.json'), '{}\n');
    expect(() => evaluateRoot(new FsSource(f.repo, f.cache), '.')).toThrow('SHA-256 mismatch');
    f.write(f.source.replace('v1.2.0', 'different-ref'));
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances[0].type).toBe('terraform_module_call');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('the bundled Action reads the optional module-cache without network access', async () => {
  const f = setup();
  const git = (args: string[]) => {
    const r = spawnSync('git', ['-C', f.repo, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw Error(r.stderr); return r.stdout.trim();
  };
  try {
    f.write(f.source); expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    git(['init', '-q']); git(['add', '.']); git(['commit', '-qm', 'base']);
    const root = path.join(f.repo, 'main.tf'); fs.writeFileSync(root, fs.readFileSync(root, 'utf8').replace('name="logs"', 'name="logs-next"'));
    git(['add', '.']); git(['commit', '-qm', 'change']);
    const summary = path.join(f.dir, 'summary');
    const r = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=()=>{throw Error("network forbidden")}', path.resolve(import.meta.dirname, '../../dist/action.js')], { cwd: f.repo, encoding: 'utf8', env: { ...process.env, GITHUB_WORKSPACE: f.repo, GITHUB_STEP_SUMMARY: summary, GITHUB_EVENT_PATH: '', INPUT_MODE: 'pr', INPUT_BASE: 'HEAD^', INPUT_COMMENT: 'false', INPUT_POLICY: '', INPUT_ADVISORY: 'true', INPUT_STRICT: 'false', 'INPUT_MODULE-CACHE': f.cache } });
    expect(r.status).toBe(0);
    expect(fs.readFileSync(summary, 'utf8')).toContain('module.bucket.aws_s3_bucket.this');
    expect(r.stderr).not.toContain('network forbidden');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('a lock-only change compares the old and new pinned contents for nested roots', async () => {
  const f = setup();
  const git = (args: string[]) => {
    const r = spawnSync('git', ['-C', f.repo, '-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
    if (r.status) throw Error(r.stderr); return r.stdout.trim();
  };
  try {
    f.write(f.source.replace('?ref=v1.2.0', ''));
    fs.mkdirSync(path.join(f.repo, 'infra/prod'), { recursive: true }); fs.renameSync(path.join(f.repo, 'main.tf'), path.join(f.repo, 'infra/prod/main.tf'));
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    git(['init', '-q']); git(['add', '.']); git(['commit', '-qm', 'base']); const base = git(['rev-parse', 'HEAD']);
    fs.writeFileSync(path.join(f.remote, 'main.tf'), fixture.module.replace('bucket=var.name', 'bucket="other"')); f.git(['add', '.']); f.git(['commit', '-qm', 'new contents']);
    fs.rmSync(path.join(f.repo, 'terratrust.modules.lock.json'));
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    git(['add', '.']); git(['commit', '-qm', 'update module lock']);
    const { GitSource } = await import('./source.js');
    expect(evaluateRoot(new GitSource(f.repo, base, f.cache), 'infra/prod').instances[0].attrs.bucket).toBe('logs');
    expect(evaluateRoot(new GitSource(f.repo, 'HEAD', f.cache), 'infra/prod').instances[0].attrs.bucket).toBe('other');
    const out = path.join(f.dir, 'replay'); expect((await f.run('replay', '--repo', f.repo, '--commit', 'HEAD', '--module-cache', f.cache, '--out-dir', out)).exit).toBe(0);
    const report = JSON.parse(fs.readFileSync(path.join(out, git(['rev-parse', '--short=9', 'HEAD']) + '.json'), 'utf8'));
    expect(report.roots[0].root).toBe('infra/prod'); expect(report.roots[0].result.changes[0].action).toBe('replace');
    const absent = path.join(f.dir, 'absent-replay');
    expect((await f.run('replay', '--repo', f.repo, '--commit', 'HEAD', '--module-cache', path.join(f.dir, 'missing-cache'), '--out-dir', absent)).exit).toBe(0);
    expect(JSON.parse(fs.readFileSync(path.join(absent, git(['rev-parse', '--short=9', 'HEAD']) + '.json'), 'utf8')).combined.gate.result).toBe('review');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('check-app can grant access through IAM and compute defined by a cached module', async () => {
  const f = setup();
  try {
    fs.appendFileSync(path.join(f.remote, 'main.tf'), `\nresource "aws_iam_role" "r" {\n name="worker"\n assume_role_policy="{}"\n}\nresource "aws_iam_role_policy" "p" {\n role=aws_iam_role.r.name\n policy=jsonencode({Statement=[{Effect="Allow",Action="s3:GetObject",Resource="arn:aws:s3:::logs/*"}]})\n}\nresource "aws_lambda_function" "f" {\n function_name="worker"\n role=aws_iam_role.r.arn\n environment {\n variables={DATA_BUCKET=var.name}\n }\n}\n`);
    f.git(['add', '.']); f.git(['commit', '-qm', 'iam and compute']); f.write(f.source.replace('?ref=v1.2.0', ''));
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    fs.writeFileSync(path.join(f.repo, 'app.ts'), 'import {GetObjectCommand} from "@aws-sdk/client-s3"; new GetObjectCommand({Bucket:process.env.DATA_BUCKET,Key:"x"});\n');
    const out = path.join(f.dir, 'app.json');
    const r = await f.run('check-app', '--app', f.repo, '--worktree', '--module-cache', f.cache, '--json', out);
    expect(r.exit).toBe(0);
    expect(JSON.parse(fs.readFileSync(out, 'utf8')).links[0].status).toBe('GRANTED');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

for (const [constraint, expected] of [['~> 1.2.0', '1.2.9'], ['~> 1.2', '1.3.0'], ['>= 1.2, < 2, != 1.3.0', '1.2.9'], ['1.2.0', '1.2.0'], ['= 2.0.0-beta.2', '2.0.0-beta.2'], ['', '2.0.0']] as const) test(`registry constraint ${constraint || 'unconstrained'} chooses ${expected}`, async () => {
  const f = setup();
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/.well-known/terraform.json') return Response.json({ 'modules.v1': '/modules/' });
    if (url.pathname.endsWith('/versions')) return Response.json({ modules: [{ versions: ['1.2.0', '1.2.9', '1.3.0', '2.0.0-beta.2', '2.0.0-beta.11', '2.0.0'].map((version) => ({ version })) }] });
    return new Response(null, { status: 204, headers: { 'X-Terraform-Get': f.source } });
  } });
  try {
    f.write(`127.0.0.1:${server.port}/example/bucket/aws`, constraint);
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    expect(JSON.parse(fs.readFileSync(path.join(f.repo, 'terratrust.modules.lock.json'), 'utf8')).modules[0].version).toBe(expected);
  } finally { server.stop(true); fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('unsafe registry archives fail without writing a lock or extracting files', async () => {
  const f = setup(), archive = path.join(f.dir, 'unsafe.tgz');
  fs.symlinkSync('../outside', path.join(f.remote, 'link'));
  expect(spawnSync('tar', ['-czf', archive, '-C', f.remote, 'main.tf', 'link']).status).toBe(0);
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/.well-known/terraform.json') return Response.json({ 'modules.v1': '/modules/' });
    if (url.pathname.endsWith('/versions')) return Response.json({ modules: [{ versions: [{ version: '1.0.0' }] }] });
    if (url.pathname === '/unsafe.tgz') return new Response(Bun.file(archive));
    return new Response(null, { status: 204, headers: { 'X-Terraform-Get': '/unsafe.tgz' } });
  } });
  try {
    f.write(`127.0.0.1:${server.port}/example/bucket/aws`);
    const result = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(result.exit).toBe(1); expect(result.stderr).toContain('links and special files');
    expect(fs.existsSync(path.join(f.repo, 'terratrust.modules.lock.json'))).toBe(false);
    expect(fs.existsSync(path.join(f.dir, 'outside'))).toBe(false);
  } finally { server.stop(true); fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('fetch rejects nonliteral module sources rather than writing an empty lock', async () => {
  const f = setup();
  try {
    fs.writeFileSync(path.join(f.repo, 'main.tf'), 'module "dynamic" { source=var.module_source }');
    const result = await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache);
    expect(result.exit).toBe(1); expect(result.stderr).toContain('literal module source');
    expect(fs.existsSync(path.join(f.repo, 'terratrust.modules.lock.json'))).toBe(false);
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('cache visibility changes cover counted module instances without lifecycle claims', async () => {
  const { compareEvaluations } = await import('./compare.js'); const f = setup();
  try {
    f.write(f.source);
    const file = path.join(f.repo, 'main.tf'); fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('name="logs"', 'count=2\n name="logs"'));
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    const opaque = evaluateRoot(new FsSource(f.repo), '.'), known = evaluateRoot(new FsSource(f.repo, f.cache), '.');
    for (const changes of [compareEvaluations(opaque, known), compareEvaluations(known, opaque)]) { expect(changes.map((c) => c.action)).toEqual(['update']); expect(changes[0].confidence).toBe('unknown'); }
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('an unknown version expression cannot reuse an unconstrained lock', async () => {
  const f = setup();
  try {
    f.write(f.source); expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    const file = path.join(f.repo, 'main.tf'); fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('name="logs"', 'version=var.version\n name="logs"'));
    expect(evaluateRoot(new FsSource(f.repo, f.cache), '.').instances[0].type).toBe('terraform_module_call');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('a locked registry version must satisfy the declared constraint', async () => {
  const f = setup();
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/.well-known/terraform.json') return Response.json({ 'modules.v1': '/modules/' });
    if (url.pathname.endsWith('/versions')) return Response.json({ modules: [{ versions: [{ version: '1.2.0' }] }] });
    return new Response(null, { status: 204, headers: { 'X-Terraform-Get': f.source } });
  } });
  try {
    f.write(`127.0.0.1:${server.port}/example/bucket/aws`, '~> 1.2.0');
    expect((await f.run('modules', 'fetch', '--repo', f.repo, '--cache', f.cache)).exit).toBe(0);
    const file = path.join(f.repo, 'terratrust.modules.lock.json'), lock = JSON.parse(fs.readFileSync(file, 'utf8'));
    lock.modules[0].version = '2.0.0'; fs.writeFileSync(file, JSON.stringify(lock));
    expect(() => evaluateRoot(new FsSource(f.repo, f.cache), '.')).toThrow('No module version matches');
  } finally { server.stop(true); fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test('an ordinary local module directory can use the cache namespace name without a cache', () => {
  const f = setup();
  try {
    const module = path.join(f.repo, '__terratrust_modules/local'); fs.mkdirSync(module, { recursive: true }); fs.writeFileSync(path.join(module, 'main.tf'), fixture.module);
    f.write('./__terratrust_modules/local');
    expect(evaluateRoot(new FsSource(f.repo), '.').instances[0].attrs.bucket).toBe('logs');
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});
