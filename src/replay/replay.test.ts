import { describe, expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { renderMarkdown } from '../report/markdown.js';
import { combineRoots, replayCommit, shortRootLabels } from './replay.js';

describe('combineRoots', () => {
  const result = () => analyze(readPlan(plan([rc('module.svc.aws_sns_topic.t', 'aws_sns_topic', ['create'], { name: 't' })])));

  test('labels roots by the path segments that differ', async () => {
    expect(shortRootLabels(['infra/envs/prod/svc', 'infra/envs/sandbox/svc'])).toEqual({
      'infra/envs/prod/svc': 'prod',
      'infra/envs/sandbox/svc': 'sandbox',
    });
    expect(shortRootLabels(['infra/envs/prod/a', 'infra/envs/prod/b', 'infra/envs/sandbox/a'])).toEqual({
      'infra/envs/prod/a': 'prod/a',
      'infra/envs/prod/b': 'prod/b',
      'infra/envs/sandbox/a': 'sandbox/a',
    });
  });

  test('identical findings in two environments become one row', async () => {
    const merged = combineRoots([
      { root: 'infra/envs/prod/svc', changes: [], result: result(), diagnostics: [] },
      { root: 'infra/envs/sandbox/svc', changes: [], result: result(), diagnostics: [] },
    ]);
    const warn = merged.findings.filter((f) => f.ruleId === 'sns.encryption');
    expect(warn.map((f) => f.resource)).toEqual(['prod, sandbox: module.svc.aws_sns_topic.t']);
    expect(merged.blast.map((b) => b.resource)).toEqual(['prod, sandbox: module.svc.aws_sns_topic.t']);
    expect(merged.changes.length).toBe(2);
  });

  test('a merged row keeps the confidence of its change (review of the footer change)', async () => {
    const likely = () => analyze(readPlan(plan([rc('module.svc.aws_sns_topic.t', 'aws_sns_topic', ['create'], { name: 't' })])).map((c) => ({ ...c, confidence: 'likely' as const })));
    const merged = combineRoots([
      { root: 'infra/envs/prod/svc', changes: [], result: likely(), diagnostics: [] },
      { root: 'infra/envs/sandbox/svc', changes: [], result: likely(), diagnostics: [] },
    ]);
    expect(merged.blast.map((b) => [b.resource, b.confidence])).toEqual([['prod, sandbox: module.svc.aws_sns_topic.t', 'likely']]);
    expect(renderMarkdown(merged, { title: 'x' })).toContain('| `prod, sandbox: module.svc.aws_sns_topic.t` | create (likely) |');
  });
});

describe('replayCommit', () => {
  const OPEN_PORT =
    'resource "aws_vpc_security_group_ingress_rule" "devices" {\n  security_group_id = "sg-1"\n  cidr_ipv4 = "0.0.0.0/0"\n  from_port = 25004\n  to_port = 25004\n  ip_protocol = "tcp"\n}\n';
  const EXCEPTION = JSON.stringify({ exceptions: [{ rule: 'network.open-ingress', resource: 'aws_vpc_security_group_ingress_rule.devices', reason: 'devices', expires: '2099-01-01' }] });

  function repo() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-replay-'));
    const git = (...args: string[]) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
    git('init', '-q');
    const commit = (files: Record<string, string>, msg: string) => {
      for (const [f, c] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.writeFileSync(path.join(dir, f), c);
      }
      git('add', '-A');
      git('commit', '-qm', msg);
    };
    return { dir, commit, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
  }

  test('exceptions already on the base branch apply to the change', async () => {
    const r = repo();
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n', '.diffseal.json': EXCEPTION }, 'base with exception');
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n' + OPEN_PORT }, 'open port');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.findings.find((f) => f.ruleId === 'network.open-ingress')?.accepted?.reason).toBe('devices');
    expect(result.combined.gate.result).toBe('pass');
    r.done();
  });

  test('a commit from before the rename to Diffseal still reads its .terratrust.json exceptions', async () => {
    const r = repo();
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n', '.terratrust.json': EXCEPTION }, 'base with exception under the old name');
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n' + OPEN_PORT }, 'open port');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.findings.find((f) => f.ruleId === 'network.open-ingress')?.accepted?.reason).toBe('devices');
    expect(result.combined.gate.result).toBe('pass');
    r.done();
  });

  test('a change cannot accept its own findings: exceptions it adds apply only after merge, and the change is reviewed', async () => {
    const r = repo();
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n' }, 'base');
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n' + OPEN_PORT, '.diffseal.json': EXCEPTION }, 'open port and accept it');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.findings.find((f) => f.ruleId === 'network.open-ingress')?.accepted).toBeUndefined();
    expect(result.combined.gate.result).toBe('review');
    expect(result.combined.gate.reasons.join(' ')).toContain('.diffseal.json');
    r.done();
  });

  test('editing only a policy file a module reads with file() still replays the root', async () => {
    const r = repo();
    const tf = 'terraform {\n  backend "s3" {}\n}\nresource "aws_iam_policy" "p" {\n  name   = "p"\n  policy = file("${path.module}/policy.json")\n}\n';
    r.commit({ 'main.tf': tf, 'policy.json': JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }) }, 'base');
    r.commit({ 'policy.json': JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }) }, 'widen');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => `${c.action} ${c.address}`)).toEqual(['update aws_iam_policy.p']);
    expect(result.combined.gate.result).toBe('review');
    r.done();
  });

  test('a directory with resources that nothing calls is evaluated as a root', async () => {
    const r = repo();
    r.commit({ 'README.md': 'x' }, 'base');
    r.commit({ 'loose/main.tf': 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n' }, 'no backend anywhere');
    expect((await replayCommit({ repo: r.dir, head: 'HEAD' })).roots.map((x) => x.root)).toEqual(['loose']);
    r.done();
  });

  test('Terraform changed outside the analyzed roots is reviewed, not passed (review batch 4)', async () => {
    const r = repo();
    r.commit({ 'README.md': 'x' }, 'base');
    r.commit({ 'infra/prod/main.tf': 'terraform {\n  backend "s3" {}\n}\nresource "aws_sqs_queue" "q" {\n  name = "q"\n}\n' }, 'change');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD', rootsUnder: 'elsewhere' });
    expect(result.combined.gate.result).toBe('review');
    expect(result.combined.gate.reasons.join(' ')).toContain('infra/prod/main.tf');
    r.done();
  });

  test('a Terragrunt directory is a root', async () => {
    const r = repo();
    r.commit({ 'live/prod/terragrunt.hcl': 'terraform {\n  source = "../../modules/x"\n}\n', 'live/prod/main.tf': '' }, 'base');
    r.commit({ 'live/prod/main.tf': 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n' }, 'add queue');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.roots.map((x) => x.root)).toEqual(['live/prod']);
    r.done();
  });

  test('a policy file inside the repository is read from the base, and changing it is reviewed (round 2, P1)', async () => {
    const r = repo();
    const strict = JSON.stringify({ blockOn: ['CRITICAL'] });
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\nresource "aws_dynamodb_table" "t" {\n  name = "t"\n  hash_key = "id"\n}\n', 'ci/policy.json': strict }, 'base');
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n', 'ci/policy.json': JSON.stringify({ blockOn: [] }) }, 'delete table and disable blocking');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD', policyFile: 'ci/policy.json' });
    expect(result.combined.gate.result).toBe('block');
    expect(result.combined.gate.reasons.join(' ')).toContain('ci/policy.json');
    r.done();
  });

  test('exceptions are judged on the date of the replayed change, not today (round 2)', async () => {
    const r = repo();
    const exp = JSON.stringify({ exceptions: [{ rule: 'network.open-ingress', resource: 'aws_vpc_security_group_ingress_rule.devices', reason: 'devices', expires: '2000-06-01' }] });
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n', '.diffseal.json': exp }, 'base');
    spawnSync('git', ['-C', r.dir, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '--allow-empty', '-qm', 'noop']);
    fs.writeFileSync(path.join(r.dir, 'main.tf'), 'terraform {\n  backend "s3" {}\n}\n' + OPEN_PORT);
    spawnSync('git', ['-C', r.dir, 'add', '-A']);
    spawnSync('git', ['-C', r.dir, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'open port in 2000'], { env: { ...process.env, GIT_AUTHOR_DATE: '2000-01-15T12:00:00Z', GIT_COMMITTER_DATE: '2000-01-15T12:00:00Z' } });
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.gate.result).toBe('pass');
    r.done();
  });

  test('inputs static replay does not evaluate (terragrunt inputs, -var-file tfvars) are reviewed (round 2)', async () => {
    const r = repo();
    r.commit({ 'live/terragrunt.hcl': 'inputs = {\n  deletion_protection = true\n}\n', 'envs/prod.tfvars': 'x = 1\n', 'README.md': 'x' }, 'base');
    r.commit({ 'live/terragrunt.hcl': 'inputs = {\n  deletion_protection = false\n}\n', 'envs/prod.tfvars': 'x = 2\n' }, 'change inputs');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.gate.result).toBe('review');
    expect(result.combined.gate.reasons.join(' ')).toContain('live/terragrunt.hcl');
    expect(result.combined.gate.reasons.join(' ')).toContain('envs/prod.tfvars');
    r.done();
  });

  test('a policy file read from a directory without Terraform still replays the root that reads it (round 2)', async () => {
    const r = repo();
    const tf = 'terraform {\n  backend "s3" {}\n}\nresource "aws_iam_policy" "p" {\n  name   = "p"\n  policy = file("${path.module}/../policies/app.json")\n}\n';
    r.commit({ 'infra/main.tf': tf, 'policies/app.json': JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }) }, 'base');
    r.commit({ 'policies/app.json': JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }) }, 'widen');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => `${c.action} ${c.address}`)).toEqual(['update aws_iam_policy.p']);
    r.done();
  });

  test('a live check judges exceptions now, not on the commit date (round 2 codex)', async () => {
    const r = repo();
    const exp = JSON.stringify({ exceptions: [{ rule: 'network.open-ingress', resource: 'aws_vpc_security_group_ingress_rule.devices', reason: 'devices', expires: '2026-06-01' }] });
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\n', '.diffseal.json': exp }, 'base');
    fs.writeFileSync(path.join(r.dir, 'main.tf'), 'terraform {\n  backend "s3" {}\n}\n' + OPEN_PORT);
    spawnSync('git', ['-C', r.dir, 'add', '-A']);
    // A backdated commit: judged on its own date the exception is live, judged now it has expired.
    spawnSync('git', ['-C', r.dir, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'open port'], { env: { ...process.env, GIT_AUTHOR_DATE: '2026-01-15T12:00:00Z', GIT_COMMITTER_DATE: '2026-01-15T12:00:00Z' } });
    expect((await replayCommit({ repo: r.dir, head: 'HEAD' })).combined.gate.result).toBe('pass');
    const live = await replayCommit({ repo: r.dir, head: 'HEAD', now: new Date('2026-10-25') });
    expect(live.combined.gate.result).toBe('review');
    r.done();
  });

  test('a root that stops managing its last resource with removed { destroy = false } forgets it (round 4 codex)', async () => {
    const r = repo();
    const head = 'terraform {\n  backend "s3" {}\n}\n';
    r.commit({ 'main.tf': `${head}resource "aws_dynamodb_table" "t" {\n  name         = "orders"\n  hash_key     = "id"\n  billing_mode = "PAY_PER_REQUEST"\n  attribute {\n    name = "id"\n    type = "S"\n  }\n}\n` }, 'base');
    r.commit({ 'main.tf': `${head}removed {\n  from = aws_dynamodb_table.t\n  lifecycle {\n    destroy = false\n  }\n}\n` }, 'forget');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => c.action)).not.toContain('delete');
    expect(result.combined.gate.result).not.toBe('block');
    r.done();
  });

  test('a change to terraform.tfvars.json alone replays the root (round 3 codex P1)', async () => {
    const r = repo();
    const tf = 'terraform {\n  backend "s3" {}\n}\nvariable "tables" {\n  type = list(string)\n}\nresource "aws_dynamodb_table" "t" {\n  for_each     = toset(var.tables)\n  name         = each.key\n  hash_key     = "id"\n  billing_mode = "PAY_PER_REQUEST"\n  attribute {\n    name = "id"\n    type = "S"\n  }\n}\n';
    r.commit({ 'main.tf': tf, 'terraform.tfvars.json': JSON.stringify({ tables: ['orders', 'users'] }) }, 'base');
    r.commit({ 'terraform.tfvars.json': JSON.stringify({ tables: ['users'] }) }, 'drop orders');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => `${c.action} ${c.address}`)).toEqual(['delete aws_dynamodb_table.t["orders"]']);
    expect(result.combined.gate.result).toBe('block');
    r.done();
  });

  test('a file read only through filesha256() or filebase64sha256() is tracked (round 3)', async () => {
    const r = repo();
    const tf = 'terraform {\n  backend "s3" {}\n}\nresource "aws_lambda_function" "f" {\n  function_name    = "f"\n  role             = "r"\n  filename         = "fn.zip"\n  source_code_hash = filebase64sha256("${path.module}/fn.zip")\n  tags             = { h = filesha256("${path.module}/fn.zip") }\n}\n';
    r.commit({ 'main.tf': tf, 'fn.zip': 'build-one' }, 'base');
    r.commit({ 'fn.zip': 'build-two' }, 'new build');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => `${c.action} ${c.address}`)).toEqual(['update aws_lambda_function.f']);
    expect(JSON.stringify(result.combined.changes)).not.toContain('build-');
    r.done();
  });

  test('Terraform that does not parse at head is reviewed, naming file and line (round 3)', async () => {
    const r = repo();
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\nresource "aws_sqs_queue" "q" {\n  name = "q"\n}\n' }, 'base');
    r.commit({ 'main.tf': 'terraform {\n  backend "s3" {}\n}\nresource "aws_sqs_queue" "q" {\n  name = "q"\n  tags = {\n}\n' }, 'broken');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.gate.result).toBe('review');
    expect(result.combined.gate.reasons.join(' ')).toMatch(/main\.tf:\d+/);
    r.done();
  });

  test('a file Terraform reads is tracked even when it is application code (round 2 codex)', async () => {
    const r = repo();
    const tf = 'terraform {\n  backend "s3" {}\n}\nresource "aws_instance" "i" {\n  ami       = "ami-1"\n  user_data = file("bootstrap.py")\n}\n';
    r.commit({ 'main.tf': tf, 'bootstrap.py': 'print(1)\n' }, 'base');
    r.commit({ 'bootstrap.py': 'print(2)\n' }, 'change bootstrap');
    const result = await replayCommit({ repo: r.dir, head: 'HEAD' });
    expect(result.combined.changes.map((c) => `${c.action} ${c.address}`)).toEqual(['update aws_instance.i']);
    r.done();
  });
});
