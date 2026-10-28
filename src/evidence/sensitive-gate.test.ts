import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { analyze } from '../analysis/analyze.js';
import { analyzeBlastRadius } from '../analysis/blastRadius.js';
import { scrubDeep, type Gate, type Severity } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { combineRoots, replayCommit } from '../replay/replay.js';
import { renderReplay } from '../replay/render.js';
import { renderMarkdown } from '../report/markdown.js';
import { changeRecord } from './changeRecord.js';
import { upsertComment } from '../action/comment.js';
import { uploadRun } from '../action/upload.js';

const fixture = JSON.parse(fs.readFileSync(new URL('../../fixtures/evidence/sensitive-gate.fixture', import.meta.url), 'utf8')) as {
  hidden: string[]; base: string; head: string; plan: unknown;
};
const aligned = (gate: Gate) => gate.items.length === gate.reasons.length && gate.items.every((item, i) => item.text === gate.reasons[i]);
const privateText = (value: unknown) => fixture.hidden.every((secret) => !JSON.stringify(value).includes(secret));

for (const mode of ['plan', 'replay']) for (const blocking of [true, false]) {
  test(`${mode} ${blocking ? 'blocking risk' : 'FAIL control'} stays private in records, comments and upload serialization`, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-sensitive-gate-'));
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
      if (r.status) throw new Error(r.stderr);
    };
    const blockOn: Severity[] = blocking ? ['LOW'] : [];
    try {
      git('init', '-q');
      for (const root of ['prod', 'staging']) { fs.mkdirSync(path.join(dir, root)); fs.writeFileSync(path.join(dir, root, 'main.tf'), fixture.base); }
      git('add', '.'); git('commit', '-qm', 'base');
      for (const root of ['prod', 'staging']) fs.writeFileSync(path.join(dir, root, 'main.tf'), fixture.head);
      git('add', '.'); git('commit', '-qm', 'change');
      const replay = await replayCommit({ repo: dir, head: 'HEAD', policy: { blockOn } });
      // Plan review and replay share the analysis/output boundary. Production plan uploads remain disabled.
      if (mode === 'plan') {
        const changes = readPlan(fixture.plan);
        expect(analyzeBlastRadius(changes).some((row) => fixture.hidden.some((secret) => row.reason.includes(secret)))).toBe(true);
        const result = analyze(changes, { policy: { blockOn } });
        expect(privateText(renderMarkdown(result, {}))).toBe(true);
        replay.roots = ['prod', 'staging'].map((root) => ({ root, changes, result, diagnostics: [] }));
        replay.combined = combineRoots(replay.roots);
      }
      expect(replay.combined.gate.result).toBe(blocking ? 'block' : 'review');
      expect(replay.combined.findings.some((f) => f.status === 'FAIL' && f.detail.includes('(sensitive)'))).toBe(true);
      for (const root of replay.roots) expect(aligned(root.result.gate)).toBe(true);
      expect(aligned(replay.combined.gate)).toBe(true);
      expect(replay.combined.gate.items.some((item) => item.kind === (blocking ? 'risk' : 'control'))).toBe(true);
      expect(replay.combined.gate.items.every((item) => item.text.startsWith('prod, staging: '))).toBe(true);
      const record = changeRecord({ commit: replay.commit, base: replay.base, roots: replay.roots.map((r) => r.root), result: replay.combined, appLinks: replay.appLinks, engine: { version: 'test', replaceCatalog: 'test' } });
      expect(privateText(record)).toBe(true);
      const comment = renderReplay(replay, { commit: false });
      expect(privateText(comment)).toBe(true);
      await upsertComment(comment, { api: 'https://github.example', repo: 'o/r', pr: 1, token: 'test', author: 'bot', fetchFn: (async (_url, init) => {
        if (!init?.method) return Response.json([]);
        expect(privateText(String(init.body))).toBe(true);
        return Response.json({});
      }) as typeof fetch });
      let uploaded = false;
      const response = await uploadRun({ mode: 'pr', upload: 'true', eventName: 'push', advisory: true, replay, env: { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'test' }, fetchFn: (async (_url, init) => {
        if (!init?.method) return Response.json({ value: 'test-oidc' });
        uploaded = true;
        expect(privateText(String(init.body))).toBe(true);
        const body = JSON.parse(String(init.body));
        expect(aligned(body.record.gate)).toBe(true);
        return Response.json({ id: 'test-run', pageUrl: 'https://api.diffseal.com/test-run' });
      }) as typeof fetch });
      expect(uploaded).toBe(true); expect(response?.id).toBe('test-run');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
}

test('scrubbing analysis keeps unrelated raw text fields intact', () => {
  const value = fixture.hidden[0];
  const clean = scrubDeep({ text: value, reason: value }, [value]);
  expect(clean.text === value).toBe(true); expect(clean.reason).toBe('(sensitive)');
});

for (const expires of ['2020-01-01', 'malformed']) {
  test(`sensitive ${expires === 'malformed' ? 'malformed' : 'expired'} exceptions keep item text aligned`, () => {
    const expiry = '2020-01-01';
    const plan = structuredClone(fixture.plan) as { resource_changes: unknown[] };
    plan.resource_changes.push({ address: 'aws_ssm_parameter.expiry', type: 'aws_ssm_parameter', name: 'expiry', mode: 'managed', change: { actions: ['create'], before: null, after: { name: 'expiry', type: 'SecureString', value: expiry }, after_sensitive: { value: true } } });
    const result = analyze(readPlan(plan), { now: new Date('2026-10-27'), policy: { blockOn: [], exceptions: [{ rule: 'network.open-ingress', resource: 'aws_security_group_rule.ssh', expires, reason: 'fixture' }] } });
    expect(result.gate.items.some((item) => item.kind === 'exception')).toBe(true);
    expect(aligned(result.gate)).toBe(true);
    expect(JSON.stringify(result.gate).includes(expiry)).toBe(false);
    if (expires !== 'malformed') expect(result.gate.items.some((item) => item.kind === 'exception' && item.text.includes('(sensitive)'))).toBe(true);
  });
}

test('check-app builds aligned access items from already scrubbed links', async () => {
  const { checkApp } = await import('../app/checkApp.js');
  const { renderAppCheck } = await import('../report/appCheck.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-private-app-gate-'));
  const topic = 'arn:aws:sns:eu-west-1:111122223333:fixture-private-topic';
  try {
    const init = spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' }); if (init.status) throw new Error(init.stderr);
    fs.writeFileSync(path.join(dir, 'main.tf'), `terraform {
  backend "s3" {}
}
resource "aws_iam_role" "r" {
  name = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.r.name
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["sns:Subscribe"], Resource = "*" }] })
}
resource "aws_lambda_function" "f" {
  function_name = "f"
  role = aws_iam_role.r.arn
  environment {
    variables = { TOPIC_ARN = sensitive("${topic}") }
  }
}
`);
    fs.writeFileSync(path.join(dir, 'app.ts'), `import { PublishCommand } from '@aws-sdk/client-sns';\nawait sns.send(new PublishCommand({ TopicArn: process.env.TOPIC_ARN, Message: 'fixture' }));\n`);
    const result = await checkApp({ app: dir, worktree: true, roles: ['r'] });
    expect(result.gate.items.some((item) => item.kind === 'access')).toBe(true);
    expect(aligned(result.gate)).toBe(true);
    expect(JSON.stringify(result.gate).includes(topic)).toBe(false);
    expect(renderAppCheck(result).includes(topic)).toBe(false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
