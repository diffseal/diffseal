import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { checkApp } from './checkApp.js';

const INFRA = `terraform {
  backend "s3" {}
}
resource "aws_sns_topic" "t" {
  name = "events"
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.r.name
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["sns:Publish"], Resource = [aws_sns_topic.t.arn] }] })
}
resource "aws_lambda_function" "f" {
  function_name = "f"
  role          = aws_iam_role.r.arn
  environment {
    variables = { TOPIC_ARN = aws_sns_topic.t.arn }
  }
}
`;

describe('checkApp', () => {
  test('worktree with a base checks uncommitted and untracked changes since the base', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-app-'));
    const git = (...args: string[]) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
    git('init', '-q');
    fs.mkdirSync(path.join(dir, 'infra'));
    fs.writeFileSync(path.join(dir, 'infra/main.tf'), INFRA);
    fs.writeFileSync(path.join(dir, 'app.ts'), `import { PublishCommand } from '@aws-sdk/client-sns';\nexport const a = 1;\n`);
    git('add', '-A');
    git('commit', '-qm', 'base');
    // Uncommitted edit to a tracked file, and a new untracked file.
    fs.appendFileSync(path.join(dir, 'app.ts'), `await sns.send(new PublishCommand({ TopicArn: process.env.TOPIC_ARN, Message: 'x' }));\n`);
    fs.writeFileSync(
      path.join(dir, 'new.ts'),
      `import { DeleteTopicCommand } from '@aws-sdk/client-sns';\nawait sns.send(new DeleteTopicCommand({ TopicArn: process.env.TOPIC_ARN }));\n`
    );
    const r = await checkApp({ app: dir, worktree: true, base: 'HEAD' });
    const byAction = Object.fromEntries(r.links.map((l) => [l.actions.join(','), l.status]));
    expect(byAction).toEqual({ 'sns:Publish': 'GRANTED', 'sns:DeleteTopic': 'NOT_GRANTED' });
    expect(r.gate.result).toBe('review');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('worktree with a base works when the app is a subdirectory of the repository (round 2)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-app-sub-'));
    const git = (...args: string[]) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
    git('init', '-q');
    fs.mkdirSync(path.join(dir, 'infra'));
    fs.mkdirSync(path.join(dir, 'services/orders'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'infra/main.tf'), INFRA);
    fs.writeFileSync(path.join(dir, 'services/orders/app.ts'), `import { DeleteTopicCommand } from '@aws-sdk/client-sns';\nexport const a = 1;\n`);
    git('add', '-A');
    git('commit', '-qm', 'base');
    fs.appendFileSync(path.join(dir, 'services/orders/app.ts'), `await sns.send(new DeleteTopicCommand({ TopicArn: process.env.TOPIC_ARN }));\n`);
    const r = await checkApp({ app: path.join(dir, 'services/orders'), infra: dir, worktree: true, base: 'HEAD' });
    expect(r.links.map((l) => l.status)).toEqual(['NOT_GRANTED']);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('with a base, link settings in .terratrust.json come from the base, and a change to them is flagged (round 3)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-app-link-'));
    const git = (...args: string[]) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
    git('init', '-q');
    fs.mkdirSync(path.join(dir, 'infra'));
    fs.writeFileSync(path.join(dir, 'infra/main.tf'), INFRA);
    fs.writeFileSync(path.join(dir, '.terratrust.json'), JSON.stringify({ roles: ['r'] }));
    fs.writeFileSync(path.join(dir, 'app.ts'), `import { GetQueueUrlCommand } from '@aws-sdk/client-sqs';\nexport const a = 1;\n`);
    git('add', '-A');
    git('commit', '-qm', 'base');
    // The pull request claims QUEUE_URL is set outside Terraform and switches to a role it likes.
    fs.writeFileSync(path.join(dir, '.terratrust.json'), JSON.stringify({ roles: ['other'], env: ['QUEUE_URL'] }));
    fs.appendFileSync(path.join(dir, 'app.ts'), `console.log(process.env.QUEUE_URL);\n`);
    git('add', '-A');
    git('commit', '-qm', 'pr');
    const r = await checkApp({ app: dir, rev: 'HEAD', base: 'HEAD~1' });
    expect(r.link.roles).toEqual(['r']);
    expect(r.link.env).toEqual([]);
    expect(r.gate.result).toBe('review');
    expect(r.notes.join(' ')).toContain('.terratrust.json changed');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
