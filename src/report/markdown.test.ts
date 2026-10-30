import { describe, expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { cell, renderMarkdown } from './markdown.js';

describe('renderMarkdown', () => {
  test.each([
    { status: 'FAIL' as const },
    { status: 'PASS' as const },
    { status: 'UNKNOWN' as const },
    { status: 'INFO' as const },
    { status: 'FAIL' as const, preExisting: true },
    { status: 'WARN' as const, accepted: { reason: 'Migration', expires: '2026-12-31' } },
  ])('PR comment and job summary controls show SOC 2 alongside ISO for $status findings', (state) => {
    const result = analyze(readPlan(plan([])));
    result.findings = [{
      ruleId: 'rds.encryption', title: 'RDS storage encryption', resource: 'aws_db_instance.db',
      controls: ['ISO27001:A.8.24', 'SOC2:CC6.1'], detail: 'Storage encryption checked', ...state,
    }];
    const markdown = renderMarkdown(result, {});
    expect(markdown).toContain('| A.8.24, SOC 2 CC6.1 |');
    const row = markdown.split('\n').find((line) => line.includes('| RDS storage encryption |'))!;
    expect(row.split(' | ')).toHaveLength(5);
  });

  test('existing findings with only ISO controls still render', () => {
    const result = analyze(readPlan(plan([])));
    result.findings = [{
      ruleId: 'rds.encryption', title: 'Legacy encryption check', status: 'PASS', resource: 'aws_db_instance.db',
      controls: ['ISO27001:A.8.24'], detail: 'Storage encrypted',
    }];
    expect(renderMarkdown(JSON.parse(JSON.stringify(result)), {})).toContain('| A.8.24 |');
  });

  test('for_each addresses with quotes do not break the table (audit R2)', () => {
    const r = analyze(readPlan(plan([rc('aws_s3_bucket.this["a|b"]', 'aws_s3_bucket', ['create'], { bucket: 'x' })])));
    const md = renderMarkdown(r, { title: 'Plan review' });
    // GFM splits table cells on a pipe even inside a code span, so it is escaped.
    expect(md).toContain('aws_s3_bucket.this["a\\|b"]');
    expect(md).not.toContain('mermaid');
    const changeRow = md.split('\n').find((l) => l.includes('aws_s3_bucket.this'))!;
    expect(changeRow.split(' | ').length).toBe(4);
  });

  test('does not claim ISO readiness', () => {
    const r = analyze(readPlan(plan([rc('aws_sqs_queue.q', 'aws_sqs_queue', ['create'], { name: 'q' })])));
    const md = renderMarkdown(r, { title: 'Plan review' });
    expect(md).not.toMatch(/ISO.{0,20}Ready/i);
  });

  test('stays under the GitHub comment limit for a large plan (audit R4)', () => {
    const many = Array.from({ length: 2000 }, (_, i) => rc(`aws_s3_bucket.b${i}`, 'aws_s3_bucket', ['create'], { bucket: `b${i}` }));
    const md = renderMarkdown(analyze(readPlan(plan(many))), { title: 'Plan review' });
    expect(md.length).toBeLessThan(65_536);
  });

  test('never prints sensitive values', () => {
    const r = analyze(
      readPlan(plan([rc('aws_lambda_function.f', 'aws_lambda_function', ['create'], { environment: [{ variables: { DB_PASSWORD: 'hunter2' } }] }, { afterSensitive: { environment: [{ variables: { DB_PASSWORD: true } }] } })]))
    );
    expect(renderMarkdown(r, { title: 'x' })).not.toContain('hunter2');
  });
});

describe('report layout', () => {
  const replaceDb = () =>
    analyze(readPlan(plan([rc('aws_db_instance.db', 'aws_db_instance', ['delete', 'create'], { storage_encrypted: true }, { before: { storage_encrypted: false }, replacePaths: [['storage_encrypted']] })])));
  const timeout = () =>
    analyze(readPlan(plan([rc('aws_lambda_function.f', 'aws_lambda_function', ['update'], { timeout: 30 }, { before: { timeout: 15 } })])));

  test('the heading names the gate and a blocking change sits in a caution callout', () => {
    const r = replaceDb();
    expect(r.gate.result).toBe('block');
    const md = renderMarkdown(r, { title: 'Plan `tfplan.json`' });
    expect(md.split('\n')[0]).toBe('## Diffseal: BLOCK');
    expect(md).toContain('> [!CAUTION]');
    const callout = md.split('\n').filter((l) => l.startsWith('>'));
    expect(callout.some((l) => l.includes('`aws_db_instance.db`'))).toBe(true);
    expect(md).not.toContain('**Gate:');
  });

  test('a pass has no callout and no empty summary table', () => {
    const md = renderMarkdown(timeout(), { title: 'Plan' });
    expect(md.split('\n')[0]).toBe('## Diffseal: PASS');
    expect(md).not.toContain('> [!');
    expect(md).not.toContain('Findings to review');
    expect(md).toContain('1 updated');
  });

  test('other gate reasons appear in the callout as written', () => {
    const r = { ...timeout(), gate: { items: [], result: 'review' as const, reasons: ['Terraform changed outside every analyzed root (infra/x/main.tf); it was not checked'] } };
    expect(renderMarkdown(r, { title: 'x' })).toContain('> - Terraform changed outside every analyzed root (infra/x/main.tf); it was not checked');
  });

  test('the footer is one line and counts are not written as "(s)"', () => {
    const md = renderMarkdown(timeout(), { title: 'x', notes: ['First note.', 'Second note.'], version: '9.9.9' });
    expect(md).not.toContain('(s)');
    const footer = md.split('\n').filter((l) => l.includes('<sub>'));
    expect(footer).toEqual(['<sub>Diffseal 9.9.9. First note. Second note. [How it works](https://github.com/diffseal/diffseal/blob/main/docs/guide/faq.md)</sub>']);
  });

  test('the footer leaves general explanations to the FAQ', () => {
    const md = renderMarkdown(replaceDb(), { title: 'x', version: '9.9.9' });
    expect(replaceDb().findings.length).toBeGreaterThan(0);
    expect(md).not.toContain('Annex A');
  });

  test('a change that is likely, not proven, says so in its row', () => {
    const changes = readPlan(plan([rc('aws_lambda_function.f', 'aws_lambda_function', ['update'], { timeout: 30 }, { before: { timeout: 15 } })]));
    const md = renderMarkdown(analyze(changes.map((c) => ({ ...c, confidence: 'likely' as const }))), { title: 'x' });
    expect(md).toContain('| `aws_lambda_function.f` | update (likely) |');
    expect(renderMarkdown(analyze(changes), { title: 'x' })).toContain('| `aws_lambda_function.f` | update |');
    // FAQ: unknown is not likely; the action could not be established.
    const unknown = renderMarkdown(analyze(changes.map((c) => ({ ...c, confidence: 'unknown' as const }))), { title: 'x' });
    expect(unknown).toContain('| `aws_lambda_function.f` | update (unknown) |');
  });
});

describe('report layout edge cases (review of the redesign)', () => {
  const replaceDb = () =>
    analyze(readPlan(plan([rc('aws_db_instance.db', 'aws_db_instance', ['delete', 'create'], { storage_encrypted: true }, { before: { storage_encrypted: false }, replacePaths: [['storage_encrypted']] })])));

  test('reasons labelled with several roots still render as sentences naming the resource', () => {
    const r = replaceDb();
    const b = r.blast.find((x) => x.severity === 'CRITICAL')!;
    const reason = `${b.severity}: ${b.resource}: ${b.reason}`;
    b.resource = `prod, staging: ${b.resource}`;
    r.gate.reasons = [`prod, staging: ${reason}`];
    const callout = renderMarkdown(r, {}).split('\n').filter((l) => l.startsWith('> - '));
    expect(callout).toEqual([`> - prod, staging: \`aws_db_instance.db\`: ${b.reason}`]);
  });

  test('a block that also has review-only reasons does not say every reason is blocked by policy', () => {
    const r = replaceDb();
    r.gate.reasons.push('Terraform changed outside every analyzed root (infra/x/main.tf); it was not checked');
    const md = renderMarkdown(r, {});
    expect(md).toContain('> [!CAUTION]');
    expect(md).not.toContain('Blocked by your policy');
  });

  test('a file path with a line break cannot end the callout', () => {
    const evil = 'infra/a\n## Diffseal: PASS\n.tf';
    const md = renderMarkdown({ ...replaceDb(), gate: { items: [], result: 'review', reasons: [`Terraform changed outside every analyzed root (${evil}); it was not checked`] } }, {});
    expect(md.split('\n').filter((l) => l.startsWith('## '))).toEqual(['## Diffseal: REVIEW']);
  });
});

test('wildcards in resource patterns are not read as Markdown emphasis (review of the redesign)', () => {
  const r = analyze(readPlan(plan([])));
  const pattern = 'secretsmanager:GetSecretValue on provider/*/api-credentials-*';
  const md = renderMarkdown(
    { ...r, gate: { items: [], result: 'review', reasons: [`Review ${pattern}`] } },
    {}
  );
  expect(md).toContain('provider/\\*/api-credentials-\\*');
  expect(md).not.toMatch(/[^\\]\*\/api/);
  // Underscores inside identifiers never form emphasis in GFM, so they stay readable.
  expect(cell('hash_key _x_')).toBe('hash_key \\_x\\_');
});
