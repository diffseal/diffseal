import { describe, expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { renderMarkdown } from './markdown.js';

describe('renderMarkdown', () => {
  test('for_each addresses with quotes do not break the table (audit R2)', () => {
    const r = analyze(readPlan(plan([rc('aws_s3_bucket.this["a|b"]', 'aws_s3_bucket', ['create'], { bucket: 'x' })])));
    const md = renderMarkdown(r, { title: 'Plan review' });
    expect(md).toContain('aws_s3_bucket.this["a|b"]');
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
    expect(md.split('\n')[0]).toBe('## TerraTrust: BLOCK');
    expect(md).toContain('> [!CAUTION]');
    const callout = md.split('\n').filter((l) => l.startsWith('>'));
    expect(callout.some((l) => l.includes('`aws_db_instance.db`'))).toBe(true);
    expect(md).not.toContain('**Gate:');
  });

  test('a pass has no callout and no empty summary table', () => {
    const md = renderMarkdown(timeout(), { title: 'Plan' });
    expect(md.split('\n')[0]).toBe('## TerraTrust: PASS');
    expect(md).not.toContain('> [!');
    expect(md).not.toContain('Findings to review');
    expect(md).toContain('1 updated');
  });

  test('a missing permission is a warning callout and the gate reason is not repeated as raw text', () => {
    const md = renderMarkdown(
      { ...timeout(), gate: { result: 'review', reasons: ['NOT_GRANTED: src/h.ts:59: dynamodb:Query on shipments'] } },
      {
        title: 'x',
        appLinks: [
          { status: 'NOT_GRANTED', callsite: 'src/h.ts:59', access: 'dynamodb:Query on shipments', detail: 'role r does not allow dynamodb:Query on shipments' },
          { status: 'GRANTED', callsite: 'src/h.ts:12', access: 'dynamodb:GetItem on shipments', detail: 'role r allows it' },
        ],
      }
    );
    expect(md).toContain('> [!WARNING]');
    expect(md).toContain('> - `src/h.ts:59` needs dynamodb:Query on shipments, but its role does not allow it.');
    expect(md).not.toContain('NOT_GRANTED');
    // Granted calls are evidence, not something to act on, so they are folded away.
    expect(md).toMatch(/<details><summary>1 granted<\/summary>[\s\S]*src\/h\.ts:12[\s\S]*<\/details>/);
  });

  test('other gate reasons appear in the callout as written', () => {
    const r = { ...timeout(), gate: { result: 'review' as const, reasons: ['Terraform changed outside every analyzed root (infra/x/main.tf); it was not checked'] } };
    expect(renderMarkdown(r, { title: 'x' })).toContain('> - Terraform changed outside every analyzed root (infra/x/main.tf); it was not checked');
  });

  test('the footer is one line and counts are not written as "(s)"', () => {
    const md = renderMarkdown(timeout(), { title: 'x', notes: ['First note.', 'Second note.'], version: '9.9.9' });
    expect(md).not.toContain('(s)');
    const footer = md.split('\n').filter((l) => l.includes('<sub>'));
    expect(footer).toEqual(['<sub>TerraTrust 9.9.9. First note. Second note.</sub>']);
  });
});
