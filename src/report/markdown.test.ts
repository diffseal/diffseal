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
