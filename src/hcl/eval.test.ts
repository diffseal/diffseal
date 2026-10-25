import { describe, expect, test } from 'bun:test';
import { Unknown, isUnknown } from '../core/model.js';
import { ResourceValue, evaluate, stableKey, type EvalScope } from './eval.js';
import { parseHcl } from './parser.js';

function scope(roots: Record<string, unknown>): EvalScope {
  return { root: (n) => roots[n] };
}

function e(expr: string, roots: Record<string, unknown> = {}) {
  const { body, diagnostics } = parseHcl(`x = ${expr}\n`);
  if (diagnostics.length) throw new Error(diagnostics.map((d) => d.message).join('; '));
  return evaluate(body.attributes[0].expr, scope(roots));
}

const bucket = new ResourceValue('aws_s3_bucket.b', () => ({ bucket: 'exports-prod' }));

describe('evaluate', () => {
  test('templates interpolate known values', () => {
    expect(e('"acme-${var.env}"', { var: { env: 'prod' } })).toBe('acme-prod');
  });

  test('a single interpolation returns the value unconverted', () => {
    expect(e('"${var.n}"', { var: { n: 5 } })).toBe(5);
  });

  test('computed resource attributes are unknown and remember the resource', () => {
    const v = e('aws_s3_bucket.b.arn', { aws_s3_bucket: { b: bucket } });
    expect(isUnknown(v) && v.refs).toEqual(['aws_s3_bucket.b']);
  });

  test('configured resource arguments resolve to their values', () => {
    expect(e('aws_s3_bucket.b.bucket', { aws_s3_bucket: { b: bucket } })).toBe('exports-prod');
  });

  test('a template with an unknown part keeps the known text as a pattern', () => {
    const v = e('"arn:aws:secretsmanager:${local.region}:${local.acct}:secret:provider/*/api-credentials-??????"', {
      local: { region: new Unknown('data source'), acct: new Unknown('data source') },
    });
    expect(isUnknown(v) && v.pattern).toBe('arn:aws:secretsmanager:{?}:{?}:secret:provider/*/api-credentials-??????');
  });

  test('"${arn}/*" on a resource becomes a scoped pattern', () => {
    const v = e('"${aws_s3_bucket.b.arn}/*"', { aws_s3_bucket: { b: bucket } });
    expect(isUnknown(v) && v.pattern).toBe('{?}/*');
  });

  test('concat keeps known and unknown elements apart', () => {
    const v = e('concat(["a"], [aws_s3_bucket.b.arn])', { aws_s3_bucket: { b: bucket } }) as unknown[];
    expect(v[0]).toBe('a');
    expect(isUnknown(v[1])).toBe(true);
  });

  test('jsonencode keeps the object when parts are unknown, so policies stay analyzable', () => {
    const v = e('jsonencode({ Statement = [{ Effect = "Allow", Resource = aws_s3_bucket.b.arn }] })', { aws_s3_bucket: { b: bucket } }) as any;
    expect(v.Statement[0].Effect).toBe('Allow');
  });

  test('jsonencode of known values is a JSON string', () => {
    expect(e('jsonencode({ a = 1 })')).toBe('{"a":1}');
  });

  test('for expressions, conditionals and functions', () => {
    expect(e('[for s in ["a", "b"] : upper(s) if s != "b"]')).toEqual(['A']);
    expect(e('{ for k, v in { x = 1 } : k => v * 2 }')).toEqual({ x: 2 });
    expect(e('var.on ? "yes" : "no"', { var: { on: false } })).toBe('no');
    expect(e('coalesce(null, "", "z")')).toBe('z');
    expect(e('lookup({ a = 1 }, "b", 7)')).toBe(7);
    expect(e('format("%s-%d", "q", 3)')).toBe('q-3');
    expect(e('merge({ a = 1 }, { b = 2 })')).toEqual({ a: 1, b: 2 });
    expect(e('toset(["b", "a", "b"])')).toEqual(['a', 'b']);
    expect(e('cidrsubnet("10.0.0.0/16", 8, 2)')).toBe('10.0.2.0/24');
  });

  test('try falls back past errors, and errors become unknowns instead of throwing', () => {
    expect(e('try(var.missing.x, "fallback")', { var: {} })).toBe('fallback');
    expect(isUnknown(e('var.missing.x', { var: {} }))).toBe(true);
  });

  test('an unknown condition with equal branches is still known', () => {
    expect(e('var.u ? "same" : "same"', { var: { u: new Unknown('x') } })).toBe('same');
  });

  test('stableKey treats two references to the same computed attribute as equal', () => {
    const a = e('aws_s3_bucket.b.arn', { aws_s3_bucket: { b: bucket } });
    const b = e('aws_s3_bucket.b.arn', { aws_s3_bucket: { b: bucket } });
    expect(stableKey(a)).toBe(stableKey(b));
  });

  test('stableKey tells apart unknowns derived from different resources', () => {
    const other = new ResourceValue('aws_s3_bucket.other', () => ({}));
    const a = e('aws_s3_bucket.b.arn', { aws_s3_bucket: { b: bucket } });
    const b = e('aws_s3_bucket.o.arn', { aws_s3_bucket: { o: other } });
    expect(stableKey(a)).not.toBe(stableKey(b));
  });

  test('structural functions keep known keys when values are unknown (a production Lambda env)', () => {
    const v = e('merge({ A = var.u }, { B = 1 })', { var: { u: new Unknown('x') } }) as Record<string, unknown>;
    expect(Object.keys(v)).toEqual(['A', 'B']);
    expect(v.B).toBe(1);
    expect(e('length([var.u, 2])', { var: { u: new Unknown('x') } })).toBe(2);
    expect(e('keys({ k = var.u })', { var: { u: new Unknown('x') } })).toEqual(['k']);
  });

  test('try() falls back on invalid JSON and on RE2-only regex syntax instead of aborting', () => {
    expect(e('try(jsondecode(""), {})')).toEqual({});
    expect(e('try(regex("(?P<n>a)", "a"), "x")')).toEqual({ n: 'a' });
    expect(e('try(regex("(?i)ABC", "abc"), "no")')).toBe('abc');
    expect(isUnknown(e('regex("([", "a")'))).toBe(true);
  });

  test('splat over a list of objects', () => {
    expect(e('var.l[*].n', { var: { l: [{ n: 1 }, { n: 2 }] } })).toEqual([1, 2]);
  });
});
