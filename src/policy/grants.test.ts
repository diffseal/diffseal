import { expect, test } from 'bun:test';
import { Unknown } from '../core/model.js';
import { grantsWithin } from './grants.js';

const allow = (Action: unknown, Resource: unknown, extra: Record<string, unknown> = {}) => ({ Statement: [{ Effect: 'Allow', Action, Resource, ...extra }] });

test('a grant on a resource partly known at plan time is judged by its widest reading (source case: forms-deploy 951687f6b)', () => {
  const bucketObjects = new Unknown('bucket name', 'arn:aws:s3:::{?}/*', []);
  expect(grantsWithin(allow('s3:*', 'arn:aws:s3:::*'), allow('s3:GetObject', bucketObjects))).toBe(true);
  expect(grantsWithin(allow('s3:*', 'arn:aws:s3:::logs*'), allow('s3:GetObject', bucketObjects))).toBe(false);
});

test('containment is only claimed when certain', () => {
  expect(grantsWithin(allow('s3:Get*', '*'), allow('s3:GetObject', 'arn:aws:s3:::b/k'))).toBe(true);
  expect(grantsWithin(allow('s3:GetObject', '*'), allow('s3:Get*', '*'))).toBe(false);
  expect(grantsWithin(allow('s3:*', 'arn:aws:s3:::a*b'), allow('s3:GetObject', 'arn:aws:s3:::a*'))).toBe(false);
  expect(grantsWithin(allow('s3:*', '*'), { Statement: [{ Effect: 'Allow', NotAction: 's3:DeleteBucket', Resource: '*' }] })).toBe(false);
  expect(grantsWithin(allow('s3:*', '*'), allow(new Unknown('action'), '*'))).toBe(false);
});
