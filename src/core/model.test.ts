import { expect, test } from 'bun:test';
import { instancesCompatible } from './model.js';

test('instance keys of the same module path must agree', () => {
  expect(instancesCompatible('module.b["a"].aws_s3_bucket_policy.p', 'module.b["b"].aws_s3_bucket.x')).toBe(false);
  expect(instancesCompatible('module.b["a"].aws_s3_bucket_policy.p', 'module.b["a"].aws_s3_bucket.x')).toBe(true);
  expect(instancesCompatible('aws_s3_bucket_policy.p["a"]', 'aws_s3_bucket.x["b"]')).toBe(false);
  expect(instancesCompatible('aws_s3_bucket_policy.p[*]', 'aws_s3_bucket.x["b"]')).toBe(true);
});

test('keys of different modules say nothing about each other (round 3)', () => {
  expect(instancesCompatible('module.guard[0].aws_s3_bucket_public_access_block.p', 'module.buckets["logs"].aws_s3_bucket.b')).toBe(true);
  expect(instancesCompatible('module.guard[0].aws_s3_bucket_public_access_block.p[0]', 'module.buckets.aws_s3_bucket.b["logs"]')).toBe(true);
  expect(instancesCompatible('aws_s3_bucket_policy.p[0]', 'module.buckets.aws_s3_bucket.b["logs"]')).toBe(true);
  // A shared parent still has to agree.
  expect(instancesCompatible('module.env["a"].module.guard.aws_x.p', 'module.env["b"].module.buckets.aws_s3_bucket.b')).toBe(false);
});
