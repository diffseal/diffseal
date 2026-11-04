import { expect, test } from 'bun:test';
import { Unknown } from '../core/model.js';
import { analyzeBlastRadius } from '../analysis/blastRadius.js';
import type { ResourceChange } from '../core/model.js';
import { diffGrants, grantsWithin } from './grants.js';

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

test('wildcard containment takes linear time on adversarial patterns (review round 12)', () => {
  const outer = 'arn:aws:s3:::' + 'a*'.repeat(24) + 'b';
  const inner = 'arn:aws:s3:::' + 'a'.repeat(34) + 'c';
  const started = Date.now();
  expect(grantsWithin(allow('s3:*', outer), allow('s3:GetObject', inner))).toBe(false);
  expect(Date.now() - started).toBeLessThan(500);
  expect(grantsWithin(allow('s3:*', 'arn:aws:s3:::a*b?d'), allow('s3:GetObject', 'arn:aws:s3:::axxbcd'))).toBe(true);
});

const doc = (...Statement: Record<string, unknown>[]) => ({ Version: '2012-10-17', Statement });

test('a grant replaced by a wider one is not revoked (source case: diffseal/demo#2)', () => {
  const table = new Unknown('table arn', '{?}', ['module.fulfillment.aws_dynamodb_table.shipments']);
  const d = diffGrants(
    doc({ Effect: 'Allow', Action: ['dynamodb:PutItem', 'dynamodb:GetItem'], Resource: table }),
    doc({ Effect: 'Allow', Action: ['dynamodb:*'], Resource: ['*'] })
  );
  expect(d?.removed).toEqual([]);
  expect(d?.added).toEqual([{ effect: 'Allow', action: 'dynamodb:*', resource: '*' }]);
  // `*` and a prefix wildcard on the resource cover too; IAM action names ignore case.
  expect(diffGrants(doc({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/k' }), doc({ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' }))?.removed).toEqual([]);
  expect(diffGrants(doc({ Effect: 'Allow', Action: 'S3:GetObject', Resource: '*' }), doc({ Effect: 'Allow', Action: 's3:get*', Resource: '*' }))?.removed).toEqual([]);
});

test('a grant is revoked when nothing in the new version certainly covers it', () => {
  const removed = (before: unknown, after: unknown) => diffGrants(before, after)?.removed.map((g) => g.action);
  const old = doc({ Effect: 'Allow', Action: ['dynamodb:PutItem', 'dynamodb:GetItem'], Resource: 'arn:aws:dynamodb:eu-north-1:1:table/t' });
  // Narrower actions or another resource.
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:Get*', Resource: '*' }))).toEqual(['dynamodb:PutItem']);
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:*', Resource: 'arn:aws:dynamodb:eu-north-1:1:table/other' }))).toEqual(['dynamodb:PutItem', 'dynamodb:GetItem']);
  // A new grant with a condition may not apply to every caller.
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:*', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'true' } } }))).toEqual(['dynamodb:PutItem', 'dynamodb:GetItem']);
  // NotAction and NotResource are not a grant of what they name.
  expect(removed(old, doc({ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }))).toEqual(['dynamodb:PutItem', 'dynamodb:GetItem']);
  // An old NotAction grant shown with the same text is not kept by a grant of what it names.
  expect(removed(doc({ Effect: 'Allow', NotAction: 's3:*', Resource: '*' }), doc({ Effect: 'Allow', Action: '*', Resource: '*' }, { Effect: 'Deny', Action: 'iam:*', Resource: '*' }))).toEqual(['s3:*']);
  // A new Deny that may match takes the access away whatever the Allow says.
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:*', Resource: '*' }, { Effect: 'Deny', Action: 'dynamodb:PutItem', Resource: '*' }))).toEqual(['dynamodb:PutItem']);
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:*', Resource: '*' }, { Effect: 'Deny', Action: 'dynamodb:Put*', Resource: 'arn:aws:dynamodb:*' }))).toEqual(['dynamodb:PutItem']);
  // A Deny that cannot match the old grant leaves it in place.
  expect(removed(old, doc({ Effect: 'Allow', Action: 'dynamodb:*', Resource: '*' }, { Effect: 'Deny', Action: 'dynamodb:DeleteTable', Resource: '*' }))).toEqual([]);
  // An action not known statically covers nothing.
  expect(removed(old, doc({ Effect: 'Allow', Action: new Unknown('action'), Resource: '*' }))).toEqual(['dynamodb:PutItem', 'dynamodb:GetItem']);
});

test('a Deny that holds a value not known statically may match other requests at apply time (review round 1)', () => {
  const old = doc({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' });
  const endpoint = new Unknown('endpoint id', '{?}', ['aws_vpc_endpoint.guard']);
  const guard = { Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: { StringNotEquals: { 'aws:SourceVpce': endpoint } } };
  expect(diffGrants({ ...old, Statement: [...old.Statement, guard] }, doc({ Effect: 'Allow', Action: 's3:Get*', Resource: '*' }, guard))?.removed.map((g) => g.action)).toEqual(['s3:GetObject']);
  const fixed = { ...guard, Condition: { StringNotEquals: { 'aws:SourceVpce': 'vpce-1' } } };
  expect(diffGrants({ ...old, Statement: [...old.Statement, fixed] }, doc({ Effect: 'Allow', Action: 's3:Get*', Resource: '*' }, fixed))?.removed).toEqual([]);
});

test('removing a statement that a wider grant still covers is INFO, not a policy that cannot be read (review round 1)', () => {
  const change = (before: unknown, after: unknown): ResourceChange => ({
    address: 'aws_iam_policy.p', type: 'aws_iam_policy', name: 'p', mode: 'managed', action: 'update',
    before: { name: 'p', policy: JSON.stringify(before) }, after: { name: 'p', policy: JSON.stringify(after) }, references: {}, confidence: 'proven',
  } as ResourceChange);
  const wide = { Effect: 'Allow', Action: 'dynamodb:*', Resource: '*' };
  const [row] = analyzeBlastRadius([change(doc(wide, { Effect: 'Allow', Action: 'dynamodb:GetItem', Resource: 'arn:aws:dynamodb:eu-north-1:1:table/t' }), doc(wide))]);
  expect(row).toMatchObject({ severity: 'INFO', downtime: 'no' });
  expect(row.reason).toContain('dynamodb:GetItem on arn:aws:dynamodb:eu-north-1:1:table/t');
  expect(row.reason).not.toContain('not known statically');
  expect(row.reason).not.toContain('Revokes');
});
