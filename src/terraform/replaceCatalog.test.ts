import { expect, test } from 'bun:test';
import type { Attrs } from '../core/model.js';
import { typed } from '../policy/values.js';
import { NESTED_REPLACE, REPLACE_CATALOG_SOURCE, REPLACE_CATALOG_VERSION, REPLACE_ON_CHANGE } from './replaceCatalog.js';
import {
  PROVIDER_SCHEMA_FORMAT_VERSION,
  PROVIDER_SCHEMA_LOCK_H1,
  PROVIDER_SCHEMA_MAX_DEPTH,
  PROVIDER_SCHEMA_RESOURCE_COUNT,
  PROVIDER_SCHEMA_SHA256,
  PROVIDER_SCHEMA_SOURCE,
  PROVIDER_SCHEMA_VERSION,
  resourceSchema,
} from './schemaCatalog.js';

test('the replacement catalogue loads, is stamped, and has known entries', () => {
  expect(REPLACE_CATALOG_SOURCE).toMatch(/^hashicorp\/terraform-provider-aws@[0-9a-f]{9}$/);
  expect(REPLACE_CATALOG_VERSION).toBe('6.70.0');
  expect(Object.keys(REPLACE_ON_CHANGE).length).toBeGreaterThan(1000);
  expect(REPLACE_ON_CHANGE.aws_dynamodb_table).toEqual(expect.arrayContaining(['name', 'hash_key', 'range_key', 'local_secondary_index']));
  expect(REPLACE_ON_CHANGE.aws_db_instance).toEqual(expect.arrayContaining(['storage_encrypted', 'kms_key_id', 'engine']));
  // RDS identifier is an in-place rename, not a replacement.
  expect(REPLACE_ON_CHANGE.aws_db_instance).not.toContain('identifier');
  expect(NESTED_REPLACE.aws_dynamodb_table?.local_secondary_index).toEqual(expect.arrayContaining(['name', 'range_key']));
  expect(NESTED_REPLACE.aws_msk_cluster?.broker_node_group_info).not.toContain('instance_type');
});

test('the provider schema snapshot loads, matches the replace catalogue version, and has known flags', () => {
  expect(PROVIDER_SCHEMA_SOURCE).toBe('hashicorp/aws@6.70.0');
  expect(PROVIDER_SCHEMA_VERSION).toBe(REPLACE_CATALOG_VERSION);
  expect(PROVIDER_SCHEMA_FORMAT_VERSION).toStartWith('1.');
  expect(PROVIDER_SCHEMA_SHA256).toMatch(/^[0-9a-f]{64}$/);
  expect(PROVIDER_SCHEMA_LOCK_H1).toStartWith('h1:');
  expect(PROVIDER_SCHEMA_MAX_DEPTH).toBe(3);
  expect(PROVIDER_SCHEMA_RESOURCE_COUNT).toBeGreaterThan(1700);

  expect(resourceSchema('aws_s3_bucket')?.bool.has('force_destroy')).toBe(true);
  expect(resourceSchema('aws_s3_bucket')?.computed.has('arn')).toBe(true);
  expect(resourceSchema('aws_s3_bucket')?.blocks.server_side_encryption_configuration).toBe('list1');

  expect(resourceSchema('aws_db_instance')?.sensitive.has('password')).toBe(true);
  expect(resourceSchema('aws_db_instance')?.sensitive.has('password_wo')).toBe(true);
  expect(resourceSchema('aws_db_instance')?.writeOnly.has('password_wo')).toBe(true);
  expect(resourceSchema('aws_db_instance')?.computed.has('arn')).toBe(true);
  expect(resourceSchema('aws_db_instance')?.number.has('allocated_storage')).toBe(true);
  expect(resourceSchema('aws_db_instance')?.bool.has('deletion_protection')).toBe(true);

  expect(resourceSchema('aws_iam_access_key')?.computed.has('secret')).toBe(true);
  expect(resourceSchema('aws_iam_access_key')?.sensitive.has('secret')).toBe(true);

  expect(resourceSchema('aws_security_group_rule')?.number.has('from_port')).toBe(true);
  expect(resourceSchema('aws_security_group')?.number.has('ingress.from_port')).toBe(true);
  expect(resourceSchema('aws_security_group')?.bool.has('ingress.self')).toBe(true);

  // Negative checks: string attributes whose names match booleans elsewhere are not in bool.
  expect(resourceSchema('aws_cognito_user_pool')?.bool.has('deletion_protection')).toBe(false);
  expect(resourceSchema('aws_redshift_cluster')?.bool.has('encrypted')).toBe(false);
});

test('typed() uses the provider schema when known and keeps fallback behaviour for uncatalogued attributes', () => {
  expect(typed<Attrs>({ deletion_protection: 'true' }, 'aws_db_instance')).toEqual({ deletion_protection: true });
  expect(typed<Attrs>({ deletion_protection: 'true' }, 'aws_cognito_user_pool')).toEqual({ deletion_protection: 'true' });
  expect(typed<Attrs>({ encrypted: 'true' }, 'aws_ebs_volume')).toEqual({ encrypted: true });
  expect(typed<Attrs>({ encrypted: 'true' }, 'aws_redshift_cluster')).toEqual({ encrypted: 'true' });
  // Fallback when resource type is omitted or not in the AWS schema snapshot.
  expect(typed<Attrs>({ deletion_protection: 'true', from_port: '443' })).toEqual({ deletion_protection: true, from_port: 443 });
  expect(typed<Attrs>({ deletion_protection: 'true', from_port: '443' }, 'custom_resource')).toEqual({ deletion_protection: true, from_port: 443 });
  // Fallback for paths deeper than max_depth (3).
  expect(typed<Attrs>({ a: { b: { c: { enabled: 'true' } } } }, 'aws_s3_bucket')).toEqual({ a: { b: { c: { enabled: true } } } });
});
