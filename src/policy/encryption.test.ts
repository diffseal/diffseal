import { expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { Redacted, Unknown, type Attrs, type FindingStatus } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { cfg, plan, rc } from '../testing/planFixtures.js';
import { evaluatePolicies } from './engine.js';
import { MemorySource } from '../terraform/source.js';
import { evaluateRoot } from '../terraform/expand.js';
import { compareEvaluations } from '../terraform/compare.js';
import { renderMarkdown } from '../report/markdown.js';
import { changeRecord } from '../evidence/changeRecord.js';

function check(rule: string, type: string, criterion: string, cases: Array<[string, Attrs, FindingStatus]>) {
  const address = (name: string) => `module.service["prod"].${type}.${name}["example"]`;
  const findings = evaluatePolicies(readPlan(plan(cases.map(([name, attrs]) => rc(address(name), type, ['create'], attrs)))))
    .filter((f) => f.ruleId === rule);
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual(cases.map(([name, _attrs, status]) => [
    address(name), status, ['ISO27001:A.8.24', `SOC2:${criterion}`],
  ]));
}

test('every encryption flag requires explicit configuration for PASS or WARN', () => {
  const flags = [
    ['ebs.default-encryption', 'aws_ebs_encryption_by_default', 'enabled', 'CC6.1'],
    ['ebs.encryption', 'aws_ebs_volume', 'encrypted', 'CC6.1'],
    ['efs.encryption', 'aws_efs_file_system', 'encrypted', 'CC6.1'],
    ['elasticache.encryption', 'aws_elasticache_replication_group', 'at_rest_encryption_enabled', 'CC6.1'],
    ['elasticache.transit-encryption', 'aws_elasticache_replication_group', 'transit_encryption_enabled', 'CC6.7'],
    ['rds.encryption', 'aws_db_instance', 'storage_encrypted', 'CC6.1'],
    ['sqs.encryption', 'aws_sqs_queue', 'sqs_managed_sse_enabled', 'CC6.1'],
  ];
  for (const [rule, type, attr, criterion] of flags) {
    check(rule, type, criterion, [
      ['on', { [attr]: true }, 'PASS'],
      ['off', { [attr]: false }, 'WARN'],
      ['omitted', {}, 'UNKNOWN'],
      ['null', { [attr]: null }, 'UNKNOWN'],
      ['unknown', { [attr]: new Unknown('configured variable') }, 'UNKNOWN'],
      ['redacted', { [attr]: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('RDS cross-region replicas ignore storage_encrypted even with a destination KMS key', () => {
  const replica = { replicate_source_db: 'arn:aws:rds:us-east-1:123456789012:db:source' };
  check('rds.encryption', 'aws_db_instance', 'CC6.1', [
    ['off_with_key', { ...replica, storage_encrypted: false, kms_key_id: 'arn:aws:kms:us-west-2:123456789012:key/destination' }, 'UNKNOWN'],
    ['off', { ...replica, storage_encrypted: false }, 'UNKNOWN'],
    ['on', { ...replica, storage_encrypted: true }, 'UNKNOWN'],
    ['omitted', replica, 'UNKNOWN'],
    ['same_region_identifier', { replicate_source_db: 'source', storage_encrypted: false }, 'WARN'],
    ['standalone_off', { storage_encrypted: false }, 'WARN'],
    ['standalone_on', { storage_encrypted: true }, 'PASS'],
  ]);
  check('rds.encryption', 'aws_rds_cluster', 'CC6.1', [['off', { storage_encrypted: false }, 'WARN']]);
});

test('encryption checks never attest inferred service or nested-block defaults', () => {
  for (const [rule, type, attrs] of [
    ['s3.encryption', 'aws_s3_bucket', {}],
    ['sqs.encryption', 'aws_sqs_queue', {}],
    ['sns.encryption', 'aws_sns_topic', {}],
    ['dynamodb.encryption', 'aws_dynamodb_table', {}],
    ['opensearch.encryption', 'aws_opensearch_domain', {}],
    ['opensearch.node-to-node-encryption', 'aws_opensearch_domain', {}],
    ['opensearch.https', 'aws_opensearch_domain', { domain_endpoint_options: [{}] }],
    ['elb.tls-policy', 'aws_lb_listener', { protocol: 'HTTPS' }],
    ['cloudfront.tls-policy', 'aws_cloudfront_distribution', { viewer_certificate: [{}] }],
  ] as const) {
    expect(evaluatePolicies(readPlan(plan([rc(`${type}.example`, type, ['create'], attrs)])))
      .find((f) => f.ruleId === rule)?.status).toBe('UNKNOWN');
  }
});

test('DynamoDB explicit false selects an AWS-owned key and preserves the customer-managed-key policy', () => {
  const changes = readPlan(plan([
    rc('aws_dynamodb_table.aws_owned', 'aws_dynamodb_table', ['create'], { server_side_encryption: [{ enabled: false }] }),
    rc('aws_dynamodb_table.aws_owned_with_key', 'aws_dynamodb_table', ['create'], { server_side_encryption: [{ enabled: 'false', kms_key_arn: 'arn:aws:kms:eu-west-1:123456789012:key/customer' }] }),
    rc('aws_dynamodb_table.aws_managed', 'aws_dynamodb_table', ['create'], { server_side_encryption: [{ enabled: true }] }),
    rc('aws_dynamodb_table.customer_managed', 'aws_dynamodb_table', ['create'], { server_side_encryption: [{ enabled: true, kms_key_arn: 'arn:aws:kms:eu-west-1:123456789012:key/customer' }] }),
    rc('aws_dynamodb_table.omitted', 'aws_dynamodb_table', ['create'], {}),
    rc('aws_dynamodb_table.null', 'aws_dynamodb_table', ['create'], { server_side_encryption: [{ enabled: null }] }),
  ]));
  const findings = evaluatePolicies(changes).filter((f) => f.ruleId === 'dynamodb.encryption');
  expect(findings.map((f) => [f.resource, f.status])).toEqual([
    ['aws_dynamodb_table.aws_owned', 'PASS'], ['aws_dynamodb_table.aws_owned_with_key', 'PASS'],
    ['aws_dynamodb_table.aws_managed', 'PASS'], ['aws_dynamodb_table.customer_managed', 'PASS'],
    ['aws_dynamodb_table.omitted', 'UNKNOWN'], ['aws_dynamodb_table.null', 'UNKNOWN'],
  ]);
  const strict = evaluatePolicies(changes, { requireCustomerManagedKeys: true }).filter((f) => f.ruleId === 'dynamodb.encryption');
  expect(strict.map((f) => [f.resource, f.status])).toEqual([
    ['aws_dynamodb_table.aws_owned', 'WARN'], ['aws_dynamodb_table.aws_owned_with_key', 'WARN'],
    ['aws_dynamodb_table.aws_managed', 'WARN'], ['aws_dynamodb_table.customer_managed', 'PASS'],
    ['aws_dynamodb_table.omitted', 'UNKNOWN'], ['aws_dynamodb_table.null', 'UNKNOWN'],
  ]);
  expect(strict[0].detail).toContain('AWS-owned key');
  expect(strict[0].detail).toContain('policy requires a customer managed KMS key');
  expect(strict[0].detail).not.toContain('disabled');
});

test('unrecognized KMS key values and omitted redirect protocols remain UNKNOWN', () => {
  for (const [rule, type] of [['sqs.encryption', 'aws_sqs_queue'], ['sns.encryption', 'aws_sns_topic']]) {
    check(rule, type, 'CC6.1', [['invalid_key', { kms_master_key_id: false }, 'UNKNOWN']]);
  }
  check('elb.https', 'aws_lb_listener', 'CC6.7', [
    ['omitted', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{}] }] }, 'UNKNOWN'],
    ['invalid', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: 'unrecognized' }] }] }, 'UNKNOWN'],
  ]);
});

test('provider-populated encryption values and nested flags are not configured evidence', () => {
  const cases = [
    rc('aws_ebs_volume.computed', 'aws_ebs_volume', ['update'], { encrypted: true }),
    rc('aws_efs_file_system.computed', 'aws_efs_file_system', ['create'], { encrypted: false }),
    rc('aws_opensearch_domain.computed', 'aws_opensearch_domain', ['create'], { encrypt_at_rest: [{ enabled: true }] }),
    rc('aws_opensearch_domain.nested', 'aws_opensearch_domain', ['create'], { domain_endpoint_options: [{ enforce_https: true, custom_endpoint_enabled: false }] }),
  ];
  const resources = cases.map((c) => ({ address: c.address, expressions: c.address.endsWith('.nested')
    ? { domain_endpoint_options: [{ custom_endpoint_enabled: { constant_value: false } }] } : {} }));
  const findings = evaluatePolicies(readPlan(plan(cases, [], { configuration: { root_module: { resources } } })));
  expect(findings.filter((f) => ['ebs.encryption', 'efs.encryption', 'opensearch.encryption', 'opensearch.https'].includes(f.ruleId))
    .every((f) => f.status === 'UNKNOWN')).toBe(true);
});

test('literal nulls stay omitted and explicit flags take precedence over provider-populated plan values', () => {
  const resources = [
    { address: 'aws_ebs_volume.omitted', expressions: { encrypted: { constant_value: null } } },
    { address: 'aws_ebs_volume.disabled', expressions: { encrypted: { constant_value: false } } },
    { address: 'aws_elasticache_replication_group.primary', expressions: {
      global_replication_group_id: { constant_value: null },
      at_rest_encryption_enabled: { constant_value: false }, transit_encryption_enabled: { constant_value: false },
    } },
    { address: 'aws_opensearch_domain.omitted', expressions: { domain_endpoint_options: [{ enforce_https: { constant_value: null } }] } },
  ];
  const findings = evaluatePolicies(readPlan(plan([
    rc(resources[0].address, 'aws_ebs_volume', ['create'], { encrypted: true }),
    rc(resources[1].address, 'aws_ebs_volume', ['create'], { encrypted: true }),
    rc(resources[2].address, 'aws_elasticache_replication_group', ['create'], {
      global_replication_group_id: 'computed-primary', at_rest_encryption_enabled: false, transit_encryption_enabled: false,
    }),
    rc(resources[3].address, 'aws_opensearch_domain', ['create'], { domain_endpoint_options: [{ enforce_https: true }] }),
  ], [], { configuration: { root_module: { resources } } })));
  expect(findings.filter((f) => ['ebs.encryption', 'elasticache.encryption', 'elasticache.transit-encryption', 'opensearch.https'].includes(f.ruleId))
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_ebs_volume.omitted', 'UNKNOWN'], ['aws_ebs_volume.disabled', 'WARN'],
      ['aws_elasticache_replication_group.primary', 'WARN'], ['aws_elasticache_replication_group.primary', 'WARN'],
      ['aws_opensearch_domain.omitted', 'UNKNOWN'],
    ]);
});

test('nullable expressions do not turn planned encryption defaults into configured evidence', () => {
  const resources = [
    { address: 'aws_efs_file_system.existing', expressions: { encrypted: { references: ['var.encrypt'] } } },
    { address: 'aws_db_instance.example', expressions: { storage_encrypted: { references: ['var.encrypt'] } } },
  ];
  const changes = readPlan(plan([
    rc(resources[0].address, 'aws_efs_file_system', ['update'], { encrypted: true }, { before: { encrypted: true } }),
    rc(resources[1].address, 'aws_db_instance', ['create'], { storage_encrypted: false }),
  ], [], {
    variables: { encrypt: { value: null } },
    configuration: { root_module: { resources } },
  }));
  expect(evaluatePolicies(changes).filter((f) => ['efs.encryption', 'rds.encryption'].includes(f.ruleId))
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_efs_file_system.existing', 'UNKNOWN'], ['aws_db_instance.example', 'UNKNOWN'],
    ]);
});

test('null-producing conditionals and module outputs never attest provider-populated encryption', () => {
  const source = new MemorySource({ 'main.tf': `
    variable "enabled" { default = true }
    module "settings" {
      source = "./settings"
      enabled = var.enabled
    }
    resource "aws_efs_file_system" "conditional" { encrypted = var.enabled ? null : true }
    resource "aws_efs_file_system" "output" { encrypted = module.settings.encrypted }
  `, 'settings/main.tf': `
    variable "enabled" { default = true }
    output "encrypted" { value = var.enabled ? null : true }
  ` });
  const fromSource = compareEvaluations(undefined, evaluateRoot(source, '.'));
  for (const encrypted of [false, true]) {
    const fromPlan = readPlan(plan([
      rc('aws_efs_file_system.conditional', 'aws_efs_file_system', ['create'], { encrypted }),
      rc('aws_efs_file_system.output', 'aws_efs_file_system', ['create'], { encrypted }),
    ], [], { variables: { enabled: { value: true } }, configuration: { root_module: {
      resources: [
        cfg('aws_efs_file_system.conditional', { encrypted: ['var.enabled'] }),
        cfg('aws_efs_file_system.output', { encrypted: ['module.settings.encrypted', 'module.settings'] }),
      ],
      module_calls: { settings: { expressions: { enabled: { constant_value: true } }, module: {
        outputs: { encrypted: { expression: { references: ['var.enabled'] } } },
      } } },
    } } }));
    for (const changes of [fromSource, fromPlan]) {
      expect(evaluatePolicies(changes).filter((f) => f.ruleId === 'efs.encryption').map((f) => [f.resource, f.status]))
        .toEqual([
          ['aws_efs_file_system.conditional', 'UNKNOWN'], ['aws_efs_file_system.output', 'UNKNOWN'],
        ]);
    }
  }
});

test('nullable nested object attributes cannot attest provider-populated encryption values', () => {
  for (const [reference, value, status] of [
    ['var.config.encrypted', { encrypted: null }, 'UNKNOWN'],
    ['var.config.storage.encrypted', { storage: { encrypted: null } }, 'UNKNOWN'],
    ['var.config.storage.encrypted', { storage: null }, 'UNKNOWN'],
    ['var.config.storage.encrypted', { storage: { encrypted: true }, other: null }, 'PASS'],
    ['var.config["storage"].encrypted', { storage: { encrypted: null } }, 'UNKNOWN'],
  ] as const) {
    const resources = [
      { address: 'aws_db_instance.example', expressions: { storage_encrypted: { references: [reference, 'var.config'] } } },
      { address: 'aws_efs_file_system.example', expressions: { encrypted: { references: [reference, 'var.config'] } } },
    ];
    const findings = evaluatePolicies(readPlan(plan([
      rc(resources[0].address, 'aws_db_instance', ['create'], { storage_encrypted: status === 'PASS' }),
      rc(resources[1].address, 'aws_efs_file_system', ['update'], { encrypted: true }, { before: { encrypted: true } }),
    ], [], { variables: { config: { value } }, configuration: { root_module: { resources } } })));
    expect([reference, findings.filter((f) => ['rds.encryption', 'efs.encryption'].includes(f.ruleId)).map((f) => f.status)])
      .toEqual([reference, ['UNKNOWN', 'UNKNOWN']]);
    const source = new MemorySource({ 'main.tf': `
      variable "config" {}
      resource "aws_db_instance" "example" { storage_encrypted = ${reference} }
      resource "aws_efs_file_system" "example" { encrypted = ${reference} }
    ` });
    expect(evaluatePolicies(compareEvaluations(undefined, evaluateRoot(source, '.', { config: value })))
      .filter((f) => ['rds.encryption', 'efs.encryption'].includes(f.ruleId)).map((f) => f.status)).toEqual([status, status]);
  }
});

test('RDS replica sources must be known same-region identifiers before judging storage_encrypted', () => {
  const changes = readPlan(plan([
    rc('aws_db_instance.source', 'aws_db_instance', ['create'], { storage_encrypted: false }, { afterUnknown: { arn: true } }),
    rc('aws_db_instance.replica', 'aws_db_instance', ['create'], { storage_encrypted: true }, { afterUnknown: { replicate_source_db: true } }),
  ], [cfg('aws_db_instance.replica', { replicate_source_db: ['aws_db_instance.source.arn'] })]));
  expect(evaluatePolicies(changes).filter((f) => f.ruleId === 'rds.encryption').map((f) => [f.resource, f.status])).toEqual([
    ['aws_db_instance.source', 'WARN'], ['aws_db_instance.replica', 'UNKNOWN'],
  ]);
  check('rds.encryption', 'aws_db_instance', 'CC6.1', [
    ['unknown_off', { replicate_source_db: new Unknown('source'), storage_encrypted: false }, 'UNKNOWN'],
    ['unknown_on', { replicate_source_db: new Unknown('source'), storage_encrypted: true }, 'UNKNOWN'],
    ['invalid', { replicate_source_db: {}, storage_encrypted: true }, 'UNKNOWN'],
    ['identifier', { replicate_source_db: 'source-db', storage_encrypted: true }, 'PASS'],
  ]);
});

test('coalesce fallbacks cannot erase nullable encryption inputs or configured snapshot inheritance', () => {
  const resources = [
    { address: 'aws_db_instance.example', expressions: { storage_encrypted: { references: ['var.encrypt'] } } },
    { address: 'aws_efs_file_system.example', expressions: { encrypted: { references: ['var.config.encrypted', 'var.config'] } } },
    { address: 'aws_ebs_volume.example', expressions: { encrypted: { constant_value: false }, snapshot_id: { references: ['var.snapshot'] } } },
    { address: 'aws_ebs_volume.enabled', expressions: { encrypted: { constant_value: true }, snapshot_id: { references: ['var.snapshot'] } } },
  ];
  const findings = evaluatePolicies(readPlan(plan([
    rc(resources[0].address, 'aws_db_instance', ['create'], { storage_encrypted: false }),
    rc(resources[1].address, 'aws_efs_file_system', ['create'], { encrypted: true }),
    rc(resources[2].address, 'aws_ebs_volume', ['create'], { encrypted: false, snapshot_id: 'snap-external' }),
    rc(resources[3].address, 'aws_ebs_volume', ['create'], { encrypted: true, snapshot_id: 'snap-external' }),
  ], [], { variables: { encrypt: { value: null }, config: { value: { encrypted: null } }, snapshot: { value: null } },
    configuration: { root_module: { resources } } })));
  expect(findings.filter((f) => ['rds.encryption', 'efs.encryption', 'ebs.encryption'].includes(f.ruleId)).map((f) => f.status))
    .toEqual(['UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'PASS']);
});

test('module inputs and outputs preserve null, unknown and computed dependencies for encryption evidence', () => {
  for (const [expression, sourceExpression, status] of [
    [{ constant_value: true }, 'true', 'PASS'],
    [{ constant_value: false }, 'false', 'WARN'],
    [{ references: ['var.enabled'] }, 'var.enabled', 'PASS'],
    [{ references: ['var.config.encrypted', 'var.config'] }, 'var.config.encrypted', 'UNKNOWN'],
    [{ references: ['var.missing'] }, 'var.missing', 'UNKNOWN'],
    [{ references: ['aws_efs_file_system.computed.encrypted'] }, 'aws_efs_file_system.computed.encrypted', 'UNKNOWN'],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_efs_file_system.computed', 'aws_efs_file_system', ['no-op'], { encrypted: true }),
      rc('aws_efs_file_system.consumer', 'aws_efs_file_system', ['create'], { encrypted: true }),
      rc('module.settings.aws_efs_file_system.consumer', 'aws_efs_file_system', ['create'], { encrypted: true }),
    ], [], { variables: { enabled: { value: true }, config: { value: { encrypted: null } } }, configuration: { root_module: {
      resources: [
        { address: 'aws_efs_file_system.computed', expressions: {} },
        cfg('aws_efs_file_system.consumer', { encrypted: ['module.settings.encrypted', 'module.settings'] }),
      ],
      module_calls: { settings: { expressions: { enabled: expression }, module: {
        resources: [cfg('aws_efs_file_system.consumer', { encrypted: ['var.enabled'] })],
        outputs: { encrypted: { expression: { references: ['var.enabled'] } } },
      } } },
    } } })));
    expect(findings.filter((f) => f.ruleId === 'efs.encryption').map((f) => [f.resource, f.status])).toEqual([
      ['aws_efs_file_system.consumer', 'UNKNOWN'], ['module.settings.aws_efs_file_system.consumer', 'UNKNOWN'],
    ]);
    const source = new MemorySource({ 'main.tf': `
      variable "enabled" { default = true }
      variable "config" { default = { encrypted = null } }
      variable "missing" {}
      resource "aws_efs_file_system" "computed" {}
      module "settings" {
        source = "./settings"
        enabled = ${sourceExpression}
      }
      resource "aws_efs_file_system" "consumer" { encrypted = module.settings.encrypted }
    `, 'settings/main.tf': `
      variable "enabled" {}
      resource "aws_efs_file_system" "consumer" { encrypted = var.enabled }
      output "encrypted" { value = var.enabled }
    ` });
    expect(evaluatePolicies(compareEvaluations(undefined, evaluateRoot(source, '.')))
      .filter((f) => f.ruleId === 'efs.encryption' && f.resource.endsWith('.consumer')).map((f) => f.status)).toEqual([status, status]);
  }
});

test('computed KMS key references cannot become explicit encryption evidence', () => {
  const source = new MemorySource({ 'main.tf': `
    resource "aws_kms_key" "example" {}
    resource "aws_sqs_queue" "example" { kms_master_key_id = aws_kms_key.example.arn }
  ` });
  const fromSource = compareEvaluations(undefined, evaluateRoot(source, '.'));
  const fromPlan = readPlan(plan([
    rc('aws_kms_key.example', 'aws_kms_key', ['create'], {}, { afterUnknown: { arn: true } }),
    rc('aws_sqs_queue.example', 'aws_sqs_queue', ['create'], {}, { afterUnknown: { kms_master_key_id: true } }),
  ], [cfg('aws_sqs_queue.example', { kms_master_key_id: ['aws_kms_key.example.arn'] })]));
  for (const changes of [fromSource, fromPlan]) {
    expect(evaluatePolicies(changes).find((f) => f.ruleId === 'sqs.encryption')?.status).toBe('UNKNOWN');
  }
});

test('module object traversal selects known attributes without losing nullable siblings', () => {
  for (const [encrypted, status] of [[true, 'PASS'], [null, 'UNKNOWN']] as const) {
    const changes = readPlan(plan([
      rc('module.settings.aws_efs_file_system.example', 'aws_efs_file_system', ['create'], { encrypted: true }),
      rc('aws_efs_file_system.example', 'aws_efs_file_system', ['create'], { encrypted: true }),
    ], [], { variables: { config: { value: { nested: { encrypted }, other: null } } }, configuration: { root_module: {
      resources: [cfg('aws_efs_file_system.example', { encrypted: ['module.settings.config.nested.encrypted', 'module.settings.config', 'module.settings'] })],
      module_calls: { settings: { expressions: { config: { references: ['var.config'] } }, module: {
        resources: [cfg('aws_efs_file_system.example', { encrypted: ['var.config.nested.encrypted', 'var.config'] })],
        outputs: { config: { expression: { references: ['var.config'] } } },
      } } },
    } } }));
    expect(evaluatePolicies(changes).filter((f) => f.ruleId === 'efs.encryption').map((f) => f.status)).toEqual(['UNKNOWN', 'UNKNOWN']);
    const source = new MemorySource({ 'main.tf': `
      variable "config" {}
      module "settings" {
        source = "./settings"
        config = var.config
      }
      resource "aws_efs_file_system" "example" { encrypted = module.settings.config.nested.encrypted }
    `, 'settings/main.tf': `
      variable "config" {}
      resource "aws_efs_file_system" "example" { encrypted = var.config.nested.encrypted }
      output "config" { value = var.config }
    ` });
    expect(evaluatePolicies(compareEvaluations(undefined, evaluateRoot(source, '.', { config: { nested: { encrypted }, other: null } })))
      .filter((f) => f.ruleId === 'efs.encryption').map((f) => f.status)).toEqual([status, status]);
  }
});

test('source evaluation preserves uncertainty through nested attributes, functions, locals and module outputs', () => {
  const source = new MemorySource({ 'main.tf': `
    variable "config" { default = { encrypted = null, known = true } }
    variable "missing" {}
    variable "snapshot" { default = null }
    locals { fallback = coalesce(var.config.encrypted, true) }
    module "settings" {
      source = "./settings"
      enabled = local.fallback
    }
    resource "aws_efs_file_system" "fallback" { encrypted = local.fallback }
    resource "aws_efs_file_system" "module" { encrypted = module.settings.encrypted }
    resource "aws_efs_file_system" "unknown" { encrypted = var.missing ? true : true }
    resource "aws_efs_file_system" "unused_fallback" { encrypted = coalesce(true, var.config.encrypted) }
    resource "aws_efs_file_system" "comparison" { encrypted = var.config.encrypted == null }
    resource "aws_efs_file_system" "unary" { encrypted = !var.config.encrypted }
    resource "aws_efs_file_system" "known_attribute" { encrypted = var.config.known }
    resource "aws_efs_file_system" "known" { encrypted = coalesce(true, false) }
    resource "aws_ebs_volume" "snapshot" {
      encrypted = false
      snapshot_id = coalesce(var.snapshot, "snap-external")
    }
  `, 'settings/main.tf': `
    variable "enabled" {}
    output "encrypted" { value = var.enabled }
  ` });
  const evaluated = evaluateRoot(source, '.');
  expect(evaluated.diagnostics).toEqual([]);
  expect(evaluatePolicies(compareEvaluations(undefined, evaluated)).filter((f) => ['efs.encryption', 'ebs.encryption'].includes(f.ruleId))
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_efs_file_system.fallback', 'UNKNOWN'], ['aws_efs_file_system.module', 'UNKNOWN'],
      ['aws_efs_file_system.unknown', 'UNKNOWN'], ['aws_efs_file_system.unused_fallback', 'UNKNOWN'],
      ['aws_efs_file_system.comparison', 'UNKNOWN'], ['aws_efs_file_system.unary', 'UNKNOWN'],
      ['aws_efs_file_system.known_attribute', 'PASS'], ['aws_efs_file_system.known', 'PASS'], ['aws_ebs_volume.snapshot', 'UNKNOWN'],
    ]);
});

test('null expression handling is shared across nested flags and module inputs without hiding explicit key choices', () => {
  const changes = readPlan(plan([
    rc('aws_opensearch_domain.example', 'aws_opensearch_domain', ['create'], { encrypt_at_rest: [{ enabled: true }] }),
    rc('aws_sqs_queue.example', 'aws_sqs_queue', ['create'], { sqs_managed_sse_enabled: false, kms_master_key_id: 'alias/customer' }),
    rc('aws_db_instance.null', 'aws_db_instance', ['create'], { storage_encrypted: null }),
    rc('module.omitted.aws_efs_file_system.example', 'aws_efs_file_system', ['create'], { encrypted: true }),
    rc('module.explicit.aws_efs_file_system.example', 'aws_efs_file_system', ['create'], { encrypted: false }),
  ], [], {
    variables: { encrypt: { value: null } },
    configuration: { root_module: {
      resources: [
        { address: 'aws_opensearch_domain.example', expressions: { encrypt_at_rest: [{ enabled: { references: ['var.encrypt'] } }] } },
        { address: 'aws_sqs_queue.example', expressions: { sqs_managed_sse_enabled: { references: ['var.encrypt'] }, kms_master_key_id: { constant_value: 'alias/customer' } } },
        { address: 'aws_db_instance.null', expressions: { storage_encrypted: { references: ['var.other'] } } },
      ],
      module_calls: {
        omitted: { expressions: { encrypt: { references: ['var.encrypt'] } }, module: { resources: [
          { address: 'aws_efs_file_system.example', expressions: { encrypted: { references: ['var.encrypt'] } } },
        ] } },
        explicit: { expressions: { encrypt: { constant_value: false } }, module: { resources: [
          { address: 'aws_efs_file_system.example', expressions: { encrypted: { references: ['var.encrypt'] } } },
        ] } },
      },
    } },
  }));
  expect(changes[2].configuredAfter?.storage_encrypted).toBeInstanceOf(Unknown);
  expect(evaluatePolicies(changes).filter((f) => ['opensearch.encryption', 'sqs.encryption', 'rds.encryption', 'efs.encryption'].includes(f.ruleId))
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_opensearch_domain.example', 'UNKNOWN'], ['aws_sqs_queue.example', 'PASS'], ['aws_db_instance.null', 'UNKNOWN'],
      ['module.omitted.aws_efs_file_system.example', 'UNKNOWN'], ['module.explicit.aws_efs_file_system.example', 'UNKNOWN'],
    ]);
});

test('encryption omissions and snapshot inheritance agree when evaluating HCL directly', () => {
  const source = new MemorySource({ 'main.tf': `
    variable "encrypt" { default = null }
    resource "aws_efs_file_system" "example" { encrypted = var.encrypt }
    resource "aws_db_instance" "example" { storage_encrypted = var.encrypt }
    resource "aws_ebs_snapshot_copy" "example" { encrypted = true }
    resource "aws_ebs_volume" "example" {
      encrypted = false
      snapshot_id = aws_ebs_snapshot_copy.example.id
    }
  ` });
  const evaluated = evaluateRoot(source, '.');
  expect(evaluated.diagnostics).toEqual([]);
  expect(evaluatePolicies(compareEvaluations(undefined, evaluated)).filter((f) => ['efs.encryption', 'rds.encryption', 'ebs.encryption'].includes(f.ruleId))
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_efs_file_system.example', 'UNKNOWN'], ['aws_db_instance.example', 'UNKNOWN'], ['aws_ebs_volume.example', 'UNKNOWN'],
    ]);
});

test('computed global membership does not suppress explicit primary encryption checks', () => {
  for (const membership of [new Unknown('known after apply'), 'computed-global-primary', new Redacted()]) {
    const address = 'aws_elasticache_replication_group.primary';
    const findings = evaluatePolicies(readPlan(plan([
      rc(address, 'aws_elasticache_replication_group', ['create'], {
        global_replication_group_id: membership,
        at_rest_encryption_enabled: false, transit_encryption_enabled: false,
      }),
    ], [], { configuration: { root_module: { resources: [{ address, expressions: {
      at_rest_encryption_enabled: { constant_value: false }, transit_encryption_enabled: { constant_value: false },
    } }] } } }))).filter((f) => f.ruleId.startsWith('elasticache.'));
    expect(findings.map((f) => [f.ruleId, f.status])).toEqual([
      ['elasticache.encryption', 'WARN'], ['elasticache.transit-encryption', 'WARN'],
    ]);
  }
});

test('enabling regional EBS defaults does not attest encryption of an existing volume', () => {
  const base = new MemorySource({ 'main.tf': `
    resource "aws_ebs_encryption_by_default" "regional" { enabled = false }
    resource "aws_ebs_volume" "existing" { size = 10 }
  ` });
  const head = new MemorySource({ 'main.tf': `
    resource "aws_ebs_encryption_by_default" "regional" { enabled = true }
    resource "aws_ebs_volume" "existing" { size = 20 }
  ` });
  const findings = evaluatePolicies(compareEvaluations(evaluateRoot(base, '.'), evaluateRoot(head, '.')));
  expect(findings.find((f) => f.ruleId === 'ebs.encryption')?.status).toBe('UNKNOWN');
});

test('ignored encryption configuration is UNKNOWN on existing resources and applies on create', () => {
  const source = (encrypted: boolean, team: string, ignored: string) => new MemorySource({ 'main.tf': `
    resource "aws_efs_file_system" "existing" {
      encrypted = ${encrypted}
      tags = { team = "${team}" }
      lifecycle { ignore_changes = ${ignored} }
    }
  ` });
  for (const ignored of ['[encrypted]', 'all']) {
    for (const encrypted of [true, false]) {
      const head = evaluateRoot(source(encrypted, 'new', ignored), '.');
      const changes = compareEvaluations(evaluateRoot(source(!encrypted, 'old', ignored), '.'), head);
      expect(changes[0].after?.encrypted).toBe(!encrypted);
      if (ignored === '[encrypted]') {
        expect(changes[0].action).toBe('update');
        expect(evaluatePolicies(changes).find((f) => f.ruleId === 'efs.encryption')?.status).toBe('UNKNOWN');
      }
      expect(changes[0].configuredAfter?.encrypted).toBeUndefined();
      expect(evaluatePolicies(compareEvaluations(undefined, head)).find((f) => f.ruleId === 'efs.encryption')?.status)
        .toBe(encrypted ? 'PASS' : 'WARN');
    }
  }
});

test('ignored nested encryption paths do not remove evidence from other attributes', () => {
  const source = (team: string, ignored: string) => new MemorySource({ 'main.tf': `
    resource "aws_opensearch_domain" "example" {
      encrypt_at_rest { enabled = true }
      domain_endpoint_options {
        enforce_https = true
        custom_endpoint_enabled = false
      }
      tags = { team = "${team}" }
      lifecycle { ignore_changes = ${ignored} }
    }
  ` });
  for (const [ignored, encryption, https] of [
    ['[encrypt_at_rest[0].enabled]', 'UNKNOWN', 'PASS'],
    ['[encrypt_at_rest]', 'UNKNOWN', 'PASS'],
    ['[domain_endpoint_options[0].enforce_https]', 'PASS', 'UNKNOWN'],
    ['[domain_endpoint_options[0].custom_endpoint_enabled]', 'PASS', 'PASS'],
  ]) {
    const changes = compareEvaluations(evaluateRoot(source('old', ignored), '.'), evaluateRoot(source('new', ignored), '.'));
    expect(changes[0].action).toBe('update');
    expect(evaluatePolicies(changes).filter((f) => ['opensearch.encryption', 'opensearch.https'].includes(f.ruleId))
      .map((f) => [f.ruleId, f.status])).toEqual([['opensearch.encryption', encryption], ['opensearch.https', https]]);
  }
});

test('ignored regional defaults cannot attest enforcement for a new volume', () => {
  for (const ignored of ['[enabled]', 'all']) {
    const defaults = `
      resource "aws_ebs_encryption_by_default" "regional" {
        enabled = true
        lifecycle { ignore_changes = ${ignored} }
      }
    `;
    const base = new MemorySource({ 'main.tf': defaults });
    const head = new MemorySource({ 'main.tf': `${defaults}
      resource "aws_ebs_volume" "example" { encrypted = false }
    ` });
    const changes = compareEvaluations(evaluateRoot(base, '.'), evaluateRoot(head, '.'));
    expect(evaluatePolicies(changes).find((f) => f.ruleId === 'ebs.encryption')?.status).toBe('WARN');
  }
});

test('an in-place Redis to Valkey upgrade does not attest omitted at-rest encryption', () => {
  const source = (engine: string, version: string) => new MemorySource({ 'main.tf': `
    resource "aws_elasticache_replication_group" "existing" {
      engine = "${engine}"
      engine_version = "${version}"
    }
  ` });
  const changes = compareEvaluations(evaluateRoot(source('redis', '7.1'), '.'), evaluateRoot(source('valkey', '7.2'), '.'));
  expect(changes[0].action).toBe('update');
  expect(evaluatePolicies(changes).find((f) => f.ruleId === 'elasticache.encryption')?.status).toBe('UNKNOWN');
});

test('regional EBS enforcement suppresses explicit-false warnings only at creation in the same provider and region', () => {
  const cases: Array<[string[], Attrs, Attrs, string, FindingStatus]> = [
    [['create'], { enabled: true }, {}, 'aws.same', 'UNKNOWN'],
    [['delete', 'create'], { enabled: true }, {}, 'aws.same', 'UNKNOWN'],
    [['update'], { enabled: true }, {}, 'aws.same', 'WARN'],
    [['create'], { enabled: false }, {}, 'aws.same', 'WARN'],
    [['create'], {}, {}, 'aws.same', 'WARN'],
    [['create'], { enabled: new Unknown('enabled') }, {}, 'aws.same', 'WARN'],
    [['create'], { enabled: true }, {}, 'aws.other', 'WARN'],
    [['create'], { enabled: true, region: 'us-east-1' }, { region: 'us-west-2' }, 'aws.same', 'WARN'],
    [['create'], { enabled: true, region: 'us-east-1' }, { region: 'us-east-1' }, 'aws.same', 'UNKNOWN'],
  ];
  for (const [actions, defaults, volume, provider, status] of cases) {
    const changes = readPlan(plan([
      rc('aws_ebs_encryption_by_default.regional', 'aws_ebs_encryption_by_default', ['no-op'], defaults, { before: defaults }),
      rc('aws_ebs_volume.example', 'aws_ebs_volume', actions, { encrypted: false, ...volume }, { before: { encrypted: false } }),
    ]));
    changes[0].providerAddress = 'aws.same';
    changes[1].providerAddress = provider;
    expect(evaluatePolicies(changes).find((f) => f.ruleId === 'ebs.encryption')?.status).toBe(status);
  }
});

test('a listener-rule-only redirect downgrade re-evaluates its unchanged listener', () => {
  const listener = { arn: 'listener-http', protocol: 'HTTP', default_action: [{ type: 'forward' }] };
  const rule = { listener_arn: 'listener-http', priority: 1, condition: [{ path_pattern: [{ values: ['/*'] }] }] };
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_lb_listener.http', 'aws_lb_listener', ['no-op'], listener, { before: listener }),
    rc('aws_lb_listener_rule.routing', 'aws_lb_listener_rule', ['update'], { ...rule, action: [{ type: 'forward' }] }, {
      before: { ...rule, action: [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }] },
    }),
  ]))).filter((f) => f.ruleId === 'elb.https');
  expect(findings.map((f) => [f.resource, f.status, f.preExisting])).toEqual([['aws_lb_listener.http', 'WARN', undefined]]);
});

test('an unresolved listener owner reports UNKNOWN on the changed rule', () => {
  const address = 'aws_lb_listener_rule.routing';
  const findings = evaluatePolicies(readPlan(plan([
    rc(address, 'aws_lb_listener_rule', ['update'], { listener_arn: new Unknown('external listener'), action: [{ type: 'forward' }] }),
  ]))).filter((f) => f.ruleId === 'elb.https');
  expect(findings.map((f) => [f.resource, f.status, f.remediation])).toEqual([[address, 'UNKNOWN', undefined]]);
});

test('listener-rule creation, replacement and deletion re-evaluate the unchanged owner', () => {
  const redirect = [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }];
  const forward = [{ type: 'forward' }];
  const listener = { arn: 'listener-http', protocol: 'HTTP', default_action: forward };
  const rule = { listener_arn: 'listener-http', priority: 1, condition: [{ path_pattern: [{ values: ['/*'] }] }] };
  for (const [actions, after, before, status, preExisting] of [
    [['create'], { ...rule, action: redirect }, null, 'PASS', undefined],
    [['delete', 'create'], { ...rule, action: forward }, { ...rule, action: redirect }, 'WARN', undefined],
    [['delete'], null, { ...rule, action: redirect }, 'WARN', undefined],
    [['update'], { ...rule, priority: 2, action: forward }, { ...rule, action: forward }, 'WARN', true],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_lb_listener.http', 'aws_lb_listener', ['no-op'], listener, { before: listener }),
      rc('aws_lb_listener_rule.routing', 'aws_lb_listener_rule', [...actions], after, { before }),
    ]))).filter((f) => f.ruleId === 'elb.https');
    expect(findings.map((f) => [f.resource, f.status, f.preExisting])).toEqual([['aws_lb_listener.http', status, preExisting]]);
  }
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_lb_listener_rule.external', 'aws_lb_listener_rule', ['delete'], null, { before: { listener_arn: 'external' } }),
  ]))).filter((f) => f.ruleId === 'elb.https');
  expect(findings.map((f) => [f.resource, f.status])).toEqual([['aws_lb_listener_rule.external', 'UNKNOWN']]);
});

test('EBS default encryption requires explicit enablement or disablement', () => {
  check('ebs.default-encryption', 'aws_ebs_encryption_by_default', 'CC6.1', [
    ['off', { enabled: false }, 'WARN'],
    ['on', { enabled: 'true' }, 'PASS'],
    ['default', {}, 'UNKNOWN'],
    ['null', { enabled: null }, 'UNKNOWN'],
    ['unknown', { enabled: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { enabled: new Redacted() }, 'UNKNOWN'],
    ['invalid', { enabled: 'unrecognized' }, 'UNKNOWN'],
  ]);
});

test('EBS volumes warn only about explicitly disabled encryption and leave omitted encryption UNKNOWN', () => {
  check('ebs.encryption', 'aws_ebs_volume', 'CC6.1', [
    ['off', { encrypted: 'false' }, 'WARN'],
    ['on', { encrypted: true }, 'PASS'],
    ['unset', {}, 'UNKNOWN'],
    ['null', { encrypted: null }, 'UNKNOWN'],
    ['snapshot', { snapshot_id: 'snap-example' }, 'UNKNOWN'],
    ['unknown', { encrypted: new Unknown('computed') }, 'UNKNOWN'],
    ['redacted', { encrypted: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('EBS snapshot inheritance remains UNKNOWN even when snapshot metadata says unencrypted', () => {
  const changes = readPlan(plan([
    rc('aws_ebs_snapshot_copy.encrypted', 'aws_ebs_snapshot_copy', ['create'], { id: 'snap-encrypted', encrypted: true }),
    rc('data.aws_ebs_snapshot.unencrypted', 'aws_ebs_snapshot', ['read'], { id: 'snap-unencrypted', encrypted: false }, { mode: 'data' }),
    rc('aws_ebs_volume.encrypted_snapshot', 'aws_ebs_volume', ['create'], { encrypted: false, snapshot_id: new Unknown('snapshot id') }),
    rc('aws_ebs_volume.external_snapshot', 'aws_ebs_volume', ['create'], { encrypted: false, snapshot_id: 'snap-external' }),
    rc('aws_ebs_volume.unencrypted_snapshot', 'aws_ebs_volume', ['create'], { encrypted: false, snapshot_id: 'snap-unencrypted' }),
    rc('aws_ebs_volume.explicit_enablement', 'aws_ebs_volume', ['create'], { encrypted: true, snapshot_id: 'snap-external' }),
    rc('aws_ebs_volume.null_snapshot', 'aws_ebs_volume', ['create'], { encrypted: false, snapshot_id: null }),
  ], [cfg('aws_ebs_volume.encrypted_snapshot', { snapshot_id: ['aws_ebs_snapshot_copy.encrypted.id'] })]));
  expect(evaluatePolicies(changes).filter((f) => f.ruleId === 'ebs.encryption').map((f) => [f.resource, f.status])).toEqual([
    ['aws_ebs_volume.encrypted_snapshot', 'UNKNOWN'],
    ['aws_ebs_volume.external_snapshot', 'UNKNOWN'],
    ['aws_ebs_volume.unencrypted_snapshot', 'UNKNOWN'],
    ['aws_ebs_volume.explicit_enablement', 'PASS'],
    ['aws_ebs_volume.null_snapshot', 'WARN'],
  ]);
});

test('unchanged snapshot-copy HCL cannot establish that an inherited snapshot is unencrypted', () => {
  const source = (size: number) => new MemorySource({ 'main.tf': `
    resource "aws_ebs_snapshot_copy" "example" {
      source_snapshot_id = "snap-external"
      source_region = "eu-west-1"
      encrypted = false
    }
    resource "aws_ebs_volume" "example" {
      snapshot_id = aws_ebs_snapshot_copy.example.id
      encrypted = false
      size = ${size}
    }
  ` });
  const changes = compareEvaluations(evaluateRoot(source(10), '.'), evaluateRoot(source(20), '.'));
  expect(changes.find((r) => r.type === 'aws_ebs_snapshot_copy')?.action).toBe('no-op');
  expect(evaluatePolicies(changes).find((f) => f.ruleId === 'ebs.encryption')?.status).toBe('UNKNOWN');
});

test('EBS volumes with omitted encryption remain UNKNOWN even with a declared regional default', () => {
  for (const [attrs, action, status] of [
    [{ enabled: true }, 'no-op', 'UNKNOWN'],
    [{}, 'create', 'UNKNOWN'],
    [{ enabled: false }, 'create', 'UNKNOWN'],
    [{ enabled: new Unknown('variable') }, 'create', 'UNKNOWN'],
    [{ enabled: true }, 'delete', 'UNKNOWN'],
    [{ enabled: true, region: 'us-west-2' }, 'create', 'UNKNOWN'],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_ebs_volume.example', 'aws_ebs_volume', ['create'], {}),
      rc('aws_ebs_encryption_by_default.example', 'aws_ebs_encryption_by_default', [action], action === 'delete' ? null : attrs, { before: attrs }),
    ]))).filter((f) => f.ruleId === 'ebs.encryption');
    expect(findings.map((f) => f.status)).toEqual([status]);
  }
});

test('EBS encryption defaults do not cross provider configurations or explicit regions', () => {
  const source = new MemorySource({ 'main.tf': `
    provider "aws" { alias = "encrypted" }
    provider "aws" { alias = "other" }
    resource "aws_ebs_encryption_by_default" "regional" {
      provider = aws.encrypted
      enabled = true
    }
    resource "aws_ebs_volume" "same" { provider = aws.encrypted }
    resource "aws_ebs_volume" "other" { provider = aws.other }
  ` });
  expect(evaluatePolicies(compareEvaluations(undefined, evaluateRoot(source, '.')))
    .filter((f) => f.ruleId === 'ebs.encryption').map((f) => [f.resource, f.status])).toEqual([
      ['aws_ebs_volume.same', 'UNKNOWN'],
      ['aws_ebs_volume.other', 'UNKNOWN'],
    ]);
  const changes = [
    rc('aws_ebs_encryption_by_default.regional', 'aws_ebs_encryption_by_default', ['create'], { enabled: true }),
    rc('aws_ebs_volume.same', 'aws_ebs_volume', ['create'], {}),
    rc('aws_ebs_volume.other', 'aws_ebs_volume', ['create'], {}),
    rc('aws_ebs_volume.region', 'aws_ebs_volume', ['create'], { region: 'us-west-2' }),
  ];
  const config = ['aws_ebs_encryption_by_default.regional', 'aws_ebs_volume.same', 'aws_ebs_volume.other', 'aws_ebs_volume.region']
    .map((address) => ({ address, provider_config_key: address === 'aws_ebs_volume.other' ? 'aws.other' : 'aws.encrypted' }));
  expect(evaluatePolicies(readPlan(plan(changes, config))).filter((f) => f.ruleId === 'ebs.encryption')
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_ebs_volume.same', 'UNKNOWN'],
      ['aws_ebs_volume.other', 'UNKNOWN'],
      ['aws_ebs_volume.region', 'UNKNOWN'],
    ]);
});

test('EFS encryption distinguishes configured, absent and unresolved values', () => {
  check('efs.encryption', 'aws_efs_file_system', 'CC6.1', [
    ['off', { encrypted: false }, 'WARN'],
    ['on', { encrypted: 'true' }, 'PASS'],
    ['unset', {}, 'UNKNOWN'],
    ['null', { encrypted: null }, 'UNKNOWN'],
    ['unknown', { encrypted: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { encrypted: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('ElastiCache encryption at rest requires explicit flags for Redis and Valkey', () => {
  check('elasticache.encryption', 'aws_elasticache_replication_group', 'CC6.1', [
    ['off', { at_rest_encryption_enabled: 'false', engine: 'valkey' }, 'WARN'],
    ['on', { at_rest_encryption_enabled: 'true' }, 'PASS'],
    ['unset', {}, 'UNKNOWN'],
    ['redis', { engine: 'redis' }, 'UNKNOWN'],
    ['valkey', { engine: 'valkey' }, 'UNKNOWN'],
    ['unknown_engine', { engine: new Unknown('variable') }, 'UNKNOWN'],
    ['unknown', { at_rest_encryption_enabled: new Unknown('computed'), engine: 'valkey' }, 'UNKNOWN'],
    ['redacted', { at_rest_encryption_enabled: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('OpenSearch and Elasticsearch encryption at rest handle block lists, objects and unresolved blocks', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.encryption', type, 'CC6.1', [
      ['off', { encrypt_at_rest: [{ enabled: false }] }, 'WARN'],
      ['on', { encrypt_at_rest: [{ enabled: 'true' }] }, 'PASS'],
      ['object', { encrypt_at_rest: { enabled: true } }, 'PASS'],
      ['unset', {}, 'UNKNOWN'],
      ['empty', { encrypt_at_rest: [] }, 'UNKNOWN'],
      ['unknown', { encrypt_at_rest: [{ enabled: new Unknown('computed') }] }, 'UNKNOWN'],
      ['block', { encrypt_at_rest: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { encrypt_at_rest: [new Unknown('dynamic block collection')] }, 'UNKNOWN'],
      ['redacted', { encrypt_at_rest: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('ElastiCache transit encryption warns only on explicit false', () => {
  check('elasticache.transit-encryption', 'aws_elasticache_replication_group', 'CC6.7', [
    ['off', { transit_encryption_enabled: 'false' }, 'WARN'],
    ['on', { transit_encryption_enabled: 'true' }, 'PASS'],
    ['unset', {}, 'UNKNOWN'],
    ['null', { transit_encryption_enabled: null }, 'UNKNOWN'],
    ['unknown', { transit_encryption_enabled: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { transit_encryption_enabled: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('ElastiCache global secondaries leave inherited encryption UNKNOWN without forbidden remediation', () => {
  const cases: Attrs[] = [
    { global_replication_group_id: 'global-cache' },
    { global_replication_group_id: 'global-cache', engine: 'valkey' },
    { global_replication_group_id: 'global-cache', at_rest_encryption_enabled: false, transit_encryption_enabled: false },
    { global_replication_group_id: new Unknown('primary global group') },
    { global_replication_group_id: new Redacted() },
  ];
  const findings = evaluatePolicies(readPlan(plan(cases.map((attrs, i) =>
    rc(`aws_elasticache_replication_group.secondary_${i}`, 'aws_elasticache_replication_group', ['create'], attrs)
  )))).filter((f) => f.ruleId === 'elasticache.encryption' || f.ruleId === 'elasticache.transit-encryption');
  expect(findings.map((f) => [f.status, f.remediation])).toEqual(Array.from({ length: 10 }, () => ['UNKNOWN', undefined]));
});

test('ElastiCache Memcached transit encryption checks supported versions in a VPC and preserves uncertainty', () => {
  const supported = { engine: 'memcached', engine_version: '1.6.12', subnet_group_name: 'cache-vpc' };
  check('elasticache.transit-encryption', 'aws_elasticache_cluster', 'CC6.7', [
    ['off', { ...supported, transit_encryption_enabled: false }, 'WARN'],
    ['on', { ...supported, transit_encryption_enabled: 'true' }, 'PASS'],
    ['unset', supported, 'UNKNOWN'],
    ['null', { ...supported, transit_encryption_enabled: null }, 'UNKNOWN'],
    ['later', { ...supported, engine_version: '1.6.100', transit_encryption_enabled: true }, 'PASS'],
    ['old_patch', { ...supported, engine_version: '1.6.9' }, 'UNKNOWN'],
    ['old_minor', { ...supported, engine_version: '1.5.16' }, 'UNKNOWN'],
    ['partial_version', { ...supported, engine_version: '1.6' }, 'UNKNOWN'],
    ['unknown_version', { ...supported, engine_version: new Unknown('version') }, 'UNKNOWN'],
    ['omitted_version', { ...supported, engine_version: null }, 'UNKNOWN'],
    ['unknown_vpc', { ...supported, subnet_group_name: new Unknown('subnet') }, 'UNKNOWN'],
    ['omitted_vpc', { ...supported, subnet_group_name: null }, 'UNKNOWN'],
    ['unknown_flag', { ...supported, transit_encryption_enabled: new Unknown('flag') }, 'UNKNOWN'],
    ['redacted_flag', { ...supported, transit_encryption_enabled: new Redacted() }, 'UNKNOWN'],
    ['unknown_engine', { ...supported, engine: new Unknown('engine') }, 'UNKNOWN'],
  ]);
});

test('ElastiCache Redis and Valkey cluster members are checked only at their replication group', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_elasticache_replication_group.primary', 'aws_elasticache_replication_group', ['create'], { transit_encryption_enabled: false }),
    ...['redis', 'valkey', undefined].map((engine, i) =>
      rc(`aws_elasticache_cluster.member[${i}]`, 'aws_elasticache_cluster', ['create'], { engine, replication_group_id: 'primary' })
    ),
    rc('aws_elasticache_cluster.pending', 'aws_elasticache_cluster', ['create'], { replication_group_id: new Unknown('group') }),
  ]))).filter((f) => f.ruleId === 'elasticache.transit-encryption');
  expect(findings.map((f) => [f.resource, f.status])).toEqual([['aws_elasticache_replication_group.primary', 'WARN'], ['aws_elasticache_cluster.pending', 'UNKNOWN']]);
});

test('OpenSearch and Elasticsearch node encryption requires explicit flags and preserves block uncertainty', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.node-to-node-encryption', type, 'CC6.7', [
      ['off', { node_to_node_encryption: [{ enabled: 'false' }] }, 'WARN'],
      ['on', { node_to_node_encryption: { enabled: 'true' } }, 'PASS'],
      ['unset', {}, 'UNKNOWN'],
      ['empty', { node_to_node_encryption: [] }, 'UNKNOWN'],
      ['unknown', { node_to_node_encryption: [{ enabled: new Unknown('variable') }] }, 'UNKNOWN'],
      ['block', { node_to_node_encryption: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { node_to_node_encryption: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
      ['redacted', { node_to_node_encryption: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('OpenSearch and Elasticsearch HTTPS enforcement requires an explicit option', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.https', type, 'CC6.7', [
      ['off', { domain_endpoint_options: [{ enforce_https: 'false' }] }, 'WARN'],
      ['on', { domain_endpoint_options: { enforce_https: 'true' } }, 'PASS'],
      ['option_default', { domain_endpoint_options: [{}] }, 'UNKNOWN'],
      ['unset', {}, 'UNKNOWN'],
      ['empty', { domain_endpoint_options: [] }, 'UNKNOWN'],
      ['unknown', { domain_endpoint_options: [{ enforce_https: new Unknown('variable') }] }, 'UNKNOWN'],
      ['block', { domain_endpoint_options: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { domain_endpoint_options: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
      ['redacted', { domain_endpoint_options: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('HTTP listeners warn unless their default action redirects to HTTPS, preserving unknown actions', () => {
  check('elb.https', 'aws_lb_listener', 'CC6.7', [
    ['forward', { protocol: 'HTTP', default_action: [{ type: 'forward' }] }, 'WARN'],
    ['redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }] }, 'PASS'],
    ['object', { protocol: 'HTTP', default_action: { type: 'redirect', redirect: { protocol: 'HTTPS' } } }, 'PASS'],
    ['http_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: 'HTTP' }] }] }, 'WARN'],
    ['inherited_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{}] }] }, 'UNKNOWN'],
    ['unset_action', { protocol: 'HTTP' }, 'UNKNOWN'],
    ['unknown_action', { protocol: 'HTTP', default_action: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic_action', { protocol: 'HTTP', default_action: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['unknown_type', { protocol: 'HTTP', default_action: [{ type: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: new Unknown('computed') }] }, 'UNKNOWN'],
    ['unknown_target', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: new Unknown('variable') }] }] }, 'UNKNOWN'],
    ['https', { protocol: 'HTTPS' }, 'PASS'],
    ['unknown_protocol', { protocol: new Unknown('variable') }, 'UNKNOWN'],
    ['missing_protocol', {}, 'UNKNOWN'],
  ]);
  expect(evaluatePolicies(readPlan(plan([rc('aws_lb_listener.tcp', 'aws_lb_listener', ['create'], { protocol: 'TCP' })])))).toEqual([]);
});

test('HTTP listener HTTPS redirects account for catch-all rule conditions, association and priority', () => {
  const redirect = [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }];
  const forward = [{ type: 'forward' }];
  const catchAll = [{ path_pattern: [{ values: ['/*'] }] }];
  const partial = [{ path_pattern: [{ values: ['/admin/*'] }] }];
  const rule = (attrs: Attrs): Attrs => ({ listener_arn: 'listener-http', priority: 10, condition: catchAll, action: redirect, ...attrs });
  const cases: Array<[string, Attrs[], FindingStatus]> = [
    ['catch_all', [rule({ priority: 1 })], 'PASS'],
    ['star', [rule({ condition: { path_pattern: { values: ['*'] } } })], 'PASS'],
    ['later_forward', [rule({}), rule({ priority: 20, condition: partial, action: forward })], 'PASS'],
    ['earlier_redirect', [rule({}), rule({ priority: 1, condition: partial })], 'PASS'],
    ['earlier_forward', [rule({}), rule({ priority: 1, condition: partial, action: forward })], 'WARN'],
    ['unknown_priority', [rule({ priority: new Unknown('priority') })], 'UNKNOWN'],
    ['unknown_earlier_priority', [rule({}), rule({ priority: new Unknown('priority'), action: forward })], 'UNKNOWN'],
    ['unknown_condition', [rule({ condition: new Unknown('dynamic condition') })], 'UNKNOWN'],
    ['unknown_matching_path', [rule({ condition: [{ path_pattern: [{ values: new Unknown('paths') }] }], action: forward })], 'UNKNOWN'],
    ['unknown_action', [rule({ action: new Unknown('action') })], 'UNKNOWN'],
    ['unrecognized_action', [rule({ action: [{ type: 'unrecognized' }] })], 'UNKNOWN'],
    ['unknown_listener', [rule({ listener_arn: new Unknown('listener') })], 'UNKNOWN'],
    ['conditional', [rule({ condition: partial })], 'UNKNOWN'],
    ['additional_condition', [rule({ condition: [...catchAll, { host_header: [{ values: ['example.com'] }] }] })], 'UNKNOWN'],
    ['different_listener', [rule({ listener_arn: 'listener-other' })], 'WARN'],
  ];
  for (const [name, rules, status] of cases) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { arn: 'listener-http', protocol: 'HTTP', default_action: forward }),
      ...rules.map((attrs, i) => rc(`aws_lb_listener_rule.rule_${i}`, 'aws_lb_listener_rule', ['create'], attrs)),
    ]))).filter((f) => f.ruleId === 'elb.https' && f.resource === 'aws_lb_listener.http');
    expect([name, findings.map((f) => f.status)]).toEqual([name, [status]]);
  }
});

test('HTTP listener rule references preserve unresolved listener association', () => {
  for (const [listenerArn, ruleArn, refs, status] of [
    [new Unknown('listener ARN'), new Unknown('listener ARN'), ['aws_lb_listener.http.arn'], 'PASS'],
    ['listener-http', new Unknown('conditional listener ARN'), ['aws_lb_listener.http.arn', 'aws_lb_listener.other.arn'], 'UNKNOWN'],
    [new Unknown('listener ARN'), 'listener-rule-target', [], 'UNKNOWN'],
    ['listener-http', new Unknown('module output'), ['module.external.listener_arn'], 'UNKNOWN'],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { arn: listenerArn, protocol: 'HTTP', default_action: [{ type: 'forward' }] }),
      rc('aws_lb_listener_rule.redirect', 'aws_lb_listener_rule', ['create'], {
        listener_arn: ruleArn, priority: 1,
        condition: [{ path_pattern: [{ values: ['/*'] }] }],
        action: [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }],
      }),
    ], [cfg('aws_lb_listener_rule.redirect', { listener_arn: [...refs] })])))
      .filter((f) => f.ruleId === 'elb.https' && f.resource === 'aws_lb_listener.http');
    expect(findings.map((f) => f.status)).toEqual([status]);
  }
});

test('HTTPS listener policies require a TLS 1.2 floor rather than a recent policy date', () => {
  check('elb.tls-policy', 'aws_lb_listener', 'CC6.7', [
    ['legacy', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' }, 'WARN'],
    ['tls11', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS-1-1-2017-01' }, 'WARN'],
    ['modern_but_weak', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-0-2021-06' }, 'WARN'],
    ['tls12', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS-1-2-2017-01' }, 'PASS'],
    ['tls13', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' }, 'PASS'],
    ['tls13_only', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-3-2021-06' }, 'PASS'],
    ['forward_secrecy', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-FS-1-2-Res-2020-10' }, 'PASS'],
    ['post_quantum', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' }, 'PASS'],
    ['default', { protocol: 'HTTPS' }, 'UNKNOWN'],
    ['unknown', { protocol: 'HTTPS', ssl_policy: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { protocol: 'HTTPS', ssl_policy: new Redacted() }, 'UNKNOWN'],
    ['unrecognized', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-future' }, 'UNKNOWN'],
  ]);
  expect(evaluatePolicies(readPlan(plan([rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { protocol: 'HTTP' })])))
    .filter((f) => f.ruleId === 'elb.tls-policy')).toEqual([]);
});

test('CloudFront HTTPS checks default and every ordered behavior and retains unresolved behavior uncertainty', () => {
  check('cloudfront.https', 'aws_cloudfront_distribution', 'CC6.7', [
    ['http', { default_cache_behavior: [{ viewer_protocol_policy: 'allow-all' }] }, 'WARN'],
    ['https', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }] }, 'PASS'],
    ['redirect', { default_cache_behavior: { viewer_protocol_policy: 'redirect-to-https' } }, 'PASS'],
    ['ordered_http', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }], ordered_cache_behavior: [
      { path_pattern: '/safe/*', viewer_protocol_policy: 'redirect-to-https' },
      { path_pattern: '/unsafe/*', viewer_protocol_policy: 'allow-all' },
    ] }, 'WARN'],
    ['unset', {}, 'UNKNOWN'],
    ['unknown_policy', { default_cache_behavior: [{ viewer_protocol_policy: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_default', { default_cache_behavior: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic_ordered', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }], ordered_cache_behavior: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['redacted', { default_cache_behavior: new Redacted() }, 'UNKNOWN'],
    ['invalid', { default_cache_behavior: [{ viewer_protocol_policy: 'unrecognized' }] }, 'UNKNOWN'],
  ]);
});

test('CloudFront TLS versions distinguish TLS 1.2 policies from legacy and unresolved certificate settings', () => {
  check('cloudfront.tls-policy', 'aws_cloudfront_distribution', 'CC6.7', [
    ['ssl3', { viewer_certificate: [{ minimum_protocol_version: 'SSLv3' }] }, 'WARN'],
    ['tls1', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1' }] }, 'WARN'],
    ['tls1_2016', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1_2016' }] }, 'WARN'],
    ['tls11', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.1_2016' }] }, 'WARN'],
    ['tls12', { viewer_certificate: { minimum_protocol_version: 'TLSv1.2_2018' } }, 'PASS'],
    ['tls12_2021', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.2_2021' }] }, 'PASS'],
    ['tls13', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.3_2025' }] }, 'PASS'],
    ['custom_default', { viewer_certificate: [{ acm_certificate_arn: 'arn:aws:acm:eu-west-1:123456789012:certificate/example' }] }, 'UNKNOWN'],
    ['cloudfront_default', { viewer_certificate: [{ cloudfront_default_certificate: true, minimum_protocol_version: 'TLSv1.2_2021' }] }, 'WARN'],
    ['unset', {}, 'UNKNOWN'],
    ['unknown', { viewer_certificate: [{ minimum_protocol_version: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_block', { viewer_certificate: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic', { viewer_certificate: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['redacted', { viewer_certificate: new Redacted() }, 'UNKNOWN'],
    ['unknown_default', { viewer_certificate: [{ cloudfront_default_certificate: new Unknown('variable'), minimum_protocol_version: 'TLSv1.2_2021' }] }, 'UNKNOWN'],
    ['unrecognized', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.2_future' }] }, 'UNKNOWN'],
  ]);
});

const moduleSource = new MemorySource({
  'main.tf': `
    variable "environments" { type = map(bool) }
    module "service" {
      source = "./service"
      for_each = var.environments
      secure = each.value
    }
  `,
  'service/main.tf': `
    variable "secure" { type = bool }
    resource "aws_ebs_encryption_by_default" "default" {
      count = 2
      enabled = var.secure
    }
    resource "aws_ebs_volume" "volume" {
      count = 2
      encrypted = var.secure
    }
    resource "aws_efs_file_system" "fs" {
      count = 2
      encrypted = var.secure
    }
    resource "aws_elasticache_replication_group" "cache" {
      count = 2
      at_rest_encryption_enabled = var.secure
      transit_encryption_enabled = var.secure
    }
    resource "aws_opensearch_domain" "search" {
      count = 2
      encrypt_at_rest { enabled = var.secure }
      node_to_node_encryption { enabled = var.secure }
      domain_endpoint_options { enforce_https = var.secure }
    }
    resource "aws_elasticsearch_domain" "legacy" {
      count = 2
      encrypt_at_rest { enabled = var.secure }
      node_to_node_encryption { enabled = var.secure }
      domain_endpoint_options { enforce_https = var.secure }
    }
    resource "aws_lb_listener" "http" {
      count = 2
      protocol = "HTTP"
      default_action {
        type = "redirect"
        redirect {
          protocol = var.secure ? "HTTPS" : "HTTP"
          status_code = "HTTP_301"
        }
      }
    }
    resource "aws_lb_listener" "tls" {
      count = 2
      protocol = "HTTPS"
      ssl_policy = var.secure ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : "ELBSecurityPolicy-2016-08"
    }
    resource "aws_cloudfront_distribution" "cdn" {
      count = 2
      default_cache_behavior { viewer_protocol_policy = "https-only" }
      ordered_cache_behavior { viewer_protocol_policy = var.secure ? "https-only" : "allow-all" }
      viewer_certificate { minimum_protocol_version = var.secure ? "TLSv1.2_2021" : "TLSv1" }
    }
  `,
});

const moduleRules = [
  ['ebs.default-encryption', 'aws_ebs_encryption_by_default.default'],
  ['ebs.encryption', 'aws_ebs_volume.volume'],
  ['efs.encryption', 'aws_efs_file_system.fs'],
  ['elasticache.encryption', 'aws_elasticache_replication_group.cache'],
  ['elasticache.transit-encryption', 'aws_elasticache_replication_group.cache'],
  ['opensearch.encryption', 'aws_opensearch_domain.search'],
  ['opensearch.node-to-node-encryption', 'aws_opensearch_domain.search'],
  ['opensearch.https', 'aws_opensearch_domain.search'],
  ['opensearch.encryption', 'aws_elasticsearch_domain.legacy'],
  ['opensearch.node-to-node-encryption', 'aws_elasticsearch_domain.legacy'],
  ['opensearch.https', 'aws_elasticsearch_domain.legacy'],
  ['elb.https', 'aws_lb_listener.http'],
  ['elb.tls-policy', 'aws_lb_listener.tls'],
  ['cloudfront.https', 'aws_cloudfront_distribution.cdn'],
  ['cloudfront.tls-policy', 'aws_cloudfront_distribution.cdn'],
];

test('encryption checks resolve Terraform listener and subnet references with counted resources', () => {
  const source = new MemorySource({ 'main.tf': `
    resource "aws_ebs_encryption_by_default" "regional" { enabled = true }
    resource "aws_ebs_volume" "volume" { availability_zone = "eu-west-1a" }
    resource "aws_lb_listener" "http" {
      count = 2
      protocol = "HTTP"
      default_action { type = "forward" }
    }
    resource "aws_lb_listener_rule" "redirect" {
      count = 2
      listener_arn = aws_lb_listener.http[count.index].arn
      priority = 1
      action {
        type = "redirect"
        redirect {
          protocol = "HTTPS"
          status_code = "HTTP_301"
        }
      }
      condition { path_pattern { values = ["/*"] } }
    }
    resource "aws_elasticache_replication_group" "secondary" { global_replication_group_id = "global-cache" }
    resource "aws_elasticache_subnet_group" "cache" {
      name_prefix = "cache-"
      subnet_ids = ["subnet-vpc"]
    }
    resource "aws_elasticache_cluster" "memcached" {
      count = 2
      engine = "memcached"
      engine_version = "1.6.12"
      subnet_group_name = aws_elasticache_subnet_group.cache.name
      transit_encryption_enabled = count.index == 0
    }
    resource "aws_elasticache_cluster" "replica" { replication_group_id = aws_elasticache_replication_group.secondary.id }
  ` });
  const evaluated = evaluateRoot(source, '.');
  expect(evaluated.diagnostics).toEqual([]);
  const findings = evaluatePolicies(compareEvaluations(undefined, evaluated)).filter((f) =>
    ['ebs.encryption', 'elb.https', 'elasticache.encryption', 'elasticache.transit-encryption'].includes(f.ruleId));
  expect(findings.map((f) => [f.resource, f.ruleId, f.status])).toEqual([
    ['aws_ebs_volume.volume', 'ebs.encryption', 'UNKNOWN'],
    ['aws_lb_listener.http[0]', 'elb.https', 'PASS'],
    ['aws_lb_listener.http[1]', 'elb.https', 'PASS'],
    ['aws_elasticache_replication_group.secondary', 'elasticache.encryption', 'UNKNOWN'],
    ['aws_elasticache_replication_group.secondary', 'elasticache.transit-encryption', 'UNKNOWN'],
    ['aws_elasticache_cluster.memcached[0]', 'elasticache.transit-encryption', 'PASS'],
    ['aws_elasticache_cluster.memcached[1]', 'elasticache.transit-encryption', 'WARN'],
  ]);
});

test('all encryption rules evaluate separate count instances inside for_each modules through static HCL', () => {
  const evaluation = evaluateRoot(moduleSource, '.', { environments: { secure: true, insecure: false } });
  expect(evaluation.diagnostics).toEqual([]);
  const result = analyze(compareEvaluations(undefined, evaluation));
  for (const [rule, resource] of moduleRules) {
    for (const [env, status] of [['secure', 'PASS'], ['insecure', 'WARN']]) {
      const addresses = [0, 1].map((i) => `module.service["${env}"].${resource}[${i}]`);
      // Regional EBS enforcement spans every module using this provider configuration.
      expect(result.findings.filter((f) => f.ruleId === rule && addresses.includes(f.resource)).map((f) => [f.resource, f.status]))
        .toEqual(addresses.map((address) => [address, rule === 'ebs.encryption' && env === 'insecure' ? 'UNKNOWN' : status]));
    }
  }
  expect(result.findings.some((f) => f.status === 'FAIL')).toBe(false);
  expect(result.gate).toEqual({ result: 'pass', items: [], reasons: [] });
});

test('symbolic for_each modules keep unresolved encryption values UNKNOWN', () => {
  const evaluation = evaluateRoot(moduleSource, '.');
  expect(evaluation.diagnostics).toEqual([]);
  const findings = evaluatePolicies(compareEvaluations(undefined, evaluation));
  for (const [rule, resource] of moduleRules) {
    const addresses = [0, 1].map((i) => `module.service[*].${resource}[${i}]`);
    expect(findings.filter((f) => f.ruleId === rule && addresses.includes(f.resource)).map((f) => [f.resource, f.status]))
      .toEqual(addresses.map((address) => [address, 'UNKNOWN']));
  }
});

test('encryption findings preserve pre-existing detection, exceptions, Markdown and v1 change records', () => {
  const changes = readPlan(plan([
    rc('aws_ebs_volume.preexisting', 'aws_ebs_volume', ['update'], { encrypted: false, tags: { team: 'new' } }, { before: { encrypted: false } }),
    rc('aws_lb_listener.downgrade', 'aws_lb_listener', ['update'], { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' }, { before: { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' } }),
    rc('aws_efs_file_system.pending', 'aws_efs_file_system', ['create'], {}, { afterUnknown: { encrypted: true } }),
    rc('aws_ebs_volume.deleted', 'aws_ebs_volume', ['delete'], null, { before: { encrypted: false } }),
    rc('aws_ebs_volume.unchanged', 'aws_ebs_volume', ['no-op'], { encrypted: false }),
    rc('aws_ebs_volume.data', 'aws_ebs_volume', ['create'], { encrypted: false }, { mode: 'data' }),
  ]));
  const result = analyze(changes, {
    now: new Date('2026-10-29T00:00:00Z'),
    policy: { exceptions: [{ rule: 'elb.tls-policy', resource: '*', reason: 'Legacy client migration', expires: '2026-12-31' }] },
  });
  expect(result.findings.map((f) => [f.resource, f.ruleId, f.status, f.preExisting, f.accepted?.reason])).toEqual([
    ['aws_ebs_volume.preexisting', 'ebs.encryption', 'WARN', true, undefined],
    ['aws_lb_listener.downgrade', 'elb.https', 'PASS', undefined, undefined],
    ['aws_lb_listener.downgrade', 'elb.tls-policy', 'WARN', undefined, 'Legacy client migration'],
    ['aws_efs_file_system.pending', 'efs.encryption', 'UNKNOWN', undefined, undefined],
  ]);
  // The volume deletion still blocks through the existing blast-radius check, not encryption.
  expect(result.gate.result).toBe('block');
  expect(result.gate.items.map((item) => [item.rule, item.level])).toEqual([['blast-radius', 'block']]);
  const markdown = renderMarkdown(JSON.parse(JSON.stringify(result)), {});
  expect(markdown).toContain('A.8.24, SOC 2 CC6.7');
  expect(markdown).toContain('A.8.24, SOC 2 CC6.1');
  const record = changeRecord({
    commit: { sha: 'a'.repeat(40), parents: ['b'.repeat(40)], subject: 'encryption settings', author: 'Dev', date: '2026-10-29T00:00:00Z' },
    base: 'b'.repeat(40), roots: [], result, appLinks: [], engine: { version: 'test', replaceCatalog: 'test' },
  });
  expect(record.schema).toBe('diffseal.change-record/v1');
  expect(record.controls).toHaveLength(4);
  expect(record.controls.map((c) => [c.control, c.category, c.frameworks.soc2_tsc])).toEqual([
    ['ISO27001:A.8.24', 'encryption-at-rest', [{ ref: 'CC6.1', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-in-transit', [{ ref: 'CC6.7', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-in-transit', [{ ref: 'CC6.7', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-at-rest', [{ ref: 'CC6.1', fit: 'direct' }]],
  ]);
});
