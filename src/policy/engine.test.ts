import { expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { Unknown } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { evaluatePolicies } from './engine.js';

test('Security Hub deletion is reviewed without asserting that an uncertain deletion is proven', () => {
  const changes = readPlan(plan([
    rc('aws_securityhub_account.delete', 'aws_securityhub_account', ['delete'], null),
    rc('aws_securityhub_account.create', 'aws_securityhub_account', ['create'], {}),
    rc('aws_securityhub_account.update', 'aws_securityhub_account', ['update'], { enable_default_standards: false }, { before: { enable_default_standards: true } }),
    rc('aws_securityhub_account.replace', 'aws_securityhub_account', ['delete', 'create'], {}),
    rc('aws_securityhub_account.noop', 'aws_securityhub_account', ['no-op'], {}),
    rc('aws_securityhub_account.data', 'aws_securityhub_account', ['delete'], null, { mode: 'data' }),
    rc('aws_securityhub_account.likely_delete', 'aws_securityhub_account', ['delete'], null, { before: { enable_default_standards: new Unknown('variable') } }),
    rc('aws_securityhub_account.unknown_delete', 'aws_securityhub_account', ['delete'], null),
  ]));
  changes.at(-2)!.confidence = 'likely';
  changes.at(-1)!.confidence = 'unknown';
  const findings = evaluatePolicies(changes);
  expect(findings.map((f) => [f.resource, f.ruleId, f.status, f.controls, f.preExisting])).toEqual([
    ['aws_securityhub_account.delete', 'securityhub.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_securityhub_account.likely_delete', 'securityhub.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_securityhub_account.unknown_delete', 'securityhub.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
  ]);
  expect(findings[1]?.detail).toContain('likely, not proven');
  expect(findings[2]?.detail).toContain('unknown, not proven');
  for (const change of changes.filter((c) => c.mode === 'managed' && c.action === 'delete')) {
    expect(analyze([change]).gate.result).toBe('review');
  }
});

test('security-service deletion findings use existing policy exceptions without changing gate output fields', () => {
  const changes = readPlan(plan([
    rc('aws_cloudtrail.trail', 'aws_cloudtrail', ['delete'], null),
    rc('aws_guardduty_detector.detector', 'aws_guardduty_detector', ['delete'], null),
    rc('aws_config_configuration_recorder_status.recorder', 'aws_config_configuration_recorder_status', ['delete'], null),
    rc('aws_securityhub_account.account', 'aws_securityhub_account', ['delete'], null),
  ]));
  const result = analyze(changes, {
    now: new Date('2026-10-29T00:00:00Z'),
    policy: { exceptions: [
      { rule: 'cloudtrail.disabled', resource: '*', reason: 'Replaced by organization coverage', expires: '2026-12-31' },
      { rule: 'guardduty.disabled', resource: '*', reason: 'Replaced by organization coverage', expires: '2026-12-31' },
      { rule: 'config.disabled', resource: '*', reason: 'Replaced by organization coverage', expires: '2026-12-31' },
      { rule: 'securityhub.disabled', resource: '*', reason: 'Replaced by organization coverage', expires: '2026-12-31' },
    ] },
  });
  expect(result.findings).toHaveLength(4);
  expect(result.findings.every((f) => f.status === 'FAIL' && f.accepted?.reason === 'Replaced by organization coverage')).toBe(true);
  expect(result.gate).toEqual({ result: 'pass', reasons: [], items: [] });
});

test('AWS Config recorder disable changes review explicit false and deletes while retaining uncertainty', () => {
  const changes = readPlan(plan([
    rc('aws_config_configuration_recorder_status.create_off', 'aws_config_configuration_recorder_status', ['create'], { is_enabled: 'false' }),
    rc('aws_config_configuration_recorder_status.disable', 'aws_config_configuration_recorder_status', ['update'], { is_enabled: false }, { before: { is_enabled: 'true' } }),
    rc('aws_config_configuration_recorder_status.preexisting', 'aws_config_configuration_recorder_status', ['update'], { is_enabled: false, tags: { team: 'new' } }, { before: { is_enabled: false } }),
    rc('aws_config_configuration_recorder_status.enabled', 'aws_config_configuration_recorder_status', ['update'], { is_enabled: true }, { before: { is_enabled: false } }),
    rc('aws_config_configuration_recorder_status.replace', 'aws_config_configuration_recorder_status', ['delete', 'create'], { is_enabled: false }, { before: { is_enabled: true } }),
    rc('aws_config_configuration_recorder_status.unknown_after', 'aws_config_configuration_recorder_status', ['update'], {}, { before: { is_enabled: true }, afterUnknown: { is_enabled: true } }),
    rc('aws_config_configuration_recorder_status.unknown_before', 'aws_config_configuration_recorder_status', ['update'], { is_enabled: false }, { before: { is_enabled: new Unknown('variable') } }),
    rc('aws_config_configuration_recorder_status.delete', 'aws_config_configuration_recorder_status', ['delete'], null, { before: { is_enabled: true } }),
    rc('aws_config_configuration_recorder_status.delete_off', 'aws_config_configuration_recorder_status', ['delete'], null, { before: { is_enabled: false } }),
    rc('aws_config_configuration_recorder_status.noop', 'aws_config_configuration_recorder_status', ['no-op'], { is_enabled: false }),
    rc('aws_config_configuration_recorder_status.data', 'aws_config_configuration_recorder_status', ['delete'], null, { mode: 'data' }),
    rc('aws_config_configuration_recorder_status.likely_disable', 'aws_config_configuration_recorder_status', ['update'], { is_enabled: false }, { before: { is_enabled: true } }),
  ]));
  changes.at(-1)!.confidence = 'likely';
  const findings = evaluatePolicies(changes);
  expect(findings.map((f) => [f.resource, f.ruleId, f.status, f.controls, f.preExisting])).toEqual([
    ['aws_config_configuration_recorder_status.create_off', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.disable', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.replace', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.unknown_after', 'config.disabled', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.unknown_before', 'config.disabled', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.delete', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.delete_off', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_config_configuration_recorder_status.likely_disable', 'config.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
  ]);
  expect(findings.at(-1)?.detail).toContain('likely, not proven');
  for (const change of changes.filter((c) => ['create_off', 'disable', 'replace', 'delete', 'delete_off', 'likely_disable'].includes(c.name))) {
    expect(analyze([change]).gate.result).toBe('review');
  }
});

test('GuardDuty disable changes review explicit false and deletes while retaining uncertainty', () => {
  const changes = readPlan(plan([
    rc('aws_guardduty_detector.create_off', 'aws_guardduty_detector', ['create'], { enable: 'false' }),
    rc('aws_guardduty_detector.disable', 'aws_guardduty_detector', ['update'], { enable: false }, { before: { enable: 'true' } }),
    rc('aws_guardduty_detector.preexisting', 'aws_guardduty_detector', ['update'], { enable: false, tags: { team: 'new' } }, { before: { enable: false } }),
    rc('aws_guardduty_detector.enabled', 'aws_guardduty_detector', ['update'], { enable: true }, { before: { enable: false } }),
    rc('aws_guardduty_detector.replace', 'aws_guardduty_detector', ['delete', 'create'], { enable: false }, { before: { enable: true } }),
    rc('aws_guardduty_detector.unknown_after', 'aws_guardduty_detector', ['update'], {}, { before: { enable: true }, afterUnknown: { enable: true } }),
    rc('aws_guardduty_detector.unknown_before', 'aws_guardduty_detector', ['update'], { enable: false }, { before: { enable: new Unknown('variable') } }),
    rc('aws_guardduty_detector.delete', 'aws_guardduty_detector', ['delete'], null, { before: { enable: true } }),
    rc('aws_guardduty_detector.delete_off', 'aws_guardduty_detector', ['delete'], null, { before: { enable: false } }),
    rc('aws_guardduty_detector.noop', 'aws_guardduty_detector', ['no-op'], { enable: false }),
    rc('aws_guardduty_detector.data', 'aws_guardduty_detector', ['delete'], null, { mode: 'data' }),
    rc('aws_guardduty_detector.likely_disable', 'aws_guardduty_detector', ['update'], { enable: false }, { before: { enable: true } }),
  ]));
  changes.at(-1)!.confidence = 'likely';
  const findings = evaluatePolicies(changes);
  expect(findings.map((f) => [f.resource, f.ruleId, f.status, f.controls, f.preExisting])).toEqual([
    ['aws_guardduty_detector.create_off', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.disable', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.replace', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.unknown_after', 'guardduty.disabled', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.unknown_before', 'guardduty.disabled', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.delete', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.delete_off', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_guardduty_detector.likely_disable', 'guardduty.disabled', 'FAIL', ['SOC2:CC7.2'], undefined],
  ]);
  expect(findings.at(-1)?.detail).toContain('likely, not proven');
  for (const change of changes.filter((c) => ['create_off', 'disable', 'replace', 'delete', 'delete_off', 'likely_disable'].includes(c.name))) {
    expect(analyze([change]).gate.result).toBe('review');
  }
});

test('CloudTrail disable changes cover transitions, replacements, unknown values and deletion', () => {
  const changes = readPlan(plan([
    rc('aws_cloudtrail.disable', 'aws_cloudtrail', ['update'], { enable_logging: 'false' }, { before: { enable_logging: 'true' } }),
    rc('aws_cloudtrail.replace', 'aws_cloudtrail', ['delete', 'create'], { enable_logging: false }, { before: {} }),
    rc('aws_cloudtrail.preexisting', 'aws_cloudtrail', ['update'], { enable_logging: false, tags: { team: 'new' } }, { before: { enable_logging: false } }),
    rc('aws_cloudtrail.create', 'aws_cloudtrail', ['create'], { enable_logging: false }),
    rc('aws_cloudtrail.enabled', 'aws_cloudtrail', ['update'], { enable_logging: true }, { before: { enable_logging: false } }),
    rc('aws_cloudtrail.unknown_after', 'aws_cloudtrail', ['update'], {}, { before: { enable_logging: true }, afterUnknown: { enable_logging: true } }),
    rc('aws_cloudtrail.unknown_before', 'aws_cloudtrail', ['update'], { enable_logging: false }, { before: { enable_logging: new Unknown('variable') } }),
    rc('aws_cloudtrail.delete', 'aws_cloudtrail', ['delete'], null, { before: { enable_logging: true } }),
    rc('aws_cloudtrail.delete_off', 'aws_cloudtrail', ['delete'], null, { before: { enable_logging: false } }),
    rc('aws_cloudtrail.likely_delete', 'aws_cloudtrail', ['delete'], null),
  ]));
  changes.at(-1)!.confidence = 'likely';
  const findings = evaluatePolicies(changes).filter((f) => f.ruleId === 'cloudtrail.disabled');
  expect(findings.map((f) => [f.resource, f.status, f.controls, f.preExisting])).toEqual([
    ['aws_cloudtrail.disable', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.replace', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.unknown_after', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.unknown_before', 'UNKNOWN', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.delete', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.delete_off', 'FAIL', ['SOC2:CC7.2'], undefined],
    ['aws_cloudtrail.likely_delete', 'FAIL', ['SOC2:CC7.2'], undefined],
  ]);
  expect(findings.at(-1)?.detail).toContain('likely, not proven');
  for (const change of changes.filter((c) => ['disable', 'replace', 'delete', 'delete_off', 'likely_delete'].includes(c.name))) {
    expect(analyze([change]).gate.result).toBe('review');
  }
  expect(evaluatePolicies([changes[2]!]).find((f) => f.ruleId === 'cloudtrail.logging')?.preExisting).toBe(true);
});

test('S3 access logging checks its declared target and does not infer missing helpers on buckets', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_s3_bucket_logging.configured', 'aws_s3_bucket_logging', ['create'], { target_bucket: 'audit-logs' }),
    rc('aws_s3_bucket_logging.missing', 'aws_s3_bucket_logging', ['create'], {}),
    rc('aws_s3_bucket_logging.empty', 'aws_s3_bucket_logging', ['create'], { target_bucket: '' }),
    rc('aws_s3_bucket_logging.null', 'aws_s3_bucket_logging', ['create'], { target_bucket: null }),
    rc('aws_s3_bucket_logging.unknown', 'aws_s3_bucket_logging', ['create'], {}, { afterUnknown: { target_bucket: true } }),
    rc('aws_s3_bucket_logging.deleted', 'aws_s3_bucket_logging', ['delete'], null),
    rc('aws_s3_bucket.no_helper', 'aws_s3_bucket', ['create'], {}),
  ]))).filter((f) => f.ruleId === 's3.access-logging');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_s3_bucket_logging.configured', 'PASS', ['SOC2:CC7.2']],
    ['aws_s3_bucket_logging.missing', 'WARN', ['SOC2:CC7.2']],
    ['aws_s3_bucket_logging.empty', 'WARN', ['SOC2:CC7.2']],
    ['aws_s3_bucket_logging.null', 'WARN', ['SOC2:CC7.2']],
    ['aws_s3_bucket_logging.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('CloudWatch retention reports unlimited retention as info and uses an opt-in policy minimum', () => {
  const changes = readPlan(plan([
    rc('aws_cloudwatch_log_group.unset', 'aws_cloudwatch_log_group', ['create'], {}),
    rc('aws_cloudwatch_log_group.null', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: null }),
    rc('aws_cloudwatch_log_group.forever', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: '0' }),
    rc('aws_cloudwatch_log_group.short', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: '7' }),
    rc('aws_cloudwatch_log_group.minimum', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: 30 }),
    rc('aws_cloudwatch_log_group.long', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: 90 }),
    rc('aws_cloudwatch_log_group.unknown', 'aws_cloudwatch_log_group', ['create'], {}, { afterUnknown: { retention_in_days: true } }),
    rc('aws_cloudwatch_log_group.deleted', 'aws_cloudwatch_log_group', ['delete'], null),
  ]));
  expect(evaluatePolicies(changes, { minLogRetentionDays: 30 }).map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_cloudwatch_log_group.unset', 'INFO', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.null', 'INFO', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.forever', 'INFO', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.short', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.minimum', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.long', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudwatch_log_group.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
  expect(evaluatePolicies(changes).find((f) => f.resource === 'aws_cloudwatch_log_group.short')?.status).toBe('PASS');
});

test('CloudWatch DELIVERY retention is two days regardless of the configured retention', () => {
  const changes = readPlan(plan([
    rc('aws_cloudwatch_log_group.unset', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'DELIVERY' }),
    rc('aws_cloudwatch_log_group.null', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'DELIVERY', retention_in_days: null }),
    rc('aws_cloudwatch_log_group.zero', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'DELIVERY', retention_in_days: 0 }),
    rc('aws_cloudwatch_log_group.long', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'DELIVERY', retention_in_days: 90 }),
    rc('aws_cloudwatch_log_group.unknown', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'DELIVERY' }, { afterUnknown: { retention_in_days: true } }),
  ]));
  const findings = evaluatePolicies(changes, { minLogRetentionDays: 30 });
  expect(findings.map((f) => [f.resource, f.status])).toEqual([
    ['aws_cloudwatch_log_group.unset', 'WARN'],
    ['aws_cloudwatch_log_group.null', 'WARN'],
    ['aws_cloudwatch_log_group.zero', 'WARN'],
    ['aws_cloudwatch_log_group.long', 'WARN'],
    ['aws_cloudwatch_log_group.unknown', 'WARN'],
  ]);
  for (const finding of findings) {
    expect(finding.detail).toContain('2 day(s)');
    expect(finding.remediation).toContain('log_group_class');
  }
  for (const finding of evaluatePolicies(changes, { minLogRetentionDays: 2 })) {
    expect(finding.status).toBe('PASS');
    expect(finding.detail).toContain('2 day(s)');
  }
});

test('CloudWatch retention stays unknown when the log group class cannot be determined', () => {
  const changes = readPlan(plan([
    rc('aws_cloudwatch_log_group.unset', 'aws_cloudwatch_log_group', ['create'], {}, { afterUnknown: { log_group_class: true } }),
    rc('aws_cloudwatch_log_group.zero', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: 0 }, { afterUnknown: { log_group_class: true } }),
    rc('aws_cloudwatch_log_group.long', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: 90 }, { afterUnknown: { log_group_class: true } }),
    rc('aws_cloudwatch_log_group.sensitive', 'aws_cloudwatch_log_group', ['create'], { retention_in_days: 90 }, { afterSensitive: { log_group_class: true } }),
    rc('aws_cloudwatch_log_group.unrecognized', 'aws_cloudwatch_log_group', ['create'], { log_group_class: 'UNRECOGNIZED', retention_in_days: 90 }),
  ]));
  expect(evaluatePolicies(changes, { minLogRetentionDays: 30 }).map((f) => [f.resource, f.status])).toEqual([
    ['aws_cloudwatch_log_group.unset', 'UNKNOWN'],
    ['aws_cloudwatch_log_group.zero', 'UNKNOWN'],
    ['aws_cloudwatch_log_group.long', 'UNKNOWN'],
    ['aws_cloudwatch_log_group.sensitive', 'UNKNOWN'],
    ['aws_cloudwatch_log_group.unrecognized', 'UNKNOWN'],
  ]);
});

test('VPC flow log declarations report configured VPCs and unresolved values without inferring absence', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_flow_log.vpc', 'aws_flow_log', ['create'], { vpc_id: 'vpc-123' }),
    rc('aws_flow_log.unknown', 'aws_flow_log', ['create'], {}, { afterUnknown: { vpc_id: true } }),
    rc('aws_flow_log.subnet', 'aws_flow_log', ['create'], { subnet_id: 'subnet-123' }),
    rc('aws_flow_log.eni', 'aws_flow_log', ['create'], { eni_id: 'eni-123', vpc_id: null }),
    rc('aws_flow_log.deleted', 'aws_flow_log', ['delete'], null, { before: { vpc_id: 'vpc-123' } }),
    rc('aws_vpc.without', 'aws_vpc', ['create'], {}),
  ]))).filter((f) => f.ruleId === 'network.flow-logs');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_flow_log.vpc', 'PASS', ['SOC2:CC7.2']],
    ['aws_flow_log.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('CloudTrail KMS key flags absent keys and leaves unresolved keys unknown', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_cloudtrail.missing', 'aws_cloudtrail', ['create'], {}),
    rc('aws_cloudtrail.empty', 'aws_cloudtrail', ['create'], { kms_key_id: '' }),
    rc('aws_cloudtrail.null', 'aws_cloudtrail', ['create'], { kms_key_id: null }),
    rc('aws_cloudtrail.configured', 'aws_cloudtrail', ['create'], { kms_key_id: 'arn:aws:kms:eu-west-1:123456789012:key/example' }),
    rc('aws_cloudtrail.unknown', 'aws_cloudtrail', ['create'], {}, { afterUnknown: { kms_key_id: true } }),
    rc('aws_cloudtrail.deleted', 'aws_cloudtrail', ['delete'], null),
  ]))).filter((f) => f.ruleId === 'cloudtrail.kms-key');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_cloudtrail.missing', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.empty', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.null', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.configured', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudtrail.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('CloudTrail log file validation flags false and unset without proving unknown values', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_cloudtrail.off', 'aws_cloudtrail', ['create'], { enable_log_file_validation: false }),
    rc('aws_cloudtrail.on', 'aws_cloudtrail', ['create'], { enable_log_file_validation: 'true' }),
    rc('aws_cloudtrail.default', 'aws_cloudtrail', ['create'], {}),
    rc('aws_cloudtrail.null', 'aws_cloudtrail', ['create'], { enable_log_file_validation: null }),
    rc('aws_cloudtrail.unknown', 'aws_cloudtrail', ['create'], {}, { afterUnknown: { enable_log_file_validation: true } }),
    rc('aws_cloudtrail.deleted', 'aws_cloudtrail', ['delete'], null),
  ]))).filter((f) => f.ruleId === 'cloudtrail.log-file-validation');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_cloudtrail.off', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.on', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudtrail.default', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.null', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('CloudTrail multi-region coverage distinguishes disabled, default and unresolved settings', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_cloudtrail.off', 'aws_cloudtrail', ['create'], { is_multi_region_trail: 'false' }),
    rc('aws_cloudtrail.on', 'aws_cloudtrail', ['create'], { is_multi_region_trail: true }),
    rc('aws_cloudtrail.default', 'aws_cloudtrail', ['create'], {}),
    rc('aws_cloudtrail.unknown', 'aws_cloudtrail', ['create'], {}, { afterUnknown: { is_multi_region_trail: true } }),
    rc('aws_cloudtrail.deleted', 'aws_cloudtrail', ['delete'], null),
  ]))).filter((f) => f.ruleId === 'cloudtrail.multi-region');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_cloudtrail.off', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.on', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudtrail.default', 'WARN', ['SOC2:CC7.2']],
    ['aws_cloudtrail.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('CloudTrail logging judges explicit false, the provider default and unknown values', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_cloudtrail.off', 'aws_cloudtrail', ['create'], { enable_logging: false }),
    rc('aws_cloudtrail.on', 'aws_cloudtrail', ['create'], { enable_logging: 'true' }),
    rc('aws_cloudtrail.default', 'aws_cloudtrail', ['create'], {}),
    rc('aws_cloudtrail.unknown', 'aws_cloudtrail', ['create'], {}, { afterUnknown: { enable_logging: true } }),
    rc('aws_cloudtrail.deleted', 'aws_cloudtrail', ['delete'], null, { before: { enable_logging: false } }),
  ]))).filter((f) => f.ruleId === 'cloudtrail.logging');
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual([
    ['aws_cloudtrail.off', 'FAIL', ['SOC2:CC7.2']],
    ['aws_cloudtrail.on', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudtrail.default', 'PASS', ['SOC2:CC7.2']],
    ['aws_cloudtrail.unknown', 'UNKNOWN', ['SOC2:CC7.2']],
  ]);
});

test('findings carry SOC 2 criteria alongside their ISO controls in the existing string array', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_db_instance.db', 'aws_db_instance', ['create'], { storage_encrypted: false, backup_retention_period: 0, publicly_accessible: true }),
    rc('aws_iam_policy.p', 'aws_iam_policy', ['create'], { policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }) }),
    rc('aws_iam_role_policy_attachment.admin', 'aws_iam_role_policy_attachment', ['create'], { policy_arn: 'arn:aws:iam::aws:policy/AdministratorAccess' }),
    rc('aws_iam_access_key.key', 'aws_iam_access_key', ['create'], {}),
    rc('aws_s3_bucket.b', 'aws_s3_bucket', ['create'], { bucket: 'b' }),
  ])));
  const controls = Object.fromEntries(findings.map((f) => [f.ruleId, f.controls]));
  expect(controls).toEqual({
    'rds.encryption': ['ISO27001:A.8.24', 'SOC2:CC6.1'],
    'rds.backup-retention': ['ISO27001:A.8.13', 'SOC2:A1.2'],
    'rds.public': ['ISO27001:A.8.20', 'SOC2:CC6.6', 'SOC2:CC6.1'],
    'rds.deletion-protection': ['ISO27001:A.8.13', 'SOC2:A1.2'],
    'iam.least-privilege': ['ISO27001:A.5.15', 'ISO27001:A.5.18', 'ISO27001:A.8.3', 'SOC2:CC6.3'],
    'iam.managed-policy': ['ISO27001:A.8.2', 'SOC2:CC6.3'],
    'iam.static-credentials': ['ISO27001:A.8.5', 'SOC2:CC6.1'],
    's3.encryption': ['ISO27001:A.8.24', 'SOC2:CC6.1'],
    's3.public-access': ['ISO27001:A.8.3', 'ISO27001:A.8.12', 'SOC2:CC6.1', 'SOC2:CC6.6'],
    's3.versioning': ['ISO27001:A.8.13', 'SOC2:A1.2'],
  });
});

test('the DLQ check still reports a missing redrive policy without an unsupported ISO tag', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_sqs_queue.q', 'aws_sqs_queue', ['create'], { name: 'q' }),
  ])));
  expect(findings.find((f) => f.ruleId === 'sqs.dlq')).toMatchObject({ status: 'WARN', controls: [] });
});
