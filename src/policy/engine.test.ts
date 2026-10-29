import { expect, test } from 'bun:test';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { evaluatePolicies } from './engine.js';

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
