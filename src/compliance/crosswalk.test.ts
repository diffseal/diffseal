import { expect, test } from 'bun:test';
import { frameworksFor } from './crosswalk.js';
import crosswalk from './crosswalk.json' with { type: 'json' };

test('rule themes cite only the SOC 2 criteria confirmed in the 2022 AICPA file', () => {
  // trust-center-controls.md section 4: pp. 34, 36, 38, 45 and 50.
  const expected: Record<string, string[]> = {
    's3.encryption': ['CC6.1'],
    'sqs.encryption': ['CC6.1'],
    'sns.encryption': ['CC6.1'],
    'dynamodb.encryption': ['CC6.1'],
    'rds.encryption': ['CC6.1'],
    'kms.rotation': ['CC6.1'],
    'kms.key-policy': ['CC6.3'],
    's3.public-access': ['CC6.1', 'CC6.6'],
    's3.public-access-block': ['CC6.1', 'CC6.6'],
    's3.bucket-policy': ['CC6.1', 'CC6.6'],
    's3.versioning': ['A1.2'],
    'dynamodb.pitr': ['A1.2'],
    'dynamodb.deletion-protection': ['A1.2'],
    'rds.backup-retention': ['A1.2'],
    'rds.deletion-protection': ['A1.2'],
    'secrets.recovery-window': ['A1.2'],
    'lambda.plaintext-secrets': ['CC6.1'],
    'lambda.url-auth': ['CC6.1'],
    'iam.static-credentials': ['CC6.1'],
    'network.open-ingress': ['CC6.6', 'CC6.1'],
    'rds.public': ['CC6.6', 'CC6.1'],
    'iam.least-privilege': ['CC6.3'],
    'iam.trust': ['CC6.3'],
    'iam.managed-policy': ['CC6.3'],
    'blast-radius': ['CC8.1'],
  };
  for (const [rule, refs] of Object.entries(expected)) {
    expect(frameworksFor(rule).frameworks.soc2_tsc?.map((r) => r.ref)).toEqual(refs);
  }
});

test('DLQs do not inherit backup or redundancy references from any framework', () => {
  expect(frameworksFor('sqs.dlq')).toEqual({ category: undefined, frameworks: {} });
});

test('crosswalk criteria retain the AICPA page citations and leave unconfirmed themes empty', () => {
  const citations = Object.fromEntries(Object.entries(crosswalk).filter(([theme]) => theme !== '_meta').map(([theme, entry]) => [
    theme,
    'soc2_tsc' in entry ? entry.soc2_tsc.map((r) => [r.ref, new URL(r.source).hash]) : [],
  ]));
  expect(citations).toEqual({
    'encryption-at-rest': [['CC6.1', '#page=34']],
    'encryption-in-transit': [['CC6.7', '#page=38']],
    'backup': [['A1.2', '#page=50']],
    'redundancy': [['A1.2', '#page=50']],
    'least-privilege': [['CC6.3', '#page=36']],
    'privileged-access': [['CC6.3', '#page=36']],
    'authentication': [['CC6.1', '#page=34']],
    'public-access': [['CC6.1', '#page=34'], ['CC6.6', '#page=38']],
    'network-exposure': [['CC6.6', '#page=38'], ['CC6.1', '#page=34']],
    'logging': [['CC7.2', '#page=40']],
    'supply-chain': [],
    'change-management': [['CC8.1', '#page=45']],
    'data-residency': [],
    'secure-deletion': [],
  });
});
