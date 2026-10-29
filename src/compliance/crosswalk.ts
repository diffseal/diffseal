import crosswalk from './crosswalk.json' with { type: 'json' };

/**
 * Rule category -> references in other frameworks, verified against primary sources
 * (docs/research/compliance-crosswalk.md). Empty where a source could not be checked.
 */
export type FrameworkRefs = Record<string, Array<{ ref: string; fit: string }>>;

const data = crosswalk as unknown as Record<string, Record<string, Array<{ ref: string; fit: string }>>>;

/** Which crosswalk category each rule's finding belongs to. */
export const RULE_CATEGORY: Record<string, string> = {
  's3.encryption': 'encryption-at-rest',
  'sqs.encryption': 'encryption-at-rest',
  'sns.encryption': 'encryption-at-rest',
  'dynamodb.encryption': 'encryption-at-rest',
  'rds.encryption': 'encryption-at-rest',
  'kms.rotation': 'encryption-at-rest',
  'kms.key-policy': 'least-privilege',
  's3.public-access': 'public-access',
  's3.public-access-block': 'public-access',
  's3.bucket-policy': 'public-access',
  's3.versioning': 'backup',
  'cloudtrail.logging': 'logging',
  'cloudtrail.multi-region': 'logging',
  'cloudtrail.log-file-validation': 'logging',
  'cloudtrail.kms-key': 'logging',
  'network.flow-logs': 'logging',
  'cloudwatch.log-retention': 'logging',
  's3.access-logging': 'logging',
  'cloudtrail.disabled': 'logging',
  'guardduty.disabled': 'logging',
  'config.disabled': 'logging',
  'securityhub.disabled': 'logging',
  'dynamodb.pitr': 'backup',
  'dynamodb.deletion-protection': 'backup',
  'rds.backup-retention': 'backup',
  'rds.deletion-protection': 'backup',
  'secrets.recovery-window': 'backup',
  'lambda.plaintext-secrets': 'authentication',
  'lambda.url-auth': 'authentication',
  'iam.static-credentials': 'authentication',
  'network.open-ingress': 'network-exposure',
  'rds.public': 'network-exposure',
  'iam.least-privilege': 'least-privilege',
  'iam.trust': 'privileged-access',
  'iam.managed-policy': 'privileged-access',
  'blast-radius': 'change-management',
};

export function frameworksFor(ruleId: string): { category?: string; frameworks: FrameworkRefs } {
  const category = RULE_CATEGORY[ruleId];
  const entry = category ? data[category] : undefined;
  if (!entry) return { category, frameworks: {} };
  const frameworks: FrameworkRefs = {};
  for (const [fw, refs] of Object.entries(entry)) {
    if (fw.startsWith('_') || fw === 'iso27001_2022' || !Array.isArray(refs) || !refs.length) continue;
    frameworks[fw] = refs.map((r) => ({ ref: r.ref, fit: r.fit }));
  }
  return { category, frameworks };
}
