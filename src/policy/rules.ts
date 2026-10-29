import { configAddress, instancesCompatible, isRedacted, isUnknown, type Attrs, type ResourceChange } from '../core/model.js';
import { stableKey } from '../hcl/eval.js';
import { capitalize, type Rule, type RuleContext, type RuleResult } from './engine.js';
import { block, blocks, unknownBlock } from './values.js';
import {
  analyzeIdentityPolicy,
  analyzeManagedPolicyArn,
  analyzeTrustPolicy,
  openToAnyone,
  openUnlessUnknownCondition,
  principalUnknown,
  parsePolicy,
  worstLevel,
  type PolicyIssue,
} from './iam.js';

/*
 * Rules declare ISO/IEC 27001:2022 Annex A controls. The engine adds verified SOC 2 criteria
 * from the rule category in the crosswalk.
 * Thresholds come from the customer's policy (PolicyConfig); ISO itself does not mandate CMKs or PITR.
 */

const isSet = (v: unknown) => v !== undefined && v !== null && v !== '';

/** A data source address: `data.` after the module path. */
const isDataRef = (r: string) => /^(module\.[^.[]+(\[[^\]]*\])?\.)*data\./.test(r);

/** Classify a KMS key reference as customer managed, AWS managed, or unknown. */
function keyKind(key: unknown, res: ResourceChange, attr: string, ctx: RuleContext): 'cmk' | 'aws-managed' | 'unknown' | 'none' {
  if (isUnknown(key) || isRedacted(key)) {
    const refs = res.references[attr] ?? [];
    // A key this configuration manages is the customer's. A data source only looks a key up: it may
    // be an AWS managed one (`data "aws_kms_alias"` with `alias/aws/sqs`).
    const managed = refs.some((r) => /(^|\.)(aws_kms_key|aws_kms_replica_key|aws_kms_alias)\.[^.]+$/.test(r.replace(/\[[^\]]*\]/g, '')) && !isDataRef(r));
    if (managed) return 'cmk';
    const lookups = refs.filter((r) => isDataRef(r) && /\.(aws_kms_key|aws_kms_alias)\./.test(`.${r}`));
    // The lookup says which key: `alias/aws/...` is AWS managed, any other alias is the customer's, and
    // a lookup of a key this configuration manages is the customer's. A bare key id could be either.
    const kinds = lookups.flatMap((r) =>
      ctx.lookup(configAddress(r)).map((d): 'cmk' | 'aws-managed' | 'unknown' => {
        const v = ctx.values(d);
        const id = v.name ?? v.key_id;
        if (typeof id === 'string') return /(^|:)alias\/aws\//.test(id) ? 'aws-managed' : /(^|:)alias\//.test(id) ? 'cmk' : 'unknown';
        const via = [...(d.references.name ?? []), ...(d.references.key_id ?? [])];
        return via.some((x) => /(^|\.)(aws_kms_key|aws_kms_replica_key|aws_kms_alias)\.[^.]+$/.test(x.replace(/\[[^\]]*\]/g, '')) && !isDataRef(x)) ? 'cmk' : 'unknown';
      })
    );
    if (kinds.includes('aws-managed')) return 'aws-managed';
    return kinds.length && kinds.every((k) => k === 'cmk') ? 'cmk' : 'unknown';
  }
  if (!isSet(key)) return 'none';
  if (typeof key === 'string' && /(^|:)alias\/aws\//.test(key)) return 'aws-managed';
  return 'cmk';
}

function cmkVerdict(ctx: RuleContext, kind: 'cmk' | 'aws-managed' | 'aws-owned', description: string): RuleResult {
  if (kind !== 'cmk' && ctx.policy.requireCustomerManagedKeys) {
    return { status: 'WARN', detail: `${description}; policy requires a customer managed KMS key`, remediation: 'Encrypt with a customer managed aws_kms_key.' };
  }
  return { status: 'PASS', detail: description };
}

// ---------------------------------------------------------------- S3

function bucketEncryption(bucket: ResourceChange, values: Attrs, ctx: RuleContext): RuleResult {
  const helper = ctx.referrers(bucket, 'aws_s3_bucket_server_side_encryption_configuration', 'bucket')[0];
  const cfgSource = helper ? ctx.values(helper) : block(values.server_side_encryption_configuration);
  const rule = cfgSource ? block(cfgSource.rule) : undefined;
  const def = rule ? block(rule.apply_server_side_encryption_by_default) : undefined;
  const algo = def?.sse_algorithm;
  const unknownCfg = helper
    ? unknownBlock(ctx.values(helper).rule) || unknownBlock(rule?.apply_server_side_encryption_by_default)
    : unknownBlock(values.server_side_encryption_configuration);
  if (!def || isUnknown(algo)) {
    if (!helper && !cfgSource && !unknownCfg) {
      // The implicit default uses S3 owned keys, so a policy that requires customer managed keys still applies.
      return cmkVerdict(ctx, 'aws-owned', 'No bucket encryption configuration: S3 applies SSE-S3 (AES256) to all new objects by default since January 2023');
    }
    return { status: 'UNKNOWN', detail: 'Encryption algorithm not known until apply' };
  }
  if (algo === 'AES256') return cmkVerdict(ctx, 'aws-owned', 'SSE-S3 (AES256, S3 managed keys)');
  if (algo === 'aws:kms' || algo === 'aws:kms:dsse') {
    const label = algo === 'aws:kms' ? 'SSE-KMS' : 'DSSE-KMS';
    // References are indexed by the top-level block: `rule` on the helper, the inline block on the bucket.
    const kind = keyKind(def.kms_master_key_id, helper ?? bucket, helper ? 'rule' : 'server_side_encryption_configuration', ctx);
    if (kind === 'none' || kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', `${label} with the AWS managed key aws/s3`);
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: `${label} key not known until apply` };
    return { status: 'PASS', detail: `${label} with a customer managed KMS key` };
  }
  return { status: 'WARN', detail: `Unrecognized sse_algorithm "${String(algo)}"` };
}

const s3Encryption: Rule = {
  id: 's3.encryption',
  title: 'S3 encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_s3_bucket'],
  evaluate: (v, res, ctx) => bucketEncryption(res, v, ctx),
};

const PAB_FLAGS = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'];

function pabResult(values: Attrs): RuleResult {
  const off = PAB_FLAGS.filter((f) => values[f] !== true && !isUnknown(values[f]));
  if (off.length) {
    return { status: 'FAIL', detail: `Public access block leaves ${off.join(', ')} disabled`, remediation: 'Set all four public access block flags to true.' };
  }
  if (PAB_FLAGS.some((f) => isUnknown(values[f]))) return { status: 'UNKNOWN', detail: 'Public access block flags not known until apply' };
  return { status: 'PASS', detail: 'All four public access block flags enabled' };
}

const s3PublicAccess: Rule = {
  id: 's3.public-access',
  title: 'S3 public access restriction',
  controls: ['ISO27001:A.8.3', 'ISO27001:A.8.12'],
  types: ['aws_s3_bucket'],
  evaluate: (_v, res, ctx) => {
    const pab = ctx.referrers(res, 'aws_s3_bucket_public_access_block', 'bucket')[0];
    if (pab) return pabResult(ctx.values(pab));
    return {
      status: 'UNKNOWN',
      detail: 'No bucket-level public access block. New buckets block public access by default since April 2023 and an account-level block may apply, but neither is visible here',
      remediation: 'Add aws_s3_bucket_public_access_block with all four flags set to true.',
    };
  },
};

const s3PabResource: Rule = {
  id: 's3.public-access-block',
  title: 'S3 public access block settings',
  controls: ['ISO27001:A.8.3', 'ISO27001:A.8.12'],
  types: ['aws_s3_bucket_public_access_block', 'aws_s3_account_public_access_block'],
  evaluate: (v) => {
    const r = pabResult(v);
    return r.status === 'PASS' ? undefined : r;
  },
};

function shortestExpiryDays(lifecycle: Attrs | undefined): number | undefined {
  let min: number | undefined;
  for (const rule of blocks(lifecycle?.rule)) {
    if (rule.status !== undefined && rule.status !== 'Enabled') continue;
    const days = block(rule.expiration)?.days;
    if (typeof days === 'number' && (min === undefined || days < min)) min = days;
  }
  return min;
}

const s3Versioning: Rule = {
  id: 's3.versioning',
  title: 'S3 object versioning',
  controls: ['ISO27001:A.8.13'],
  types: ['aws_s3_bucket'],
  evaluate: (v, res, ctx) => {
    const helper = ctx.referrers(res, 'aws_s3_bucket_versioning', 'bucket')[0];
    const source = helper ? ctx.values(helper).versioning_configuration : v.versioning;
    const status = helper ? block(source)?.status : block(source)?.enabled === true ? 'Enabled' : isUnknown(block(source)?.enabled) ? block(source)!.enabled : undefined;
    if (status === 'Enabled') return { status: 'PASS', detail: 'Object versioning enabled' };
    if (isUnknown(status) || unknownBlock(source)) return { status: 'UNKNOWN', detail: 'Versioning status not known until apply' };
    const lifecycle = ctx.referrers(res, 'aws_s3_bucket_lifecycle_configuration', 'bucket')[0];
    const expiry = shortestExpiryDays(lifecycle ? ctx.values(lifecycle) : undefined);
    if (expiry !== undefined && expiry <= 7) {
      return { status: 'INFO', detail: `Objects expire after ${expiry} day(s); versioning is not expected for short-lived data` };
    }
    return {
      status: 'WARN',
      detail: status === 'Suspended' ? 'Object versioning suspended' : 'Object versioning not enabled',
      remediation: 'Add aws_s3_bucket_versioning with status = "Enabled" if objects must survive overwrite or deletion.',
    };
  },
};

const s3BucketPolicy: Rule = {
  id: 's3.bucket-policy',
  title: 'S3 bucket policy principals',
  controls: ['ISO27001:A.8.3', 'ISO27001:A.8.12'],
  types: ['aws_s3_bucket_policy'],
  evaluate: (v) => {
    const parsed = parsePolicy(v.policy);
    if (parsed.kind !== 'ok') return parsed.kind === 'unknown' ? { status: 'UNKNOWN', detail: `Bucket policy ${parsed.reason}` } : { status: 'WARN', detail: parsed.reason };
    const open = parsed.statements.filter(openToAnyone);
    if (open.length) return { status: 'FAIL', detail: 'Bucket policy allows any principal without a condition', remediation: 'Restrict Principal or add a condition (e.g. aws:SourceArn).' };
    if (parsed.statements.some((st) => principalUnknown(st) || openUnlessUnknownCondition(st))) {
      return { status: 'UNKNOWN', detail: 'Who the bucket policy admits depends on principals or conditions not known statically' };
    }
    return undefined;
  },
};

// ---------------------------------------------------------------- SQS / SNS

const sqsEncryption: Rule = {
  id: 'sqs.encryption',
  title: 'SQS encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_sqs_queue'],
  evaluate: (v, res, ctx) => {
    const kind = keyKind(v.kms_master_key_id, res, 'kms_master_key_id', ctx);
    if (kind === 'cmk') return { status: 'PASS', detail: 'SSE-KMS with a customer managed key' };
    if (kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', 'SSE-KMS with the AWS managed key aws/sqs');
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: 'KMS key not known until apply' };
    // Set explicitly but not known statically: it may be false.
    if (isUnknown(v.sqs_managed_sse_enabled)) return { status: 'UNKNOWN', detail: 'sqs_managed_sse_enabled not known until apply' };
    if (v.sqs_managed_sse_enabled === false) {
      return { status: 'FAIL', detail: 'Server-side encryption explicitly disabled (sqs_managed_sse_enabled = false)', remediation: 'Remove sqs_managed_sse_enabled = false or set kms_master_key_id.' };
    }
    return cmkVerdict(ctx, 'aws-owned', 'SSE-SQS (SQS managed keys, the default for new queues)');
  },
};

function isDeadLetterQueue(q: ResourceChange, ctx: RuleContext): boolean {
  const arn = ctx.values(q).arn;
  return ctx.all.some((other) => {
    if (other === q || other.action === 'delete') return false;
    if (other.type === 'aws_sqs_queue' && other.references.redrive_policy?.includes(q.address.replace(/\[[^\]]*\]/g, ''))) return true;
    if (other.type === 'aws_sqs_queue_redrive_policy' && other.references.redrive_policy?.includes(q.address.replace(/\[[^\]]*\]/g, ''))) return true;
    const rp = ctx.values(other).redrive_policy;
    return typeof rp === 'string' && typeof arn === 'string' && rp.includes(arn);
  });
}

const sqsDlq: Rule = {
  id: 'sqs.dlq',
  title: 'SQS dead-letter queue',
  // Retaining failed messages is neither a backup nor redundant processing infrastructure.
  controls: [],
  types: ['aws_sqs_queue'],
  evaluate: (v, res, ctx) => {
    if (isDeadLetterQueue(res, ctx)) return undefined;
    const rp = v.redrive_policy;
    const hasTarget =
      (typeof rp === 'string' && rp.includes('deadLetterTargetArn')) ||
      (rp !== null && typeof rp === 'object' && !isUnknown(rp) && 'deadLetterTargetArn' in rp);
    if (hasTarget) return { status: 'PASS', detail: 'Redrive policy routes failed messages to a dead-letter queue' };
    if (isUnknown(rp)) {
      return ctx.referencesType(res, 'redrive_policy', ['aws_sqs_queue'])
        ? { status: 'PASS', detail: 'Redrive policy routes failed messages to a dead-letter queue' }
        : { status: 'UNKNOWN', detail: 'Redrive policy not known until apply' };
    }
    if (ctx.referrers(res, 'aws_sqs_queue_redrive_policy', 'queue_url', ['id', 'url']).length) {
      return { status: 'PASS', detail: 'aws_sqs_queue_redrive_policy routes failed messages to a dead-letter queue' };
    }
    return { status: 'WARN', detail: 'No dead-letter queue: messages that keep failing are dropped after the retention period', remediation: 'Add a redrive_policy pointing at a DLQ, or document why this queue does not need one.' };
  },
};

const snsEncryption: Rule = {
  id: 'sns.encryption',
  title: 'SNS encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_sns_topic'],
  evaluate: (v, res, ctx) => {
    const kind = keyKind(v.kms_master_key_id, res, 'kms_master_key_id', ctx);
    if (kind === 'cmk') return { status: 'PASS', detail: 'Encrypted with a customer managed KMS key' };
    if (kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', 'Encrypted with the AWS managed key aws/sns');
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: 'KMS key not known until apply' };
    return { status: 'WARN', detail: 'SNS does not encrypt messages at rest unless kms_master_key_id is set', remediation: 'Set kms_master_key_id (alias/aws/sns or a customer managed key).' };
  },
};

// ---------------------------------------------------------------- DynamoDB

const dynamoPitr: Rule = {
  id: 'dynamodb.pitr',
  title: 'DynamoDB point-in-time recovery',
  controls: ['ISO27001:A.8.13'],
  types: ['aws_dynamodb_table'],
  evaluate: (v) => {
    const enabled = block(v.point_in_time_recovery)?.enabled;
    if (enabled === true) return { status: 'PASS', detail: 'Point-in-time recovery enabled' };
    if (isUnknown(enabled) || unknownBlock(v.point_in_time_recovery)) return { status: 'UNKNOWN', detail: 'PITR setting not known until apply' };
    return { status: 'FAIL', detail: 'Point-in-time recovery disabled', remediation: 'Add point_in_time_recovery { enabled = true }.' };
  },
};

const dynamoEncryption: Rule = {
  id: 'dynamodb.encryption',
  title: 'DynamoDB encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_dynamodb_table'],
  evaluate: (v, res, ctx) => {
    const sse = block(v.server_side_encryption);
    if (!sse || sse.enabled !== true) {
      if (isUnknown(sse?.enabled) || unknownBlock(v.server_side_encryption)) return { status: 'UNKNOWN', detail: 'Encryption setting not known until apply' };
      return cmkVerdict(ctx, 'aws-owned', 'Encrypted with an AWS owned key (DynamoDB default)');
    }
    const kind = keyKind(sse.kms_key_arn, res, 'server_side_encryption', ctx);
    if (kind === 'cmk') return { status: 'PASS', detail: 'Encrypted with a customer managed KMS key' };
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: 'KMS key not known until apply' };
    return cmkVerdict(ctx, 'aws-managed', 'Encrypted with the AWS managed key aws/dynamodb');
  },
};

const dynamoDeletionProtection: Rule = {
  id: 'dynamodb.deletion-protection',
  title: 'DynamoDB deletion protection',
  controls: ['ISO27001:A.8.13'],
  types: ['aws_dynamodb_table'],
  evaluate: (v) =>
    v.deletion_protection_enabled === true
      ? undefined
      : { status: 'WARN', detail: 'Deletion protection disabled', remediation: 'Set deletion_protection_enabled = true on tables holding data you cannot recreate.' },
};

// ---------------------------------------------------------------- KMS

const kmsRotation: Rule = {
  id: 'kms.rotation',
  title: 'KMS key rotation',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_kms_key'],
  evaluate: (v) => {
    const spec = v.customer_master_key_spec ?? v.key_spec;
    if (typeof spec === 'string' && spec !== 'SYMMETRIC_DEFAULT') {
      return { status: 'INFO', detail: `Automatic rotation is not available for ${spec} keys` };
    }
    if (v.enable_key_rotation === true) return { status: 'PASS', detail: 'Automatic key rotation enabled' };
    if (isUnknown(v.enable_key_rotation)) return { status: 'UNKNOWN', detail: 'Rotation setting not known until apply' };
    return { status: 'FAIL', detail: 'Automatic key rotation disabled', remediation: 'Set enable_key_rotation = true.' };
  },
};

const kmsKeyPolicy: Rule = {
  id: 'kms.key-policy',
  title: 'KMS key policy principals',
  controls: ['ISO27001:A.8.24', 'ISO27001:A.5.15'],
  // The policy is an argument of the key, or of a separate aws_kms_key_policy resource for it.
  types: ['aws_kms_key', 'aws_kms_key_policy'],
  evaluate: (v) => {
    if (!isSet(v.policy)) return undefined;
    const parsed = parsePolicy(v.policy);
    if (parsed.kind !== 'ok') return undefined;
    if (parsed.statements.some(openToAnyone)) return { status: 'FAIL', detail: 'Key policy allows any principal without a condition' };
    return parsed.statements.some((st) => principalUnknown(st) || openUnlessUnknownCondition(st))
      ? { status: 'UNKNOWN', detail: 'Who the key policy admits depends on principals or conditions not known statically' }
      : undefined;
  },
};

// ---------------------------------------------------------------- RDS

const rdsEncryption: Rule = {
  id: 'rds.encryption',
  title: 'RDS storage encryption',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_db_instance', 'aws_rds_cluster'],
  evaluate: (v) => {
    if (v.storage_encrypted === true) return { status: 'PASS', detail: 'Storage encrypted' };
    if (isUnknown(v.storage_encrypted)) return { status: 'UNKNOWN', detail: 'Storage encryption not known until apply' };
    if (typeof v.replicate_source_db === 'string' || isUnknown(v.replicate_source_db)) return undefined;
    return { status: 'FAIL', detail: 'Storage not encrypted (encryption can only be enabled at creation)', remediation: 'Set storage_encrypted = true (requires a new instance or snapshot restore for existing databases).' };
  },
};

const rdsBackups: Rule = {
  id: 'rds.backup-retention',
  title: 'RDS automated backups',
  controls: ['ISO27001:A.8.13'],
  types: ['aws_db_instance', 'aws_rds_cluster'],
  evaluate: (v, _res, ctx) => {
    const days = v.backup_retention_period;
    if (isUnknown(days)) return { status: 'UNKNOWN', detail: 'Backup retention not known until apply' };
    if (typeof days !== 'number') return undefined;
    if (days === 0) return { status: 'FAIL', detail: 'Automated backups disabled (backup_retention_period = 0)' };
    if (days < ctx.policy.minBackupRetentionDays) {
      return { status: 'WARN', detail: `Backup retention ${days} day(s) is below the policy minimum of ${ctx.policy.minBackupRetentionDays}` };
    }
    return { status: 'PASS', detail: `Automated backups kept ${days} days` };
  },
};

const rdsPublic: Rule = {
  id: 'rds.public',
  title: 'RDS network exposure',
  controls: ['ISO27001:A.8.20'],
  types: ['aws_db_instance', 'aws_rds_cluster_instance'],
  evaluate: (v) =>
    v.publicly_accessible === true
      ? { status: 'FAIL', detail: 'Database is publicly accessible', remediation: 'Set publicly_accessible = false and reach it through private subnets.' }
      : undefined,
};

const rdsDeletionProtection: Rule = {
  id: 'rds.deletion-protection',
  title: 'RDS deletion protection',
  controls: ['ISO27001:A.8.13'],
  types: ['aws_db_instance', 'aws_rds_cluster'],
  evaluate: (v) =>
    v.deletion_protection === true || isUnknown(v.deletion_protection)
      ? undefined
      : { status: 'WARN', detail: 'Deletion protection disabled', remediation: 'Set deletion_protection = true.' },
};

// ---------------------------------------------------------------- Lambda

const SECRET_KEY = /(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET)$/i;

const lambdaEnvSecrets: Rule = {
  id: 'lambda.plaintext-secrets',
  title: 'Secrets in Lambda environment variables',
  controls: ['ISO27001:A.8.24', 'ISO27001:A.5.17'],
  types: ['aws_lambda_function'],
  evaluate: (v) => {
    const vars = block(block(v.environment)?.variables) ?? block(v.environment)?.variables;
    if (!vars || typeof vars !== 'object') return undefined;
    const suspicious = Object.entries(vars as Attrs).filter(
      ([k, val]) => SECRET_KEY.test(k) && typeof val === 'string' && val.length > 0 && !val.startsWith('arn:')
    );
    if (!suspicious.length) return undefined;
    return {
      status: 'WARN',
      detail: `Plaintext value for ${suspicious.map(([k]) => k).join(', ')} in the function environment`,
      remediation: 'Store the value in Secrets Manager or SSM SecureString and pass its name or ARN instead.',
    };
  },
};

const lambdaUrlAuth: Rule = {
  id: 'lambda.url-auth',
  title: 'Lambda function URL authentication',
  controls: ['ISO27001:A.8.5'],
  types: ['aws_lambda_function_url'],
  evaluate: (v) =>
    v.authorization_type === 'NONE'
      ? { status: 'WARN', detail: 'Function URL is public (authorization_type = NONE); the function must authenticate callers itself' }
      : undefined,
};

// ---------------------------------------------------------------- Network

const OPEN_CIDRS = new Set(['0.0.0.0/0', '::/0']);
const WEB_PORTS = new Set([80, 443]);

function openIngress(cidrs: unknown[], from: unknown, to: unknown, protocol: unknown): string | undefined {
  const open = cidrs.filter((c) => typeof c === 'string' && OPEN_CIDRS.has(c));
  if (!open.length) return undefined;
  if (protocol === '-1' || protocol === -1 || protocol === 'all') return `all traffic from ${open.join(', ')}`;
  const lo = typeof from === 'number' ? from : undefined;
  // An absent to_port is the single port; one that is not known statically may be any port.
  const hi = typeof to === 'number' ? to : to === undefined || to === null ? lo : undefined;
  if (lo !== undefined && hi !== undefined && lo === hi && WEB_PORTS.has(lo)) return undefined;
  return `ports ${lo ?? '?'}${hi !== lo ? `-${hi ?? '?'}` : ''} from ${open.join(', ')}`;
}

const sgOpenIngress: Rule = {
  id: 'network.open-ingress',
  title: 'Security group ingress from the internet',
  controls: ['ISO27001:A.8.20', 'ISO27001:A.8.22'],
  types: ['aws_security_group', 'aws_security_group_rule', 'aws_vpc_security_group_ingress_rule'],
  evaluate: (v, res) => {
    const exposures: string[] = [];
    let unknown = false;
    const cidrs = (...vals: unknown[]) =>
      vals.flatMap((x) => {
        if (isUnknown(x)) unknown = true;
        return Array.isArray(x) ? x : x === undefined || x === null || isUnknown(x) ? [] : [x];
      });
    if (res.type === 'aws_security_group') {
      // A dynamic ingress block over an unknown collection leaves an Unknown element in the list.
      if (isUnknown(v.ingress) || (Array.isArray(v.ingress) && v.ingress.some(isUnknown))) unknown = true;
      for (const ing of blocks(v.ingress)) {
        const e = openIngress(cidrs(ing.cidr_blocks, ing.ipv6_cidr_blocks), ing.from_port, ing.to_port, ing.protocol);
        if (e) exposures.push(e);
      }
    } else if (res.type === 'aws_security_group_rule') {
      if (v.type !== 'ingress') return undefined;
      const e = openIngress(cidrs(v.cidr_blocks, v.ipv6_cidr_blocks), v.from_port, v.to_port, v.protocol);
      if (e) exposures.push(e);
    } else {
      const e = openIngress(cidrs(v.cidr_ipv4, v.cidr_ipv6), v.from_port, v.to_port, v.ip_protocol);
      if (e) exposures.push(e);
    }
    if (!exposures.length) return unknown ? { status: 'UNKNOWN', detail: 'Ingress sources not known until apply' } : undefined;
    return { status: 'FAIL', detail: `Allows ${exposures.join('; ')}`, remediation: 'Restrict the source CIDR or put the service behind a load balancer.' };
  },
};

// ---------------------------------------------------------------- Secrets

const secretRecovery: Rule = {
  id: 'secrets.recovery-window',
  title: 'Secrets Manager recovery window',
  controls: ['ISO27001:A.8.13', 'ISO27001:A.8.10'],
  types: ['aws_secretsmanager_secret'],
  evaluate: (v) =>
    v.recovery_window_in_days === 0
      ? { status: 'WARN', detail: 'recovery_window_in_days = 0 deletes the secret immediately and irrecoverably' }
      : undefined,
};

// ---------------------------------------------------------------- IAM

const POLICY_DOC_TYPES = ['aws_iam_policy_document'];

/** The policy document of an IAM resource, following data.aws_iam_policy_document references when the value is unknown. */
function resolvePolicyValue(value: unknown, res: ResourceChange, attr: string, ctx: RuleContext): unknown {
  if (isSet(value) && !isUnknown(value)) return value;
  for (const ref of res.references[attr] ?? []) {
    if (!ref.split('.').some((p) => POLICY_DOC_TYPES.includes(p))) continue;
    // Plan references drop instance keys: with several documents that could be the one, only a
    // document they all agree on can stand in for the unknown policy.
    const docs = ctx.lookup(ref).filter((d) => instancesCompatible(res.address, d.address));
    const jsons = docs.map((d) => ctx.values(d).json);
    const json = jsons[0];
    if (!jsons.length || jsons.some((j) => stableKey(j) !== stableKey(json))) continue;
    if (typeof json === 'string' || (json && typeof json === 'object' && !isUnknown(json))) return json;
  }
  return value;
}

function issuesResult(issues: PolicyIssue[], okDetail: string): RuleResult {
  const level = worstLevel(issues);
  if (!level) return { status: 'PASS', detail: okDetail };
  const shown = issues.filter((i) => i.level === level).map((i) => i.message);
  return {
    status: level,
    detail: capitalize(shown.join('; ')),
    remediation: level === 'FAIL' ? 'Grant explicit actions on explicit resource ARNs.' : undefined,
    issues,
  };
}

function identityPolicyResult(value: unknown): RuleResult {
  const parsed = parsePolicy(value);
  if (parsed.kind === 'unknown') return { status: 'UNKNOWN', detail: `Policy document not available: ${parsed.reason}` };
  if (parsed.kind === 'invalid') return { status: 'WARN', detail: parsed.reason };
  return issuesResult(analyzeIdentityPolicy(parsed.statements), 'Explicit actions on explicit resources');
}

const iamLeastPrivilege: Rule = {
  id: 'iam.least-privilege',
  title: 'IAM least privilege',
  controls: ['ISO27001:A.5.15', 'ISO27001:A.5.18', 'ISO27001:A.8.3'],
  types: ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy', 'aws_iam_role'],
  evaluate: (v, res, ctx) => {
    if (res.type === 'aws_iam_role') {
      const inline = blocks(v.inline_policy).filter((p) => isSet(p.policy));
      if (!inline.length) return undefined;
      // All inline policies are judged together, each issue labelled with its policy, so a new issue in
      // one policy is not hidden behind an older one in another.
      const issues = inline.flatMap((p) => {
        const label = typeof p.name === 'string' && p.name ? `inline policy "${p.name}": ` : '';
        const parsed = parsePolicy(p.policy);
        if (parsed.kind === 'unknown') return [{ level: 'UNKNOWN' as const, message: `${label}policy document not available: ${parsed.reason}` }];
        if (parsed.kind === 'invalid') return [{ level: 'WARN' as const, message: `${label}${parsed.reason}` }];
        return analyzeIdentityPolicy(parsed.statements).map((i) => ({ ...i, message: label + i.message }));
      });
      return issuesResult(issues, 'Explicit actions on explicit resources');
    }
    return identityPolicyResult(resolvePolicyValue(v.policy, res, 'policy', ctx));
  },
};

/**
 * A Federated principal written as `aws_iam_openid_connect_provider.x.arn` is unknown until apply, but the
 * provider's URL is known: substitute an ARN-shaped string so trust checks can see which provider it is.
 */
function resolveOidcPrincipals(principal: unknown, ctx: RuleContext): unknown {
  if (!principal || typeof principal !== 'object' || isUnknown(principal)) return principal;
  const out: Attrs = {};
  for (const [k, v] of Object.entries(principal as Attrs)) {
    const values = Array.isArray(v) ? v : [v];
    out[k] = values.map((x) => {
      if (!isUnknown(x)) return x;
      const provider = x.refs.flatMap((r) => ctx.lookup(r)).find((r) => r.type === 'aws_iam_openid_connect_provider');
      const url = provider ? ctx.values(provider).url : undefined;
      return typeof url === 'string' ? `arn:aws:iam::{?}:oidc-provider/${url.replace(/^https:\/\//, '')}` : x;
    });
  }
  return out;
}

const iamTrust: Rule = {
  id: 'iam.trust',
  title: 'IAM role trust policy',
  controls: ['ISO27001:A.8.2', 'ISO27001:A.8.5'],
  types: ['aws_iam_role'],
  evaluate: (v, res, ctx) => {
    const parsed = parsePolicy(resolvePolicyValue(v.assume_role_policy, res, 'assume_role_policy', ctx));
    if (parsed.kind === 'unknown') return { status: 'UNKNOWN', detail: `Trust policy not available: ${parsed.reason}` };
    if (parsed.kind === 'invalid') return { status: 'WARN', detail: parsed.reason };
    return issuesResult(analyzeTrustPolicy(parsed.statements.map((st) => ({ ...st, Principal: resolveOidcPrincipals(st.Principal, ctx) }))), 'Trust limited to specific principals');
  },
};

const iamManagedPolicy: Rule = {
  id: 'iam.managed-policy',
  title: 'Broad AWS managed policy attachment',
  controls: ['ISO27001:A.8.2'],
  types: ['aws_iam_role_policy_attachment', 'aws_iam_user_policy_attachment', 'aws_iam_group_policy_attachment', 'aws_iam_policy_attachment', 'aws_iam_role'],
  evaluate: (v, res) => {
    if (res.type === 'aws_iam_role' && isUnknown(v.managed_policy_arns)) {
      return { status: 'UNKNOWN', detail: 'Managed policy attachments not known until apply' };
    }
    const arns = res.type === 'aws_iam_role' ? (Array.isArray(v.managed_policy_arns) ? v.managed_policy_arns : []) : [v.policy_arn];
    const issues = arns.flatMap(analyzeManagedPolicyArn);
    if (res.type === 'aws_iam_role' && !issues.length) return undefined;
    return issuesResult(issues, 'No admin-equivalent AWS managed policy');
  },
};

const iamAccessKey: Rule = {
  id: 'iam.static-credentials',
  title: 'Long-lived IAM access keys',
  controls: ['ISO27001:A.8.5'],
  types: ['aws_iam_access_key'],
  evaluate: () => ({ status: 'WARN', detail: 'Creates a long-lived access key; prefer roles with OIDC or IAM Identity Center', remediation: 'Use an assumable role (OIDC for CI, instance or task roles for workloads).' }),
};

export const RULES: Rule[] = [
  s3Encryption,
  s3PublicAccess,
  s3PabResource,
  s3Versioning,
  s3BucketPolicy,
  sqsEncryption,
  sqsDlq,
  snsEncryption,
  dynamoPitr,
  dynamoEncryption,
  dynamoDeletionProtection,
  kmsRotation,
  kmsKeyPolicy,
  rdsEncryption,
  rdsBackups,
  rdsPublic,
  rdsDeletionProtection,
  lambdaEnvSecrets,
  lambdaUrlAuth,
  sgOpenIngress,
  secretRecovery,
  iamLeastPrivilege,
  iamTrust,
  iamManagedPolicy,
  iamAccessKey,
];
