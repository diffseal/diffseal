import { configAddress, instancesCompatible, isRedacted, isUnknown, reveal, type Attrs, type ResourceChange } from '../core/model.js';
import { knownConfiguration } from '../core/configuration.js';
import { containsUnknown, stableKey } from '../hcl/eval.js';
import { capitalize, type Rule, type RuleContext, type RuleResult } from './engine.js';
import { block, blocks, typed, unknownBlock } from './values.js';
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
 * Rules declare ISO/IEC 27001:2022 Annex A controls where verified. The engine adds verified SOC 2 criteria
 * from the rule category in the crosswalk.
 * Thresholds come from the customer's policy (PolicyConfig); ISO itself does not mandate CMKs or PITR.
 */

const isSet = (v: unknown) => v !== undefined && v !== null && v !== '';

/** Classify a KMS key reference as customer managed, AWS managed, or unknown. */
function keyKind(key: unknown): 'cmk' | 'aws-managed' | 'unknown' | 'none' {
  if (isUnknown(key) || isRedacted(key)) return 'unknown';
  if (!isSet(key)) return 'none';
  if (typeof key !== 'string') return 'unknown';
  if (typeof key === 'string' && /(^|:)alias\/aws\//.test(key)) return 'aws-managed';
  return 'cmk';
}

function cmkVerdict(ctx: RuleContext, kind: 'cmk' | 'aws-managed' | 'aws-owned', description: string): RuleResult {
  if (kind !== 'cmk' && ctx.policy.requireCustomerManagedKeys) {
    return encryptionDecision(false, 'customer managed KMS key', description, {
      warnDetail: `${description}; policy requires a customer managed KMS key`, remediation: 'Encrypt with a customer managed aws_kms_key.',
    });
  }
  return encryptionDecision(true, 'encryption', description, { passDetail: description });
}

// ---------------------------------------------------------------- S3

function bucketEncryption(bucket: ResourceChange, values: Attrs, ctx: RuleContext): RuleResult {
  const helper = ctx.referrers(bucket, 'aws_s3_bucket_server_side_encryption_configuration', 'bucket')[0];
  const cfgSource = helper ? ctx.configuredValues(helper) : block(values.server_side_encryption_configuration);
  const rule = cfgSource ? block(cfgSource.rule) : undefined;
  const def = rule ? block(rule.apply_server_side_encryption_by_default) : undefined;
  const algo = def?.sse_algorithm;
  if (!def || isUnknown(algo)) return encryptionDecision(undefined, 'sse_algorithm', 'S3 encryption');
  if (algo === 'AES256') return cmkVerdict(ctx, 'aws-owned', 'SSE-S3 (AES256, S3 managed keys)');
  if (algo === 'aws:kms' || algo === 'aws:kms:dsse') {
    const label = algo === 'aws:kms' ? 'SSE-KMS' : 'DSSE-KMS';
    const kind = keyKind(def.kms_master_key_id);
    if (kind === 'none' || kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', `${label} with the AWS managed key aws/s3`);
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: `${label} key not known until apply` };
    return encryptionDecision(true, 'sse_algorithm', 'S3 encryption', { passDetail: `${label} with a customer managed KMS key` });
  }
  return encryptionDecision(undefined, 'sse_algorithm', 'S3 encryption');
}

const s3Encryption: Rule = {
  configurationOnly: true,
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

// ---------------------------------------------------------------- Encryption configuration

/** Shared encryption rule: explicit on passes; off warns only when enforcement/inheritance cannot override it. */
function encryptionDecision(value: unknown, attr: string, description: string, options: {
  enforcedAtCreation?: boolean;
  mayInheritEncryption?: boolean;
  ignoresEncryptionArgument?: boolean;
  passDetail?: string;
  warnDetail?: string;
  unknownDetail?: string;
  remediation?: string;
} = {}): RuleResult {
  // ElastiCache's at_rest_encryption_enabled also accepts the string form in provider plans.
  const evidence = knownConfiguration(value) && !options.ignoresEncryptionArgument ? value : undefined;
  const enabled = evidence === 'true' ? true : evidence === 'false' ? false : evidence;
  if (enabled === true) return { status: 'PASS', detail: options.passDetail ?? `${description} configured (${attr} = true)` };
  if (enabled === false && !options.enforcedAtCreation && !options.mayInheritEncryption) return {
    status: 'WARN', detail: options.warnDetail ?? `${description} explicitly disabled (${attr}); effective AWS settings are not verified`,
    remediation: options.remediation ?? `Set ${attr} = true.`,
  };
  return { status: 'UNKNOWN', detail: options.unknownDetail ?? (options.enforcedAtCreation
    ? `${description} is subject to configured enforcement at creation; explicit encryption enablement is not established`
    : `${description} is omitted, unknown or unrecognized; explicit encryption configuration is not established`) };
}

const ebsDefaultEncryption: Rule = {
  configurationOnly: true,
  id: 'ebs.default-encryption',
  title: 'EBS default encryption',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_ebs_encryption_by_default'],
  evaluate: (v) => encryptionDecision(v.enabled, 'enabled', 'EBS default encryption'),
};

/** Keep source presence even when its value is unusable as explicit encryption evidence. */
function configuredArgument(values: Attrs, res: ResourceChange, attr: string): boolean {
  return isSet(values[attr]) || Boolean(res.configuredPaths?.includes(attr)) || Boolean(res.references[attr]?.length);
}

const ebsEncryption: Rule = {
  configurationOnly: true,
  id: 'ebs.encryption',
  title: 'EBS volume encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_ebs_volume'],
  evaluate: (v, res, ctx) => {
    const defaults = ctx.all.filter((r) => r.mode === 'managed' && r.type === 'aws_ebs_encryption_by_default'
      && (ctx.side === 'after' ? r.after !== null && r.action !== 'delete' : r.before !== null));
    const enabled = defaults.some((r) => {
      if (!res.providerAddress || r.providerAddress !== res.providerAddress) return false;
      const d = ctx.configuredValues(r);
      if (d.region != null || v.region != null) {
        if (typeof d.region !== 'string' || d.region === '' || d.region !== v.region) return false;
      }
      return d.enabled === true || d.enabled === 'true';
    });
    const mayInheritEncryption = configuredArgument(v, res, 'snapshot_id');
    return encryptionDecision(v.encrypted, 'encrypted', 'EBS volume encryption', {
      enforcedAtCreation: ctx.side === 'after' && (res.action === 'create' || res.action === 'replace') && enabled,
      mayInheritEncryption,
      unknownDetail: mayInheritEncryption ? 'EBS volume may inherit encryption from its snapshot; encrypted = false does not establish encryption disablement' : undefined,
    });
  },
};

const efsEncryption: Rule = {
  configurationOnly: true,
  id: 'efs.encryption',
  title: 'EFS encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_efs_file_system'],
  evaluate: (v) => encryptionDecision(v.encrypted, 'encrypted', 'EFS encryption'),
};

const elasticacheEncryption: Rule = {
  configurationOnly: true,
  id: 'elasticache.encryption',
  title: 'ElastiCache encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_elasticache_replication_group'],
  evaluate: (v) => {
    if (typeof v.global_replication_group_id === 'string' && v.global_replication_group_id !== '') return encryptionDecision(undefined, 'at_rest_encryption_enabled', 'ElastiCache encryption at rest', { unknownDetail: 'Configured ElastiCache global secondary inherits encryption from its primary; local encryption arguments conflict with global_replication_group_id' });
    return encryptionDecision(v.at_rest_encryption_enabled, 'at_rest_encryption_enabled', 'ElastiCache encryption at rest');
  },
};

const elasticacheTransitEncryption: Rule = {
  configurationOnly: true,
  id: 'elasticache.transit-encryption',
  title: 'ElastiCache encryption in transit',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_elasticache_replication_group', 'aws_elasticache_cluster'],
  evaluate: (v, res, ctx) => {
    if (res.type === 'aws_elasticache_cluster') {
      // Redis/Valkey members inherit their replication group's settings; this flag is Memcached-only.
      if ((typeof v.replication_group_id === 'string' && v.replication_group_id !== '') || ctx.referencesType(res, 'replication_group_id', ['aws_elasticache_replication_group']) || v.engine === 'redis' || v.engine === 'valkey') return undefined;
      if (v.engine !== 'memcached') return { status: 'UNKNOWN', detail: 'ElastiCache cluster transit encryption depends on an unknown or unrecognized engine' };
      const version = typeof v.engine_version === 'string' ? v.engine_version.match(/^(\d+)\.(\d+)\.(\d+)$/)?.slice(1).map(Number) : undefined;
      const supported = version && (version[0] > 1 || (version[0] === 1 && (version[1] > 6 || (version[1] === 6 && version[2] >= 12))));
      const inVpc = (typeof v.subnet_group_name === 'string' && v.subnet_group_name !== '')
        || ctx.referencesType(res, 'subnet_group_name', ['aws_elasticache_subnet_group']);
      if (!supported || !inVpc) return { status: 'UNKNOWN', detail: 'Memcached transit encryption requires version 1.6.12 or later in a VPC; support is not established by this configuration' };
    }
    if (typeof v.global_replication_group_id === 'string' && v.global_replication_group_id !== '') return encryptionDecision(undefined, 'transit_encryption_enabled', 'ElastiCache encryption in transit', { unknownDetail: 'Configured ElastiCache global secondary inherits encryption from its primary; local encryption arguments conflict with global_replication_group_id' });
    return encryptionDecision(v.transit_encryption_enabled, 'transit_encryption_enabled', 'ElastiCache encryption in transit');
  },
};

/** Do not mistake an unresolved (including dynamic or sensitive) block for an omitted block. */
function unresolvedBlock(value: unknown): boolean {
  return isUnknown(value) || isRedacted(value) || (Array.isArray(value) && value.some((v) => isUnknown(v) || isRedacted(v)));
}

const opensearchEncryption: Rule = {
  configurationOnly: true,
  id: 'opensearch.encryption',
  title: 'OpenSearch encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_opensearch_domain', 'aws_elasticsearch_domain'],
  evaluate: (v) => {
    if (unresolvedBlock(v.encrypt_at_rest)) return { status: 'UNKNOWN', detail: 'OpenSearch encryption at rest block not known until apply' };
    const result = encryptionDecision(block(v.encrypt_at_rest)?.enabled, 'encrypt_at_rest.enabled', 'OpenSearch encryption at rest');
    return result.status === 'WARN' ? { ...result, remediation: 'Configure encrypt_at_rest { enabled = true }; review replacement requirements for the domain version.' } : result;
  },
};

const opensearchNodeEncryption: Rule = {
  configurationOnly: true,
  id: 'opensearch.node-to-node-encryption',
  title: 'OpenSearch node-to-node encryption',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_opensearch_domain', 'aws_elasticsearch_domain'],
  evaluate: (v) => {
    if (unresolvedBlock(v.node_to_node_encryption)) return { status: 'UNKNOWN', detail: 'OpenSearch node-to-node encryption block not known until apply' };
    const result = encryptionDecision(block(v.node_to_node_encryption)?.enabled, 'node_to_node_encryption.enabled', 'OpenSearch node-to-node encryption');
    return result.status === 'WARN' ? { ...result, remediation: 'Configure node_to_node_encryption { enabled = true }; review replacement requirements for the domain version.' } : result;
  },
};

const opensearchHttps: Rule = {
  configurationOnly: true,
  id: 'opensearch.https',
  title: 'OpenSearch HTTPS enforcement',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_opensearch_domain', 'aws_elasticsearch_domain'],
  evaluate: (v) => {
    const options = block(v.domain_endpoint_options);
    if (unresolvedBlock(v.domain_endpoint_options) || !options) return { status: 'UNKNOWN', detail: 'OpenSearch endpoint options are unresolved or omitted; HTTPS enforcement is not known' };
    const result = encryptionDecision(options.enforce_https, 'domain_endpoint_options.enforce_https', 'OpenSearch HTTPS enforcement');
    return result.status === 'WARN' ? { ...result, remediation: 'Set enforce_https = true in domain_endpoint_options.' } : result;
  },
};

/** Whether a resolved action list redirects to HTTPS; undefined preserves uncertainty. */
function redirectsToHttps(value: unknown): boolean | undefined {
  if (unresolvedBlock(value)) return undefined;
  const actions = blocks(value);
  if (!actions.length) return undefined;
  if (actions.some((a) => !['forward', 'redirect', 'fixed-response', 'authenticate-cognito', 'authenticate-oidc', 'jwt-validation'].includes(a.type as string) || (a.type === 'redirect'
    && (unresolvedBlock(a.redirect) || !['HTTP', 'HTTPS'].includes(block(a.redirect)?.protocol as string))))) return undefined;
  return actions.some((a) => a.type === 'redirect' && block(a.redirect)?.protocol === 'HTTPS');
}

/** Multiple condition blocks are ANDed, so a wildcard path alone must cover every condition. */
function catchAllPaths(value: unknown): boolean {
  if (unresolvedBlock(value)) return false;
  const conditions = blocks(value);
  return conditions.length > 0 && conditions.every((c) => {
    const fields = Object.entries(c).filter(([_k, v]) => v != null && (!Array.isArray(v) || v.length > 0));
    if (fields.length !== 1 || fields[0][0] !== 'path_pattern' || unresolvedBlock(c.path_pattern)) return false;
    const paths = block(c.path_pattern)?.values;
    return Array.isArray(paths) && paths.some((p) => p === '*' || p === '/*');
  });
}

const elbHttps: Rule = {
  configurationOnly: true,
  id: 'elb.https',
  title: 'Load balancer listener HTTPS',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_lb_listener'],
  evaluate: (v, res, ctx) => {
    if (v.protocol === 'HTTPS') return encryptionDecision(true, 'protocol', 'Listener HTTPS', { passDetail: 'Listener configured to use HTTPS' });
    if (['TCP', 'TLS', 'UDP', 'TCP_UDP', 'GENEVE', 'QUIC', 'TCP_QUIC'].includes(v.protocol as string)) return undefined;
    if (v.protocol !== 'HTTP') return { status: 'UNKNOWN', detail: 'Listener protocol is omitted, unknown or unrecognized' };
    const unknown = encryptionDecision(undefined, 'protocol', 'Listener HTTPS', { unknownDetail: 'HTTP listener rule association, priority, conditions or actions do not establish an effective HTTPS redirect' });
    const warning = encryptionDecision(false, 'protocol', 'Listener HTTPS', { warnDetail: 'HTTP listener has a reachable action without an HTTPS redirect', remediation: 'Configure a default or catch-all redirect to HTTPS and ensure earlier rules also redirect to HTTPS.' });
    const exists = (r: ResourceChange) => ctx.side === 'after' ? r.after !== null && r.action !== 'delete' : r.before !== null;
    const rules = ctx.referrers(res, 'aws_lb_listener_rule', 'listener_arn', ['arn']).filter((r) => r.mode === 'managed');
    const target = configAddress(res.address);
    const ambiguous = ctx.all.some((r) => {
      if (r.type !== 'aws_lb_listener_rule' || r.mode !== 'managed' || !exists(r)) return false;
      const arn = ctx.values(r).listener_arn;
      if (typeof arn === 'string' && typeof ctx.values(res).arn === 'string') return false;
      const refs = r.references.listener_arn ?? [];
      if (refs.length === 1 && /(^|\.)aws_lb_listener\.[^.]+$/.test(refs[0])) {
        if (refs[0] !== target) return false;
        const exact = isUnknown(arn) ? arn.refs.filter((ref) => configAddress(ref) === target && ref !== target) : [];
        if (exact.length === 1) return false;
        return ctx.lookup(target).filter(exists).length !== 1 || !rules.includes(r);
      }
      return true;
    });
    if (ambiguous) return unknown;
    const ordered = rules.map((r) => ctx.configuredValues(r));
    if (ordered.some((r) => typeof r.priority !== 'number' || !Number.isInteger(r.priority) || r.priority < 1 || r.priority > 50000)) return unknown;
    ordered.sort((a, b) => (a.priority as number) - (b.priority as number));
    if (new Set(ordered.map((r) => r.priority)).size !== ordered.length) return unknown;
    for (let i = 0; i < ordered.length; i++) {
      const rule = ordered[i];
      const redirect = redirectsToHttps(rule.action);
      if (redirect === undefined) return unknown;
      if (catchAllPaths(rule.condition)) {
        return redirect ? encryptionDecision(true, 'action', 'Listener HTTPS', { passDetail: 'HTTP listener redirects to HTTPS before the default action through a catch-all listener rule' }) : warning;
      }
      // General condition overlap and reachability are not resolved by this check.
      if (!redirect) return i === 0 && !containsUnknown(rule.condition) && blocks(rule.condition).length > 0 ? warning : unknown;
    }
    const redirect = redirectsToHttps(v.default_action);
    if (redirect === undefined) return unknown;
    if (redirect) return encryptionDecision(true, 'default_action', 'Listener HTTPS', { passDetail: 'HTTP listener default and preceding actions redirect to HTTPS' });
    return ordered.length ? unknown : warning;
  },
};

const elbListenerRuleOwner: Rule = {
  id: 'elb.https',
  title: 'Load balancer listener HTTPS',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_lb_listener_rule'],
  scope: 'change',
  evaluate: (_v, res, ctx) => ctx.listenerOwners(res).length === 1 ? undefined
    : encryptionDecision(undefined, 'listener_arn', 'Listener HTTPS', { unknownDetail: 'Listener rule owner cannot be resolved uniquely; effective listener encryption is unknown' }),
};

// Protocol floors, checked against AWS's ALB security-policy tables on 2026-10-29.
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
// Unlisted names remain UNKNOWN: neither a recent date nor "TLS13" proves a TLS 1.2 floor.
const ELB_TLS12_POLICIES = new Set([
  'TLS-1-2-2017-01', 'TLS-1-2-Ext-2018-06',
  'FS-1-2-2019-08', 'FS-1-2-Res-2019-08', 'FS-1-2-Res-2020-10',
  'TLS13-1-3-2021-06', 'TLS13-1-3-PQ-2025-09',
  'TLS13-1-2-2021-06', 'TLS13-1-2-PQ-2025-09',
  'TLS13-1-2-Res-2021-06', 'TLS13-1-2-Res-PQ-2025-09',
  'TLS13-1-2-Ext1-2021-06', 'TLS13-1-2-Ext1-PQ-2025-09',
  'TLS13-1-2-Ext2-2021-06', 'TLS13-1-2-Ext2-PQ-2025-09',
  'TLS13-1-3-FIPS-2023-04', 'TLS13-1-3-FIPS-PQ-2025-09',
  'TLS13-1-2-FIPS-2023-04', 'TLS13-1-2-FIPS-PQ-2025-09',
  'TLS13-1-2-Res-FIPS-2023-04', 'TLS13-1-2-Res-FIPS-PQ-2025-09',
  'TLS13-1-2-Ext0-FIPS-2023-04', 'TLS13-1-2-Ext0-FIPS-PQ-2025-09',
  'TLS13-1-2-Ext1-FIPS-2023-04', 'TLS13-1-2-Ext1-FIPS-PQ-2025-09',
  'TLS13-1-2-Ext2-FIPS-2023-04', 'TLS13-1-2-Ext2-FIPS-PQ-2025-09',
].map((name) => `ELBSecurityPolicy-${name}`));

const ELB_LEGACY_POLICIES = new Set([
  '2016-08', 'TLS-1-1-2017-01', 'FS-2018-06', 'FS-1-1-2019-08',
  'TLS13-1-0-2021-06', 'TLS13-1-0-PQ-2025-09', 'TLS13-1-1-2021-06',
  'TLS13-1-0-FIPS-2023-04', 'TLS13-1-0-FIPS-PQ-2025-09', 'TLS13-1-1-FIPS-2023-04',
].map((name) => `ELBSecurityPolicy-${name}`));

const elbTlsPolicy: Rule = {
  configurationOnly: true,
  id: 'elb.tls-policy',
  title: 'Load balancer listener TLS policy',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_lb_listener'],
  evaluate: (v) => {
    if (v.protocol !== 'HTTPS') return undefined;
    const policy = v.ssl_policy;
    if (typeof policy !== 'string') return { status: 'UNKNOWN', detail: 'Listener SSL policy not known until apply' };
    return encryptionDecision(ELB_TLS12_POLICIES.has(policy) ? true : ELB_LEGACY_POLICIES.has(policy) ? false : undefined, 'ssl_policy', 'Listener TLS 1.2 floor', {
      passDetail: `Listener SSL policy ${policy} requires TLS 1.2 or later`,
      warnDetail: `Listener SSL policy ${policy} permits TLS versions below 1.2`,
      remediation: 'Set ssl_policy to a policy requiring TLS 1.2 or later, such as ELBSecurityPolicy-TLS13-1-2-2021-06.',
    });
  },
};

const cloudfrontHttps: Rule = {
  configurationOnly: true,
  id: 'cloudfront.https',
  title: 'CloudFront viewer HTTPS',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_cloudfront_distribution'],
  evaluate: (v) => {
    const issues: PolicyIssue[] = [];
    for (const attr of ['default_cache_behavior', 'ordered_cache_behavior']) {
      if (unresolvedBlock(v[attr]) || (attr === 'default_cache_behavior' && !block(v[attr]))) {
        issues.push({ level: 'UNKNOWN', message: `${attr} is unresolved or omitted` });
      }
      for (const [i, behavior] of blocks(v[attr]).entries()) {
        const policy = behavior.viewer_protocol_policy;
        if (policy === 'allow-all') issues.push({ level: 'WARN', message: `${attr}[${i}] allows HTTP (viewer_protocol_policy = allow-all)` });
        else if (policy !== 'https-only' && policy !== 'redirect-to-https') issues.push({ level: 'UNKNOWN', message: `${attr}[${i}] viewer protocol policy is unknown or unrecognized` });
      }
    }
    const result = issuesResult(issues, 'All declared cache behaviors require HTTPS or redirect to HTTPS');
    return { ...encryptionDecision(result.status === 'PASS' ? true : result.status === 'WARN' ? false : undefined, 'viewer_protocol_policy', 'CloudFront viewer HTTPS', {
      passDetail: result.detail, warnDetail: result.detail, unknownDetail: result.detail,
      remediation: 'Set viewer_protocol_policy = "https-only" or "redirect-to-https" on each cache behavior.',
    }), issues: result.issues };
  },
};

// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
const CLOUDFRONT_TLS12_POLICIES = new Set(['TLSv1.2_2018', 'TLSv1.2_2019', 'TLSv1.2_2021', 'TLSv1.2_2025', 'TLSv1.3_2025']);
const CLOUDFRONT_LEGACY_POLICIES = new Set(['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016']);

const cloudfrontTlsPolicy: Rule = {
  configurationOnly: true,
  id: 'cloudfront.tls-policy',
  title: 'CloudFront viewer TLS policy',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_cloudfront_distribution'],
  evaluate: (v) => {
    const certificate = block(v.viewer_certificate);
    if (unresolvedBlock(v.viewer_certificate) || !certificate) return { status: 'UNKNOWN', detail: 'CloudFront viewer certificate is unresolved or omitted' };
    const defaultCertificate = certificate.cloudfront_default_certificate;
    if (defaultCertificate != null && typeof defaultCertificate !== 'boolean') return { status: 'UNKNOWN', detail: 'CloudFront default certificate setting is unknown or unrecognized' };
    // The default CloudFront certificate forces TLSv1 regardless of minimum_protocol_version.
    const policy = defaultCertificate === true ? 'TLSv1' : certificate.minimum_protocol_version;
    if (typeof policy !== 'string') return { status: 'UNKNOWN', detail: 'CloudFront minimum TLS version not known until apply' };
    return encryptionDecision(CLOUDFRONT_TLS12_POLICIES.has(policy) ? true : CLOUDFRONT_LEGACY_POLICIES.has(policy) ? false : undefined, 'minimum_protocol_version', 'CloudFront TLS 1.2 floor', {
      passDetail: `CloudFront viewer policy ${policy} requires TLS 1.2 or later`,
      warnDetail: `CloudFront viewer policy ${policy} permits TLS versions below 1.2${defaultCertificate === true ? ' (forced by cloudfront_default_certificate)' : ''}`,
      remediation: 'Use a custom viewer certificate and minimum_protocol_version = "TLSv1.2_2021" or a later TLS 1.2+ policy.',
    });
  },
};

// ---------------------------------------------------------------- Logging / security services

const cloudtrailLogging: Rule = {
  id: 'cloudtrail.logging',
  title: 'CloudTrail logging configuration',
  controls: [],
  types: ['aws_cloudtrail'],
  evaluate: (v) => {
    if (isUnknown(v.enable_logging) || isRedacted(v.enable_logging)) return { status: 'UNKNOWN', detail: 'CloudTrail logging setting not known until apply' };
    if (v.enable_logging === false) return { status: 'FAIL', detail: 'CloudTrail logging explicitly disabled (enable_logging = false)', remediation: 'Set enable_logging = true.' };
    return { status: 'PASS', detail: 'CloudTrail logging configured as enabled (enable_logging defaults to true)' };
  },
};

const cloudtrailMultiRegion: Rule = {
  id: 'cloudtrail.multi-region',
  title: 'CloudTrail multi-region configuration',
  controls: [],
  types: ['aws_cloudtrail'],
  evaluate: (v) => {
    if (isUnknown(v.is_multi_region_trail) || isRedacted(v.is_multi_region_trail)) return { status: 'UNKNOWN', detail: 'CloudTrail multi-region setting not known until apply' };
    if (v.is_multi_region_trail === true) return { status: 'PASS', detail: 'CloudTrail configured as a multi-region trail' };
    return { status: 'WARN', detail: 'CloudTrail is not configured as a multi-region trail (is_multi_region_trail defaults to false)', remediation: 'Set is_multi_region_trail = true if this trail should cover all regions.' };
  },
};

const cloudtrailLogValidation: Rule = {
  id: 'cloudtrail.log-file-validation',
  title: 'CloudTrail log file validation',
  controls: [],
  types: ['aws_cloudtrail'],
  evaluate: (v) => {
    if (isUnknown(v.enable_log_file_validation) || isRedacted(v.enable_log_file_validation)) return { status: 'UNKNOWN', detail: 'CloudTrail log file validation setting not known until apply' };
    if (v.enable_log_file_validation === true) return { status: 'PASS', detail: 'CloudTrail log file validation configured as enabled' };
    return { status: 'WARN', detail: 'CloudTrail log file validation is false or unset', remediation: 'Set enable_log_file_validation = true.' };
  },
};

const cloudtrailKmsKey: Rule = {
  id: 'cloudtrail.kms-key',
  title: 'CloudTrail KMS key configuration',
  controls: [],
  types: ['aws_cloudtrail'],
  evaluate: (v) => {
    if (isUnknown(v.kms_key_id) || isRedacted(v.kms_key_id)) return { status: 'UNKNOWN', detail: 'CloudTrail KMS key not known until apply' };
    if (isSet(v.kms_key_id)) return { status: 'PASS', detail: 'CloudTrail has a KMS key configured' };
    return { status: 'WARN', detail: 'No kms_key_id configured for CloudTrail; this does not mean its logs are unencrypted', remediation: 'Set kms_key_id to use KMS encryption for this trail.' };
  },
};

const vpcFlowLogs: Rule = {
  id: 'network.flow-logs',
  title: 'VPC flow log configuration',
  controls: [],
  types: ['aws_flow_log'],
  evaluate: (v) => {
    if (isUnknown(v.vpc_id) || isRedacted(v.vpc_id)) return { status: 'UNKNOWN', detail: 'Flow log VPC not known until apply' };
    if (!isSet(v.vpc_id)) return undefined;
    // Referrers match best-effort config references, which cannot prove coverage of every VPC instance.
    return { status: 'PASS', detail: 'A VPC flow log is declared in Terraform; delivery and live coverage are not verified' };
  },
};

const cloudwatchLogRetention: Rule = {
  id: 'cloudwatch.log-retention',
  title: 'CloudWatch log retention',
  controls: [],
  types: ['aws_cloudwatch_log_group'],
  evaluate: (v, _res, ctx) => {
    const logClass = v.log_group_class ?? 'STANDARD';
    if (logClass !== 'STANDARD' && logClass !== 'INFREQUENT_ACCESS' && logClass !== 'DELIVERY') {
      return { status: 'UNKNOWN', detail: 'Log group class is unknown or unrecognized; effective retention cannot be determined' };
    }
    // The provider ignores retention_in_days for DELIVERY and forces two-day retention.
    const delivery = logClass === 'DELIVERY';
    const days = delivery ? 2 : v.retention_in_days;
    if (isUnknown(days) || isRedacted(days)) return { status: 'UNKNOWN', detail: 'Log retention not known until apply' };
    if (!isSet(days) || days === 0) return { status: 'INFO', detail: 'CloudWatch logs configured to never expire (retention_in_days is unset or 0)' };
    if (typeof days !== 'number') return { status: 'UNKNOWN', detail: 'Log retention is not a known number of days' };
    if (days < ctx.policy.minLogRetentionDays) {
      return {
        status: 'WARN',
        detail: `Log retention ${days} day(s) is below the policy minimum of ${ctx.policy.minLogRetentionDays}${delivery ? ' (DELIVERY class forces two-day retention)' : ''}`,
        remediation: delivery
          ? 'Use log_group_class = "STANDARD" or "INFREQUENT_ACCESS" and set retention_in_days to meet the policy minimum.'
          : 'Increase retention_in_days to meet the policy minimum, or use 0 to never expire.',
      };
    }
    return { status: 'PASS', detail: `CloudWatch logs configured to expire after ${days} day(s)` };
  },
};

const s3AccessLogging: Rule = {
  id: 's3.access-logging',
  title: 'S3 access log target',
  controls: [],
  types: ['aws_s3_bucket_logging'],
  evaluate: (v) => {
    if (isUnknown(v.target_bucket) || isRedacted(v.target_bucket)) return { status: 'UNKNOWN', detail: 'S3 access log target bucket not known until apply' };
    if (isSet(v.target_bucket)) return { status: 'PASS', detail: 'S3 access logging has a target bucket configured; delivery is not verified' };
    return { status: 'WARN', detail: 'S3 access logging has no target_bucket configured', remediation: 'Set target_bucket on aws_s3_bucket_logging.' };
  },
};

function serviceDisableChange(v: Attrs, res: ResourceChange, attr: string | undefined, service: string, defaultEnabled?: boolean): RuleResult | undefined {
  const uncertainty = res.confidence === 'proven' ? '' : ` (change is ${res.confidence}, not proven)`;
  if (res.action === 'delete') {
    return { status: 'FAIL', detail: `${res.confidence === 'proven' ? 'Deletes' : 'May delete'} the ${service} resource if applied${uncertainty}; coverage outside this Terraform configuration is not verified`, remediation: 'Retain the resource or review and accept its removal.' };
  }
  if (!attr) return undefined;
  const before = typed(reveal(res.before ?? {}) as Attrs, res.type);
  const was = before[attr] ?? defaultEnabled;
  const now = v[attr] ?? defaultEnabled;
  if (was === false || now === true) return undefined;
  if (isUnknown(now) || isRedacted(now) || (now === false && (isUnknown(was) || isRedacted(was)))) {
    return { status: 'UNKNOWN', detail: `${service} may be disabled if applied; the before or after ${attr} value is not known${uncertainty}` };
  }
  if (now !== false) return undefined;
  return { status: 'FAIL', detail: `Sets ${attr} = false on ${service}; this would disable it if applied${uncertainty}. Coverage outside this Terraform configuration is not verified`, remediation: `Keep ${attr} = true or review and accept disabling this resource.` };
}

const cloudtrailDisabled: Rule = {
  id: 'cloudtrail.disabled',
  title: 'CloudTrail disabled or deleted by this change',
  controls: [],
  types: ['aws_cloudtrail'],
  scope: 'change',
  evaluate: (v, res) => {
    if (res.action !== 'update' && res.action !== 'replace' && res.action !== 'delete') return undefined;
    return serviceDisableChange(v, res, 'enable_logging', 'CloudTrail', true);
  },
};

const guarddutyDisabled: Rule = {
  id: 'guardduty.disabled',
  title: 'GuardDuty disabled or deleted by this change',
  controls: [],
  types: ['aws_guardduty_detector'],
  scope: 'change',
  evaluate: (v, res) => serviceDisableChange(v, res, 'enable', 'GuardDuty', true),
};

const configDisabled: Rule = {
  id: 'config.disabled',
  title: 'AWS Config recorder disabled or deleted by this change',
  controls: [],
  types: ['aws_config_configuration_recorder_status'],
  scope: 'change',
  evaluate: (v, res) => serviceDisableChange(v, res, 'is_enabled', 'AWS Config recorder'),
};

const securityhubDisabled: Rule = {
  id: 'securityhub.disabled',
  title: 'Security Hub deleted by this change',
  controls: [],
  types: ['aws_securityhub_account'],
  scope: 'change',
  evaluate: (v, res) => serviceDisableChange(v, res, undefined, 'Security Hub'),
};

// ---------------------------------------------------------------- SQS / SNS

const sqsEncryption: Rule = {
  configurationOnly: true,
  id: 'sqs.encryption',
  title: 'SQS encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_sqs_queue'],
  evaluate: (v, res, ctx) => {
    const kind = keyKind(v.kms_master_key_id);
    if (kind === 'cmk') return encryptionDecision(true, 'kms_master_key_id', 'SQS encryption', { passDetail: 'SSE-KMS with a customer managed key' });
    if (kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', 'SSE-KMS with the AWS managed key aws/sqs');
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: 'KMS key not known until apply' };
    const result = encryptionDecision(v.sqs_managed_sse_enabled, 'sqs_managed_sse_enabled', 'SQS encryption');
    return result.status === 'PASS' ? cmkVerdict(ctx, 'aws-owned', 'SSE-SQS explicitly enabled (SQS managed keys)') : result;
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
  configurationOnly: true,
  id: 'sns.encryption',
  title: 'SNS encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_sns_topic'],
  evaluate: (v, res, ctx) => {
    const kind = keyKind(v.kms_master_key_id);
    if (kind === 'cmk') return encryptionDecision(true, 'kms_master_key_id', 'SNS encryption', { passDetail: 'Encrypted with a customer managed KMS key' });
    if (kind === 'aws-managed') return cmkVerdict(ctx, 'aws-managed', 'Encrypted with the AWS managed key aws/sns');
    if (kind === 'unknown') return { status: 'UNKNOWN', detail: 'KMS key not known until apply' };
    return encryptionDecision(v.kms_master_key_id === '' ? false : undefined, 'kms_master_key_id', 'SNS encryption', { remediation: 'Set kms_master_key_id (alias/aws/sns or a customer managed key).' });
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
  configurationOnly: true,
  id: 'dynamodb.encryption',
  title: 'DynamoDB encryption at rest',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_dynamodb_table'],
  evaluate: (v, res, ctx) => {
    const sse = block(v.server_side_encryption);
    if (sse?.enabled === false) return cmkVerdict(ctx, 'aws-owned', 'Encrypted with an AWS-owned key');
    const result = encryptionDecision(sse?.enabled, 'server_side_encryption.enabled', 'DynamoDB KMS encryption');
    if (result.status !== 'PASS') return result;
    const kind = keyKind(sse?.kms_key_arn);
    if (kind === 'cmk') return encryptionDecision(true, 'server_side_encryption.enabled', 'DynamoDB encryption', { passDetail: 'Encrypted with a customer managed KMS key' });
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
  configurationOnly: true,
  id: 'rds.encryption',
  title: 'RDS storage encryption',
  controls: ['ISO27001:A.8.24'],
  types: ['aws_db_instance', 'aws_rds_cluster'],
  evaluate: (v, res) => {
    const source = v.replicate_source_db;
    const uncertainSource = res.type === 'aws_db_instance' && configuredArgument(v, res, 'replicate_source_db')
      && !(typeof source === 'string' && /^[a-zA-Z][a-zA-Z0-9-]{0,62}$/.test(source) && !source.endsWith('-') && !source.includes('--'));
    return encryptionDecision(v.storage_encrypted, 'storage_encrypted', 'RDS storage encryption', {
      ignoresEncryptionArgument: uncertainSource,
      unknownDetail: uncertainSource ? 'RDS replica source is not a known same-region identifier; storage_encrypted cannot establish inherited encryption' : undefined,
      passDetail: 'Storage encrypted',
      remediation: 'Set storage_encrypted = true (requires a new instance or snapshot restore for existing databases).',
    });
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
  ebsDefaultEncryption,
  ebsEncryption,
  efsEncryption,
  elasticacheEncryption,
  elasticacheTransitEncryption,
  opensearchEncryption,
  opensearchNodeEncryption,
  opensearchHttps,
  elbHttps,
  elbListenerRuleOwner,
  elbTlsPolicy,
  cloudfrontHttps,
  cloudfrontTlsPolicy,
  cloudtrailLogging,
  cloudtrailMultiRegion,
  cloudtrailLogValidation,
  cloudtrailKmsKey,
  vpcFlowLogs,
  cloudwatchLogRetention,
  s3AccessLogging,
  cloudtrailDisabled,
  guarddutyDisabled,
  configDisabled,
  securityhubDisabled,
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
