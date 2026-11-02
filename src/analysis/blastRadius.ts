import { isRedacted, isUnknown, reveal, type Attrs, type BlastFinding, type ResourceChange, type Severity } from '../core/model.js';
import { stableKey } from '../hcl/eval.js';
import { typed } from '../policy/values.js';
import { describeGrants, diffGrants } from '../policy/grants.js';
import { describeEnvDiff, diffEnvironment } from '../terraform/environment.js';
import { REPLACE_ON_CHANGE, ROUTINE_REPLACE } from '../terraform/replaceCatalog.js';
import { retainedOnDestroy } from '../terraform/schemaCatalog.js';

const POLICY_TYPES = new Set(['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy']);

/** What an IAM policy update grants and revokes, or undefined if the documents cannot be compared. */
function policyUpdate(c: ResourceChange, changed: string[], note: string): BlastFinding | undefined {
  if (!POLICY_TYPES.has(c.type) || !changed.includes('policy')) return undefined;
  const d = diffGrants(c.before?.policy, c.after?.policy);
  if (!d || (!d.added.length && !d.removed.length)) return undefined;
  const parts: string[] = [];
  if (d.removed.length) parts.push(`Revokes ${describeGrants(d.removed)}; callers that still need it get AccessDenied`);
  if (d.added.length) parts.push(`Grants ${describeGrants(d.added)}`);
  return {
    severity: d.removed.length ? 'LOW' : 'INFO',
    resource: c.address,
    type: c.type,
    action: 'update',
    reason: parts.join('. ') + note,
    dataLoss: false,
    downtime: d.removed.length ? 'possible' : 'no',
  };
}

/** Deleting or replacing these loses data that Terraform cannot recreate. */
const STATEFUL: Record<string, string> = {
  aws_s3_bucket: 'the objects in the bucket',
  aws_dynamodb_table: 'the items in the table',
  aws_dynamodb_global_table: 'the items in the table',
  aws_db_instance: 'the database',
  aws_rds_cluster: 'the database',
  aws_rds_global_cluster: 'the database',
  aws_docdb_cluster: 'the database',
  aws_neptune_cluster: 'the database',
  aws_redshift_cluster: 'the warehouse data',
  aws_efs_file_system: 'the files',
  aws_ebs_volume: 'the volume data',
  aws_elasticache_cluster: 'the cached data',
  aws_elasticache_replication_group: 'the cached data',
  aws_opensearch_domain: 'the indexes',
  aws_elasticsearch_domain: 'the indexes',
  aws_msk_cluster: 'the topics and messages',
  aws_kinesis_stream: 'the stream records',
  aws_sqs_queue: 'messages still in the queue',
  aws_ecr_repository: 'the container images',
  aws_secretsmanager_secret: 'the secret value',
  aws_ssm_parameter: 'the parameter value and its history',
  aws_cognito_user_pool: 'every user and their password (password hashes cannot be exported)',
  aws_route53_zone: 'the zone (a new zone gets new name servers)',
  aws_cloudwatch_log_group: 'the logs, which may be audit evidence',
  aws_backup_vault: 'the recovery points',
  aws_kms_key: 'the ability to decrypt anything encrypted with this key, once the deletion window ends',
  aws_glacier_vault: 'the archives',
  aws_timestreamwrite_table: 'the time series data',
};

/** Replacing these changes an identity, endpoint or address that other systems depend on. */
const IDENTITY_OR_ENDPOINT: Record<string, string> = {
  aws_iam_role: 'resource policies that named the old role keep its unique ID and stop matching the new one',
  aws_lb: 'new DNS name',
  aws_alb: 'new DNS name',
  aws_eip: 'new public IP (allowlists break)',
  aws_security_group: 'every attached ENI must move to the new group',
  aws_vpc: 'everything in the VPC',
  aws_subnet: 'everything in the subnet',
  aws_nat_gateway: 'egress for private subnets during the swap',
  aws_api_gateway_rest_api: 'new invoke URL',
  aws_apigatewayv2_api: 'new invoke URL',
  aws_cloudfront_distribution: 'new distribution domain',
  aws_lambda_function: 'event source mappings and permissions recreated',
  aws_ecs_service: 'running tasks stopped',
  aws_ecs_cluster: 'services in the cluster',
  aws_sns_topic: 'subscriptions recreated, messages published during the swap are lost',
  aws_acm_certificate: 'listeners referencing the certificate',
  aws_iot_topic_rule: 'IoT messages during the swap',
};

/**
 * Deleting these takes an entry point out of service with nothing to replace it: no data is lost, but
 * requests fail until it is created again. Replacing them is a brief swap, rated below.
 */
const SERVES_TRAFFIC: Record<string, string> = {
  aws_api_gateway_stage: 'the API stops serving requests on this stage; redeploying the API does not recreate it',
  aws_apigatewayv2_stage: 'the API stops serving requests on this stage',
  aws_lb_listener: 'the load balancer stops accepting connections on this port',
  aws_alb_listener: 'the load balancer stops accepting connections on this port',
};

/** Guard attributes that make the provider or AWS refuse a destroy. */
function destroyGuard(type: string, before: Attrs, preventDestroy?: boolean): string | undefined {
  if (preventDestroy) return 'lifecycle.prevent_destroy = true, so Terraform will refuse to plan this';
  if (before.deletion_protection === true) return 'deletion_protection = true, so the apply will fail mid-way';
  if (before.deletion_protection_enabled === true) return 'deletion_protection_enabled = true, so the apply will fail mid-way';
  if (type === 'aws_s3_bucket' && before.force_destroy !== true) return 'S3 refuses to delete a non-empty bucket without force_destroy, so the apply fails if it holds objects';
  return undefined;
}

/** `before` holds revealed values for the decision; `raw` is consulted so a sensitive number is not printed. */
function recoverable(type: string, before: Attrs, raw: Attrs): string | undefined {
  const days = (attr: string, fallback: number) =>
    isRedacted(raw[attr]) ? 'the configured number of' : String(typeof before[attr] === 'number' ? before[attr] : fallback);
  if ((type === 'aws_db_instance' || type === 'aws_rds_cluster') && before.skip_final_snapshot === false) return 'a final snapshot is taken';
  if (type === 'aws_secretsmanager_secret' && before.recovery_window_in_days !== 0) return `recoverable for ${days('recovery_window_in_days', 30)} days`;
  if (type === 'aws_kms_key') return `deletion can be cancelled within ${days('deletion_window_in_days', 30)} days`;
  return undefined;
}

interface UpdateRisk {
  attrs: string[];
  severity: Severity;
  downtime: BlastFinding['downtime'];
  why: string;
}

/** In-place updates that still disrupt service. */
const RISKY_UPDATES: Record<string, UpdateRisk[]> = {
  aws_db_instance: [
    { attrs: ['identifier'], severity: 'HIGH', downtime: 'yes', why: 'renames the instance in place; its endpoint DNS name changes, so clients using the old endpoint fail until reconfigured' },
    { attrs: ['instance_class', 'allocated_storage', 'storage_type', 'iops', 'multi_az', 'engine_version', 'parameter_group_name', 'ca_cert_identifier'], severity: 'MEDIUM', downtime: 'possible', why: 'may reboot or fail over the database' },
  ],
  aws_rds_cluster: [{ attrs: ['engine_version', 'db_cluster_parameter_group_name', 'serverlessv2_scaling_configuration'], severity: 'MEDIUM', downtime: 'possible', why: 'may restart cluster instances' }],
  aws_rds_cluster_instance: [{ attrs: ['instance_class', 'db_parameter_group_name', 'ca_cert_identifier'], severity: 'MEDIUM', downtime: 'possible', why: 'may reboot the instance' }],
  aws_elasticache_replication_group: [{ attrs: ['node_type', 'engine_version', 'num_cache_clusters'], severity: 'MEDIUM', downtime: 'possible', why: 'may fail over or resize the cache' }],
  aws_security_group: [{ attrs: ['ingress', 'egress'], severity: 'MEDIUM', downtime: 'possible', why: 'removed rules cut traffic immediately' }],
  aws_security_group_rule: [{ attrs: ['cidr_blocks', 'from_port', 'to_port', 'source_security_group_id'], severity: 'MEDIUM', downtime: 'possible', why: 'removed sources cut traffic immediately' }],
  aws_iam_policy: [{ attrs: ['policy'], severity: 'LOW', downtime: 'possible', why: 'policy document changed and its grants are not known statically' }],
  aws_iam_role_policy: [{ attrs: ['policy'], severity: 'LOW', downtime: 'possible', why: 'policy document changed and its grants are not known statically' }],
  aws_iam_role: [{ attrs: ['assume_role_policy'], severity: 'MEDIUM', downtime: 'possible', why: 'principals no longer trusted cannot assume the role' }],
  aws_lambda_function: [{ attrs: ['reserved_concurrent_executions'], severity: 'LOW', downtime: 'possible', why: 'lower reserved concurrency throttles invocations' }],
  aws_sqs_queue: [{ attrs: ['visibility_timeout_seconds', 'message_retention_seconds', 'redrive_policy'], severity: 'LOW', downtime: 'no', why: 'changes message delivery behaviour' }],
  aws_kms_key: [{ attrs: ['policy', 'is_enabled'], severity: 'MEDIUM', downtime: 'possible', why: 'callers losing key access cannot decrypt' }],
  aws_route53_record: [{ attrs: ['records', 'alias', 'weighted_routing_policy'], severity: 'MEDIUM', downtime: 'possible', why: 'changes where clients are sent' }],
};

const SHOW_VALUE_CHANGES: Record<string, string[]> = {
  aws_cloudwatch_event_rule: ['schedule_expression', 'state', 'is_enabled'],
  aws_scheduler_schedule: ['schedule_expression', 'state'],
  aws_lambda_function: ['memory_size', 'timeout', 'reserved_concurrent_executions'],
  aws_db_instance: ['instance_class', 'engine_version', 'allocated_storage'],
};

const capitalizeFirst = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

function envChange(c: ResourceChange): string | undefined {
  const d = diffEnvironment(c.type, c.before, c.after);
  if (!d || (!d.added.length && !d.removed.length && !d.changed.length)) return undefined;
  return describeEnvDiff(d);
}

export function changedAttrs(before: Attrs | null, after: Attrs | null): string[] {
  if (!before || !after) return [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...keys].filter((k) => !deepEqual(before[k], after[k]) && !(k === 'tags_all'));
}

function deepEqual(a: unknown, b: unknown): boolean {
  return stableKey(a) === stableKey(b);
}

const fmt = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));

export function analyzeBlastRadius(changes: ResourceChange[]): BlastFinding[] {
  const out: BlastFinding[] = [];
  for (const c of changes) {
    if (c.mode !== 'managed') continue;
    // Risk decisions read sensitive values too (force_destroy = sensitive(true) still empties the bucket);
    // reports never print them, because analyze() scrubs the free-text fields.
    const before = typed(reveal(c.before ?? {}) as Attrs, c.type);
    const stateful = STATEFUL[c.type];
    const identity = IDENTITY_OR_ENDPOINT[c.type];

    const note = c.actionReason && !/^[a-z_]+$/.test(c.actionReason) ? ` (${c.actionReason})` : '';
    // A plan deletes it, but with skip_destroy = true the provider only removes it from state.
    if (c.action === 'delete' && !c.preventDestroy && retainedOnDestroy(c.type, before)) {
      out.push({ severity: 'LOW', resource: c.address, type: c.type, action: c.action, reason: `Deletes ${c.type} from Terraform state only: skip_destroy = true, so the provider leaves it in AWS${note}`, dataLoss: false, downtime: 'no' });
      continue;
    }
    if (c.action === 'delete' || c.action === 'replace') {
      const verb = c.action === 'delete' ? 'Deletes' : 'Replaces';
      const inferred = !c.replacePaths?.length && c.action === 'replace' ? changedAttrs(c.before, c.after).filter((a) => REPLACE_ON_CHANGE[c.type]?.includes(a)) : [];
      const forcedBy = c.replacePaths?.length
        ? ` (forced by changing ${c.replacePaths.map((p) => p.join('.')).join(', ')})`
        : inferred.length ? ` (likely forced by changing ${inferred.join(', ')})` : '';
      const order = c.action === 'replace' && c.replaceOrder === 'create-first' ? ', new one created before the old is destroyed' : '';
      if (stateful) {
        const guard = destroyGuard(c.type, before, c.preventDestroy);
        const recovery = recoverable(c.type, before, c.before ?? {});
        let severity: Severity = 'CRITICAL';
        let reason = `${verb} ${c.type}${forcedBy}: applying it would lose ${stateful}`;
        if (guard) {
          severity = 'HIGH';
          reason += `. ${guard}`;
        } else if (recovery) {
          severity = c.action === 'replace' ? 'CRITICAL' : 'HIGH';
          reason += `, ${recovery}`;
        }
        // A replacement static analysis cannot prove is reviewed, not blocked.
        if (severity === 'CRITICAL' && c.confidence !== 'proven') {
          severity = 'HIGH';
          reason = `Possibly ${reason[0].toLowerCase()}${reason.slice(1)}`;
        }
        out.push({ severity, resource: c.address, type: c.type, action: c.action, reason: reason + order + note, dataLoss: !guard, downtime: 'yes' });
      } else if (identity) {
        // What a replacement breaks is the swap to a new object; a deletion has no new object.
        const what = c.action === 'replace' ? `: ${identity}` : ': whatever still refers to it fails';
        const possibly = c.confidence !== 'proven' ? 'Possibly ' : '';
        const text = `${verb} ${c.type}${forcedBy}${what}${order}${note}`;
        out.push({ severity: 'HIGH', resource: c.address, type: c.type, action: c.action, reason: possibly ? possibly + text[0].toLowerCase() + text.slice(1) : text, dataLoss: false, downtime: c.replaceOrder === 'create-first' ? 'possible' : 'yes' });
      } else if (c.action === 'delete' && SERVES_TRAFFIC[c.type]) {
        const text = `Deletes ${c.type}: ${SERVES_TRAFFIC[c.type]}${note}`;
        out.push({ severity: 'HIGH', resource: c.address, type: c.type, action: c.action, reason: c.confidence !== 'proven' ? `Possibly ${text[0].toLowerCase()}${text.slice(1)}` : text, dataLoss: false, downtime: 'yes' });
      } else if (c.action === 'replace' && ROUTINE_REPLACE.has(c.type)) {
        const env = envChange(c);
        out.push({ severity: 'INFO', resource: c.address, type: c.type, action: c.action, reason: `Recreates ${c.type}${forcedBy}${order}${env ? `; ${env}` : ''}${note}`, dataLoss: false, downtime: 'no' });
      } else {
        out.push({
          severity: c.action === 'replace' ? 'MEDIUM' : 'LOW',
          resource: c.address,
          type: c.type,
          action: c.action,
          reason: `${verb} ${c.type}${forcedBy}${order}${note}`,
          dataLoss: false,
          downtime: c.action === 'replace' ? 'possible' : 'no',
        });
      }
      continue;
    }

    if (c.action === 'update' && c.confidence === 'unknown' && c.actionReason?.includes('count or for_each') && stateful) {
      out.push({ severity: 'HIGH', resource: c.address, type: c.type, action: 'update', reason: `May delete or recreate ${c.type}: ${c.actionReason}`, dataLoss: false, downtime: 'possible' });
      continue;
    }
    if (c.action === 'update') {
      const changed = changedAttrs(c.before, c.after);
      const policy = policyUpdate(c, changed, note);
      if (policy) {
        out.push(policy);
        continue;
      }
      const risks = (RISKY_UPDATES[c.type] ?? []).filter((r) => r.attrs.some((a) => changed.includes(a)));
      const shown = (SHOW_VALUE_CHANGES[c.type] ?? []).filter((a) => changed.includes(a)).map((a) => `${a}: ${fmt(c.before?.[a])} -> ${fmt(c.after?.[a])}`);
      const env = envChange(c);
      if (env) shown.push(env);
      if (risks.length) {
        const r = risks[0];
        let severity = r.severity;
        let why = r.why;
        if (c.type === 'aws_db_instance' && typed(reveal(c.after ?? {}) as Attrs, c.type).apply_immediately === true && r.downtime !== 'no') {
          severity = 'HIGH';
          why += ' immediately (apply_immediately = true), not in the maintenance window';
        }
        const attrs = r.attrs.filter((a) => changed.includes(a));
        out.push({ severity, resource: c.address, type: c.type, action: 'update', reason: `Changes ${attrs.join(', ')}: ${why}${shown.length ? `. ${shown.join('; ')}` : ''}${note}`, dataLoss: false, downtime: r.downtime });
      } else {
        out.push({
          severity: 'INFO',
          resource: c.address,
          type: c.type,
          action: 'update',
          reason: capitalizeFirst(shown.length ? shown.join('; ') : changed.length ? `In-place update of ${changed.slice(0, 6).join(', ')}${changed.length > 6 ? ', ...' : ''}` : 'In-place update') + note,
          dataLoss: false,
          downtime: 'no',
        });
      }
      continue;
    }

    if (c.action === 'create' || c.action === 'import' || c.action === 'move' || c.action === 'forget') {
      const reason =
        c.action === 'create' ? `Creates ${c.type}`
        : c.action === 'import' ? `Imports existing ${c.type} into state`
        : c.action === 'move' ? `Moves state from ${c.previousAddress} (no infrastructure change)`
        : `Removes ${c.type} from state without destroying it`;
      out.push({ severity: c.action === 'forget' ? 'LOW' : 'INFO', resource: c.address, type: c.type, action: c.action, reason, dataLoss: false, downtime: 'no' });
    }
  }
  const confidence = new Map(changes.map((c) => [c.address, c.confidence]));
  for (const b of out) {
    const k = confidence.get(b.resource);
    if (k && k !== 'proven') b.confidence = k;
  }
  const rank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  return out.sort((a, b) => rank[a.severity] - rank[b.severity]);
}
