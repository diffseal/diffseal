import generated from './aws-replace.json' with { type: 'json' };

/**
 * Arguments whose change makes the AWS provider replace the resource.
 *
 * `aws-replace.json` is extracted from hashicorp/terraform-provider-aws source by
 * `scripts/extract-forcenew.ts` (SDKv2 `ForceNew: true`, framework `RequiresReplace()`), and records the
 * provider commit it came from. `terraform providers schema -json` does not expose this.
 *
 * A type listed here is "catalogued": a change to any other argument is an in-place update. For types
 * that are not, static replay reports the action as an update with `likely` confidence.
 */
const resources = (generated as { resources: Record<string, { replace: string[]; conditional: string[]; nested?: Record<string, string[]>; sets?: string[] }> }).resources;

/**
 * For a ForceNew nested block (an SDKv2 list or set of resources), the fields inside it that force
 * replacement. The block itself forces replacement only when its element count changes.
 */
export const NESTED_REPLACE: Record<string, Record<string, string[]>> = Object.fromEntries(
  Object.entries(resources).filter(([, e]) => e.nested).map(([t, e]) => [t, e.nested!])
);

/** ForceNew nested blocks that are SDKv2 sets: their blocks have no order, so reordering them is no change. */
export const REPLACE_SETS: Record<string, string[]> = Object.fromEntries(
  Object.entries(resources).filter(([, e]) => e.sets).map(([t, e]) => [t, e.sets!])
);

/**
 * Resources the extractor cannot read yet (schemas assembled elsewhere), and the two built-in
 * "run something again" resources: hashicorp/null `null_resource.triggers` and Terraform's own
 * `terraform_data.triggers_replace` replace the resource whenever they change.
 */
const CURATED_REPLACE: Record<string, string[]> = {
  aws_vpc_security_group_egress_rule: ['security_group_id'],
  null_resource: ['triggers'],
  terraform_data: ['triggers_replace'],
};

/**
 * Arguments that replace only sometimes: ForceNew inside nested blocks, `RequiresReplaceIf`, and
 * replacements decided in CustomizeDiff. A change here is a possible replacement, never a proven one.
 */
const CURATED_CONDITIONAL: Record<string, string[]> = {
  aws_s3_bucket: ['object_lock_enabled'],
  aws_route53_record: ['name', 'type', 'set_identifier'],
  aws_ecs_service: ['deployment_controller'],
};

export const REPLACE_ON_CHANGE: Record<string, string[]> = {
  ...Object.fromEntries(Object.entries(resources).map(([t, e]) => [t, e.replace])),
  ...CURATED_REPLACE,
};

export const CONDITIONAL_REPLACE: Record<string, string[]> = Object.fromEntries(
  [...new Set([...Object.keys(resources), ...Object.keys(CURATED_CONDITIONAL)])].map((t) => [
    t,
    [...new Set([...(resources[t]?.conditional ?? []), ...(CURATED_CONDITIONAL[t] ?? [])])],
  ])
);

export const REPLACE_CATALOG_SOURCE = `${(generated as { source: string }).source}@${(generated as { commit: string }).commit.slice(0, 9)}`;
export const REPLACE_CATALOG_VERSION = (generated as { version: string }).version;

/** Types whose replacement is routine: a new revision, permission or attachment, nothing stateful. */
export const ROUTINE_REPLACE = new Set([
  'null_resource',
  'terraform_data',
  'aws_ecs_task_definition',
  'aws_lambda_permission',
  'aws_iam_role_policy_attachment',
  'aws_iam_user_policy_attachment',
  'aws_security_group_rule',
  'aws_sns_topic_subscription',
  'aws_cloudwatch_event_target',
  'aws_cloudwatch_metric_alarm',
  'aws_s3_bucket_public_access_block',
  'aws_s3_bucket_server_side_encryption_configuration',
  'aws_s3_bucket_versioning',
  'aws_s3_bucket_lifecycle_configuration',
  'aws_s3_bucket_policy',
  'aws_sqs_queue_policy',
  'aws_lambda_event_source_mapping',
]);
