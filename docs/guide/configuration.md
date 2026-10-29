# Configuration reference

Diffseal reads repository configuration from `.diffseal.json` at the root of the repository and optionally from a standalone policy JSON file passed via `--policy` in the CLI or `policy` in the GitHub Action.

## Overview of `.diffseal.json`

A `.diffseal.json` file can hold these groups of settings:

- `replay`: Analysis paths for the trusted upload workflow.
- `policy`: Thresholds and blocking severities for infrastructure policy checks and blast radius.
- `exceptions`: Time-limited acceptances for specific policy findings or destructive changes.
- `infra`, `roles`, and `env`: Link settings that tell `check-app` where to find Terraform and how the application runs in AWS.

```json
{
  "infra": {
    "repo": "../infra",
    "rev": "origin/main",
    "rootsUnder": "envs/prod"
  },
  "roles": ["orders-api-task"],
  "env": ["EXTERNAL_CONFIG_BUCKET"],
  "policy": {
    "requireCustomerManagedKeys": false,
    "minBackupRetentionDays": 7,
    "minLogRetentionDays": 0,
    "blockOn": ["CRITICAL"]
  },
  "exceptions": [
    {
      "rule": "network.open-ingress",
      "resource": "module.gateway.aws_vpc_security_group_ingress_rule.devices*",
      "reason": "Devices connect from the internet over mutual TLS",
      "owner": "platform",
      "expires": "2027-03-31"
    }
  ]
}
```

## Policy settings

In `diffseal replay` and the GitHub Action `pr` mode, policy settings are read from the `"policy"` object and top-level `"exceptions"` array in `.diffseal.json` and merged with any standalone policy JSON file passed via `--policy` or the Action `policy` input. When both `.diffseal.json` and a standalone policy file are present, fields in the standalone policy file override `.diffseal.json`. In `diffseal review --plan` and the GitHub Action `plan` mode, policy settings and exceptions are read from the standalone policy JSON file passed via `--policy` or `policy`.

| Field | Type | Default | Description |
| :-- | :-- | :-- | :-- |
| `requireCustomerManagedKeys` | `boolean` | `false` | Require customer-managed KMS keys on resources where AWS supports them, rather than AWS-managed keys or default SSE-S3 encryption. |
| `minBackupRetentionDays` | `number` | `7` | Minimum backup retention period in days for RDS instances and Aurora clusters. |
| `minLogRetentionDays` | `number` | `0` | Minimum finite CloudWatch log retention in days. `0` means no minimum. Unset retention or `retention_in_days = 0` means logs never expire and always meets the minimum. |
| `blockOn` | `Severity[]` | `["CRITICAL"]` | Blast-radius severities that set the gate to `block`. Allowed values are `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, and `"INFO"`. |
| `exceptions` | `PolicyException[]` | `[]` | Accepted findings and blast-radius items. Can be set either at the top level of `.diffseal.json`, inside `"policy"` in `.diffseal.json`, or at the top level of a standalone policy JSON file. |

If `CRITICAL` is removed from `blockOn`, unaccepted `CRITICAL` and `HIGH` blast-radius items still set the gate to `review` and never pass silently.

## Logging and security-service checks

These checks judge what Terraform declares on changed resources. They do not read AWS or establish whether logs are delivered, services are running, or organization-level coverage exists.

| Rule | Resource | What it reports | Default status |
| :-- | :-- | :-- | :-- |
| `cloudtrail.logging` | `aws_cloudtrail` | `enable_logging = false`; unset uses the provider default of true | `FAIL` (REVIEW) |
| `cloudtrail.multi-region` | `aws_cloudtrail` | `is_multi_region_trail` false or unset (default false) | `WARN` |
| `cloudtrail.log-file-validation` | `aws_cloudtrail` | `enable_log_file_validation` false or unset | `WARN` |
| `cloudtrail.kms-key` | `aws_cloudtrail` | Missing or empty `kms_key_id`; this does not imply unencrypted logs | `WARN` |
| `network.flow-logs` | `aws_flow_log` | A VPC flow log declaration with a configured `vpc_id` | `PASS` for a known VPC value |
| `cloudwatch.log-retention` | `aws_cloudwatch_log_group` | Unset or zero retention; finite retention below `minLogRetentionDays` | `INFO` for never expiring; `WARN` below the minimum |
| `s3.access-logging` | `aws_s3_bucket_logging` | Missing or empty `target_bucket` | `WARN` |
| `cloudtrail.disabled` | `aws_cloudtrail` | Logging enabled to disabled, including default true to false; resource deletion | `FAIL` (REVIEW) |
| `guardduty.disabled` | `aws_guardduty_detector` | Change sets `enable = false`, or deletes the detector | `FAIL` (REVIEW) |
| `config.disabled` | `aws_config_configuration_recorder_status` | Change sets `is_enabled = false`, or deletes the status resource | `FAIL` (REVIEW) |
| `securityhub.disabled` | `aws_securityhub_account` | Deletes the enrollment resource | `FAIL` (REVIEW) |

Unknown settings produce `UNKNOWN`, never a proven pass or disablement. A likely or unknown deletion is still referred for review, with its uncertainty stated in the detail. Existing disabled settings are not reported as a new disablement on unrelated updates. Deletion findings remain new even if the resource was already disabled. No rule fails a repository for lacking a security service.

`WARN`, `UNKNOWN` and `INFO` are advisory in the existing gate. New, unaccepted `FAIL` findings set REVIEW, never BLOCK. `blockOn` controls blast-radius severities separately; there is no per-rule policy severity override. These change checks therefore cannot block by themselves.

The flow-log rule skips subnet and ENI declarations without a `vpc_id`. It does not flag an `aws_vpc` for missing logs: the engine's best-effort reference matching cannot prove coverage across ambiguous count/for_each instances or unresolved values.

All these rules carry only `SOC2:CC7.2`, confirmed on page 40 of the AICPA file cited in the [crosswalk research](../research/compliance-crosswalk.md#soc-2-aicpa-2017-trust-services-criteria-revised-points-of-focus-2022). ISO A.8.15 remains unverified and is not assigned.

## Encryption checks

Encryption checks describe the configuration on changed resources. They do not read AWS or verify that a change was applied. Every rule below carries `ISO27001:A.8.24`, plus `SOC2:CC6.7` for transit or `SOC2:CC6.1` for at rest, through the existing crosswalk.

| Rule | Resource | Warns when |
| :-- | :-- | :-- |
| `elb.https` | `aws_lb_listener` | An HTTP listener has a known reachable action without an HTTPS redirect; associated listener rules are evaluated in priority order |
| `elb.tls-policy` | `aws_lb_listener` | An HTTPS listener's known SSL policy permits TLS below 1.2; omitted `ssl_policy` uses `ELBSecurityPolicy-2016-08` |
| `cloudfront.https` | `aws_cloudfront_distribution` | Any default or ordered cache behavior uses `viewer_protocol_policy = "allow-all"` |
| `cloudfront.tls-policy` | `aws_cloudfront_distribution` | The viewer certificate's minimum protocol permits TLS below 1.2 |
| `elasticache.transit-encryption` | `aws_elasticache_replication_group`, `aws_elasticache_cluster` | `transit_encryption_enabled` is false or unset on a primary replication group or supported Memcached cluster |
| `opensearch.node-to-node-encryption` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `node_to_node_encryption.enabled` is false or the block is omitted |
| `opensearch.https` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `domain_endpoint_options.enforce_https` is false |
| `ebs.default-encryption` | `aws_ebs_encryption_by_default` | `enabled` is false; omitted uses the provider default of true |
| `ebs.encryption` | `aws_ebs_volume` | `encrypted` is explicitly false; omitted encryption uses an applicable declared enabled default, otherwise remains `UNKNOWN` |
| `efs.encryption` | `aws_efs_file_system` | `encrypted` is false or unset |
| `elasticache.encryption` | `aws_elasticache_replication_group` | `at_rest_encryption_enabled` is false or unset on a primary, except Valkey defaults to true |
| `opensearch.encryption` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `encrypt_at_rest.enabled` is false or the block is omitted |

These rules produce at most `WARN`, which is advisory in the existing gate, and never block by themselves. Unknown or unavailable sensitive settings and unresolved blocks produce `UNKNOWN`. TLS policies are classified using verified protocol tables, rather than dates or name prefixes; unrecognized policies remain `UNKNOWN`. Ordinary deletes, unchanged resources and data sources do not run these configuration checks. Pre-existing findings and policy exceptions use the existing mechanisms and finding/evidence record schemas.

The listener checks cover HTTP/HTTPS, default actions and associated `aws_lb_listener_rule` actions. A catch-all path condition (`/*` or `*`, without additional restrictions) redirecting to HTTPS can make the default unreachable; earlier rules must also redirect. Unresolved association, priority or general condition coverage remains `UNKNOWN`. Other listener protocols are outside their scope. An omitted listener protocol is `UNKNOWN` because its default depends on load balancer type. CloudFront checks every declared cache behavior. The default CloudFront certificate forces a TLSv1 floor regardless of `minimum_protocol_version`; a custom certificate's omitted minimum also defaults to TLSv1. OpenSearch's `enforce_https` defaults to true inside a configured endpoint-options block; an omitted or unresolved block is `UNKNOWN`.

EBS volumes with omitted `encrypted` pass when an enabled `aws_ebs_encryption_by_default` applies to the same provider configuration and region. Otherwise encryption remains `UNKNOWN`, since account or snapshot defaults may exist outside Terraform. ElastiCache global secondaries with `global_replication_group_id` set return `UNKNOWN` for inherited encryption, without recommending conflicting local flags. Memcached cluster transit checks require a known version of 1.6.12 or later and VPC configuration; unresolved or unsupported prerequisites remain `UNKNOWN`. Redis/Valkey clusters and replication-group members are skipped at the cluster level. ElastiCache's transit check tests enablement, not whether `transit_encryption_mode` requires all clients to use TLS. These additions check encryption enablement, without extending the customer-managed-key policy to new resource types.

The S3 `aws:SecureTransport` deny check is skipped. The existing IAM code parses policies and analyzes grants but does not prove that a deny covers all relevant principals, actions and resources, including conditions and unresolved statements. Finding a condition key alone would not establish transport enforcement. See the [provider argument verification and scope notes](../research/compliance-crosswalk.md#encryption-check-scope).

## Exceptions

An exception accepts a policy finding or a blast-radius item on matching resources until its expiry date. Accepted items remain visible in the report under the collapsible section for passing, accepted, and pre-existing checks, and they do not fail or block the gate.

| Field | Type | Required | Description |
| :-- | :-- | :-- | :-- |
| `rule` | `string` | no | Rule identifier to accept, such as `network.open-ingress` or `iam.no-wildcard-admin`. Set `rule` to `"blast-radius"` to accept a blast-radius item such as deleting or replacing a stateful resource. Omit `rule` to accept every policy rule on the matching resource. |
| `resource` | `string` | yes | Resource address pattern to match. The `*` character matches any sequence of characters, including module or instance suffixes such as `module.db.aws_db_instance.main*`. |
| `reason` | `string` | yes | Plain explanation of why the risk is accepted, shown in reports and change records. |
| `owner` | `string` | no | Team or person responsible for reviewing the exception before it expires. |
| `expires` | `string` | yes | Expiry date in `YYYY-MM-DD` format. Must be a valid calendar date. |

### Expiry and validation rules

Every exception is validated in `analyze` before it can accept a policy finding or blast-radius item:

1. `resource` must be a string, and `expires` must match `YYYY-MM-DD` and parse as a valid date. Any exception missing `resource` or carrying an invalid `expires` date is treated as malformed and never applies.
2. In live checks such as `diffseal review` and the GitHub Action `pr` and `plan` modes, `expires` is compared with the current UTC date. In `diffseal replay`, `expires` is compared with the commit date of each replayed commit so historical replays reproduce the gate verdict from when the commit was made.
3. If an expired or malformed exception matches a finding or blast-radius item in the current change, the finding is not accepted, the gate becomes at least `review`, and the gate reasons name the expired or malformed exception.

## Application link settings

When `diffseal check-app` or the GitHub Action in `mode: app` runs on an application repository, it reads `.diffseal.json` at the root of the application repository to find the infrastructure and execution context.

| Field | Type | Default | Description |
| :-- | :-- | :-- | :-- |
| `infra.repo` | `string` | same as `--app` | Path to the repository containing Terraform configurations. Relative paths are resolved from the application repository root. Overridden by `--infra` in the CLI or `infra-path` in the Action. |
| `infra.rev` | `string` | working tree | Git revision in the infrastructure repository to evaluate, such as `origin/main` or a commit SHA. When set, Diffseal reads Terraform files from git objects at that revision without checking it out. Overridden by `--infra-rev` in the CLI. |
| `infra.rootsUnder` | `string` | all roots | Directory prefix inside the infrastructure repository to limit which Terraform roots are evaluated, such as `envs/prod`. Overridden by `--roots-under` in the CLI or `roots-under` in the Action. |
| `roles` | `string[]` | `[]` | IAM role names, `path/name` strings, or role ARNs that the application runs as. Combined with any roles discovered from task definitions or Kubernetes manifests, unless overridden by `--role` in the CLI or `role` in the Action. |
| `env` | `string[]` | `[]` | Environment variable names provided outside Terraform, such as by a deployment pipeline or runtime secret injector. Variables listed here are never reported as `MISSING`. |

## Base-commit protection

Diffseal prevents a change from relaxing the rules or link settings that judge it:

- In `diffseal replay` and the GitHub Action `pr` mode, `.diffseal.json` and any repository `policy` file are read from the base commit, not the head commit.
- In `diffseal check-app --base <rev>` and the GitHub Action `app` mode, `.diffseal.json` is read from the base commit when one is given.
- In the GitHub Action, a `policy` file path must sit inside the repository without `..` path traversal so its base-commit version can be read.
- Whenever `.diffseal.json` or the `policy` file differs between the base commit and the head commit, Diffseal raises the gate to at least `review` and notes that the updated configuration applies starting from the next change after this one is reviewed and merged.

## Trusted upload replay settings

The reusable upload workflow reads `replay` from `.diffseal.json` through `git show`. For pull requests it uses the base branch commit from the event. For pushes it uses the pushed commit on the default branch. It never reads these settings from the working tree or workflow inputs.

```json
{
  "replay": {
    "rootsUnder": "infra",
    "policyFile": "policy.json",
    "moduleCache": ".diffseal/modules"
  }
}
```

All three fields are optional paths inside the repository. `rootsUnder` limits the Terraform roots. Without it, Diffseal discovers roots across the repository. `policyFile` selects a policy JSON file. Without it, Diffseal uses the policy in `.diffseal.json` and the built-in defaults. `moduleCache` selects an existing verified offline module cache. It does not fetch modules. Without it, Diffseal uses the default cache. Unknown or unavailable module contents remain visible in the report.

The workflow has no analysis inputs. A pull request cannot narrow its own analysis by editing these settings. Changes take effect after merge. Direct CLI and Action calls still use their explicit flags and inputs.
