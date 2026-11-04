# Configuration reference

Diffseal reads repository configuration from `.diffseal.json` at the root of the repository and optionally from a standalone policy JSON file passed via `--policy` in the CLI or `policy` in the GitHub Action.

## Overview of `.diffseal.json`

A `.diffseal.json` file can hold these groups of settings:

- `replay`: Analysis paths for the trusted upload workflow.
- `roots`: The var-files and workspaces each Terraform root is deployed with.
- `policy`: Thresholds and blocking severities for infrastructure policy checks and blast radius.
- `exceptions`: Time-limited acceptances for specific policy findings or destructive changes.

The `infra`, `roles` and `env` link settings belonged to the removed application code check. Diffseal ignores them now, so you can delete them.

```json
{
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

## Root inputs: var-files and workspaces

Replay evaluates each root the way you deploy it only when it knows the inputs. Without help it finds them like this:

- **Workspaces.** A root whose configuration compares `terraform.workspace` with a string (`terraform.workspace == "prod"`), looks it up in a literal list (`contains(["test", "prod"], terraform.workspace)`), or indexes a map with it (`lookup(var.accounts, terraform.workspace)`, `local.sizes[terraform.workspace]`) is evaluated once per name found, besides `default`. This also works through a local, a module output or a module input that holds the workspace, and the map may come from `terraform.tfvars`. At most 8 names besides `default` are evaluated; the report says when more were found. A root that reads `terraform.workspace` without such a comparison is evaluated as `default` only, and the report says so.
- **Var-files.** A `.tfvars` file in the root directory, or in a directory below it that holds no Terraform, is evaluated with that root on its own. When its name matches a workspace the configuration tells apart (`prod.tfvars` and `"prod"`), it is evaluated in that workspace. A changed var-file found this way is still reviewed, because which roots load it, and with which other var-files, is set outside the configuration.

Every result names its environment: `app/workspace prod: aws_sqs_queue.q`, and the roots line of the report, the JSON output (`workspace`, `varFiles`) and the change record list `app (workspace prod)`.

To say exactly how a root is deployed, list it under `roots`:

```json
{
  "roots": {
    "infra/app": {
      "environments": [
        { "workspace": "prod", "varFiles": ["../vars/common.tfvars", "../vars/prod.tfvars"] },
        { "workspace": "staging", "varFiles": ["../vars/common.tfvars", "../vars/staging.tfvars"] }
      ]
    },
    "ops/services/*": { "workspaces": ["test", "sandbox", "prod"] }
  }
}
```

- A key is a root directory, relative to the repository root. `*` matches any characters inside one path segment. An exact key wins over a pattern; among patterns, the first in the file wins.
- `environments` lists one entry per deployment. `workspace` is the Terraform workspace (`default` when left out). `varFiles` are loaded in order, each overriding the ones before it, as repeated `-var-file` options do. Paths are relative to the root directory, the way Terraform reads `-var-file` when it runs there.
- `workspaces` is a short form: one environment per name, without var-files.
- With an entry, exactly the listed environments are evaluated, at most 16. A root the change adds or moves uses the entry for its new directory, or else the one for its old directory. The evaluation without inputs and the workspace and var-file discovery above are not used for that root. List `default` if it is a real deployment.
- A changed var-file that is evaluated through the mapping no longer needs a coverage review. It is still reviewed when it sets a variable that no root it is mapped to declares, or when it does not parse. Diffseal takes the mapping as the complete list of roots that load a mapped var-file.
- A mapped var-file that is added or deleted by the change is a new or removed environment. It is reviewed by name, not compared. One that exists at neither commit, an entry that is not valid, and a path outside the repository are ignored, and the report says so.

Diffseal reads `roots` from the base commit, never from the head. A pull request cannot change how it is reviewed: a mapping it adds or edits applies from the next change, and changing `.diffseal.json` raises the gate to REVIEW (see [Base-commit protection](#base-commit-protection)).

### Terragrunt

A `terragrunt.hcl` whose `terraform { source = ... }` is a local path, or that sits next to Terraform files, is evaluated with the module it runs:

- `inputs` with literal values and with `locals` built from literals and pure functions are read, merged with the `inputs` of a parent it includes with `include { path = find_in_parent_folders(...) }` or a path. `merge_strategy` `shallow` (the default), `deep` (maps merged, lists appended) and `no_merge` are followed; with several includes, the last one's `terraform` source wins. The path functions `get_terragrunt_dir()`, `get_parent_terragrunt_dir()`, `get_repo_root()`, `path_relative_to_include()` and `find_in_parent_folders()` are evaluated.
- A file an input reads with `file()` is read from the repository, and an edit to it, or to a file read with `read_terragrunt_config()`, replays the configuration.
- Inputs reach Terraform as `TF_VAR_` variables, so `terraform.tfvars` and `*.auto.tfvars` in the module override them, as they do in a real run.
- Diffseal never runs Terragrunt, a hook or `run_cmd`, and reads no environment variables. An input that needs `dependency` outputs, `get_env`, `run_cmd`, `read_terragrunt_config`, `sops_decrypt_file` or an exposed `include` stays unknown. When the change touches such an input, a `generate` block, a hook, `extra_arguments`, `remote_state` or another setting Diffseal does not evaluate, the change is reviewed and the line names it. An input the module does not declare is reviewed too, and the line says when a `generate` block may declare it.

## Policy settings

In `diffseal replay` and the GitHub Action `pr` mode, Diffseal reads policy settings from the `"policy"` object and top-level `"exceptions"` array in `.diffseal.json` and merges them with any standalone policy JSON file passed via `--policy` or the Action `policy` input. When both `.diffseal.json` and a standalone policy file are present, fields in the standalone policy file override `.diffseal.json`. In `diffseal review --plan` and the GitHub Action `plan` mode, Diffseal reads policy settings and exceptions from the standalone policy JSON file passed via `--policy` or `policy`.

| Field | Type | Default | Description |
| :-- | :-- | :-- | :-- |
| `requireCustomerManagedKeys` | `boolean` | `false` | Require customer-managed KMS keys on resources where AWS supports them, rather than AWS-managed keys or default SSE-S3 encryption. |
| `minBackupRetentionDays` | `number` | `7` | Minimum backup retention period in days for RDS instances and Aurora clusters. |
| `minLogRetentionDays` | `number` | `0` | Minimum finite CloudWatch log retention in days. `0` means no minimum. Unset retention or `retention_in_days = 0` means logs never expire and always meets the minimum. |
| `blockOn` | `Severity[]` | `["CRITICAL"]` | Blast-radius severities that set the gate to `block`. Allowed values are `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, and `"INFO"`. |
| `exceptions` | `PolicyException[]` | `[]` | Accepted findings and blast-radius items. Can be set either at the top level of `.diffseal.json`, inside `"policy"` in `.diffseal.json`, or at the top level of a standalone policy JSON file. |

If you remove `CRITICAL` from `blockOn`, unaccepted `CRITICAL` and `HIGH` blast-radius items still set the gate to `review` and never pass silently.

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

Unknown settings produce `UNKNOWN`, never a proven pass or disablement. A likely or unknown deletion still asks for review, and the detail states its uncertainty. Diffseal does not report an existing disabled setting as a new disablement on an unrelated update. Deletion findings remain new even if the resource was already disabled. No rule fails a repository for lacking a security service.

`WARN`, `UNKNOWN` and `INFO` are advisory in the existing gate. New, unaccepted `FAIL` findings set REVIEW, never BLOCK. `blockOn` controls blast-radius severities separately; there is no per-rule policy severity override. These change checks therefore cannot block by themselves.

The flow-log rule skips subnet and ENI declarations without a `vpc_id`. It does not flag an `aws_vpc` for missing logs, because the engine's best-effort reference matching cannot prove coverage across ambiguous count/for_each instances or unresolved values.

All these rules carry only `SOC2:CC7.2`, confirmed on page 40 of the AICPA file cited in the [crosswalk research](../research/compliance-crosswalk.md#soc-2-aicpa-2017-trust-services-criteria-revised-points-of-focus-2022). ISO A.8.15 remains unverified and is not assigned.

## Encryption checks

Encryption checks describe the configuration on changed resources. Across all encryption checks, PASS requires explicit enablement; WARN requires explicit disablement with no enforcing setting in the same configuration and provider applying at creation; all other cases are UNKNOWN. Provider defaults and computed-only plan values never establish enablement or disablement. They do not read AWS or verify that a change was applied. Every rule below carries `ISO27001:A.8.24`, plus `SOC2:CC6.7` for transit or `SOC2:CC6.1` for at rest, through the existing crosswalk.

| Rule | Resource | Warns when |
| :-- | :-- | :-- |
| `elb.https` | `aws_lb_listener` | An HTTP listener has a known reachable action without an HTTPS redirect; associated listener rules are evaluated in priority order |
| `elb.tls-policy` | `aws_lb_listener` | An HTTPS listener's known SSL policy permits TLS below 1.2; omitted `ssl_policy` remains `UNKNOWN` |
| `cloudfront.https` | `aws_cloudfront_distribution` | Any default or ordered cache behavior uses `viewer_protocol_policy = "allow-all"` |
| `cloudfront.tls-policy` | `aws_cloudfront_distribution` | The viewer certificate's minimum protocol permits TLS below 1.2 |
| `elasticache.transit-encryption` | `aws_elasticache_replication_group`, `aws_elasticache_cluster` | `transit_encryption_enabled` is explicitly false on a primary replication group or supported Memcached cluster |
| `opensearch.node-to-node-encryption` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `node_to_node_encryption.enabled` is explicitly false |
| `opensearch.https` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `domain_endpoint_options.enforce_https` is false |
| `ebs.default-encryption` | `aws_ebs_encryption_by_default` | `enabled` is explicitly false; omitted remains `UNKNOWN` |
| `ebs.encryption` | `aws_ebs_volume` | `encrypted` is explicitly false without applicable configured enforcement at creation; omitted remains `UNKNOWN` |
| `efs.encryption` | `aws_efs_file_system` | `encrypted` is explicitly false |
| `elasticache.encryption` | `aws_elasticache_replication_group` | `at_rest_encryption_enabled` is explicitly false on a primary |
| `opensearch.encryption` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | `encrypt_at_rest.enabled` is explicitly false |

These rules produce at most `WARN`, which is advisory in the existing gate, and never block by themselves. Unknown or unavailable sensitive settings and unresolved blocks produce `UNKNOWN`. TLS policies are classified using verified protocol tables, rather than dates or name prefixes; unrecognized policies remain `UNKNOWN`. Data sources and ordinary resource deletes do not run these configuration checks. Listener-rule changes, including deletion, re-evaluate their owner even when the listener is unchanged; unresolved owners produce `UNKNOWN` on the rule. Pre-existing findings and policy exceptions use the existing mechanisms and finding/evidence record schemas.

The listener checks cover HTTP/HTTPS, default actions and associated `aws_lb_listener_rule` actions. A catch-all path condition (`/*` or `*`, without additional restrictions) redirecting to HTTPS can make the default unreachable; earlier rules must also redirect. Unresolved association, priority or general condition coverage remains `UNKNOWN`. Other listener protocols are outside their scope. An omitted listener protocol is `UNKNOWN` because its default depends on load balancer type. CloudFront checks every declared cache behavior. An explicitly selected default CloudFront certificate forces a TLSv1 floor regardless of `minimum_protocol_version`; an omitted minimum remains `UNKNOWN`. OpenSearch requires explicit `enforce_https`; omitted flags and blocks remain `UNKNOWN`.

EBS volumes with omitted `encrypted` always remain `UNKNOWN`. An explicitly enabled `aws_ebs_encryption_by_default` in the same provider configuration and region suppresses an explicit-false volume warning to `UNKNOWN` only at creation or replacement. Creation defaults do not affect existing-resource updates, including Redis-to-Valkey upgrades. Only a configured, resolved `global_replication_group_id` establishes an ElastiCache global secondary, which returns `UNKNOWN` for inherited encryption without conflicting local flag remediation. Unknown or computed membership never suppresses explicit encryption flag checks. Memcached cluster transit checks require a known version of 1.6.12 or later and VPC configuration; unresolved or unsupported prerequisites remain `UNKNOWN`. Redis/Valkey clusters and replication-group members are skipped at the cluster level. ElastiCache's transit check tests enablement, not whether `transit_encryption_mode` requires all clients to use TLS. These additions check encryption enablement, without extending the customer-managed-key policy to new resource types.

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

`analyze` validates every exception before it can accept a policy finding or blast-radius item:

1. `resource` must be a string, and `expires` must match `YYYY-MM-DD` and parse as a valid date. Diffseal treats an exception without `resource`, or with an invalid `expires` date, as malformed, and it never applies.
2. In live checks such as `diffseal review` and the GitHub Action `pr` and `plan` modes, Diffseal compares `expires` with the current UTC date. In `diffseal replay`, it compares `expires` with the commit date of each replayed commit, so historical replays reproduce the gate verdict from when the commit was made.
3. If an expired or malformed exception matches a finding or blast-radius item in the current change, the finding is not accepted, the gate becomes at least `review`, and the gate reasons name the expired or malformed exception.

## Base-commit protection

Diffseal prevents a change from relaxing the rules that judge it:

- In `diffseal replay` and the GitHub Action `pr` mode, Diffseal reads `.diffseal.json` and any repository `policy` file from the base commit, not the head commit. This covers the `roots` mapping of var-files and workspaces.
- In the GitHub Action, a `policy` file path must sit inside the repository without `..` path traversal, so Diffseal can read its base-commit version.
- Whenever `.diffseal.json` or the `policy` file differs between the base commit and the head commit, Diffseal raises the gate to at least `review` and notes that the updated configuration applies starting from the next change after this one is reviewed and merged.

## Trusted upload replay settings

The reusable upload workflow reads `replay` from `.diffseal.json` through `git show`. For pull requests it uses the base branch commit from the event. For pushes it uses the first parent of the pushed commit, which is the commit the Action compares the push with. A force push or a new branch does not change that, because the workflow does not use the event's `before` commit. Only a root commit, which has no parent, is read itself. It never reads these settings from the working tree or workflow inputs.

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

The workflow has no analysis inputs. A pull request or a pushed commit cannot narrow its own analysis by editing these settings; changes take effect from the next change. A push of several commits is read with the settings of the commit before its last one, which that push can itself have changed. Push such changes on their own, or through a pull request. Direct CLI and Action calls still use their explicit flags and inputs.
