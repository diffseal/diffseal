# Configuration reference

TerraTrust reads repository configuration from `.terratrust.json` at the root of the repository and optionally from a standalone policy JSON file passed via `--policy` in the CLI or `policy` in the GitHub Action.

## Overview of `.terratrust.json`

A `.terratrust.json` file can hold these groups of settings:

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

In `terratrust replay` and the GitHub Action `pr` mode, policy settings are read from the `"policy"` object and top-level `"exceptions"` array in `.terratrust.json` and merged with any standalone policy JSON file passed via `--policy` or the Action `policy` input. When both `.terratrust.json` and a standalone policy file are present, fields in the standalone policy file override `.terratrust.json`. In `terratrust review --plan` and the GitHub Action `plan` mode, policy settings and exceptions are read from the standalone policy JSON file passed via `--policy` or `policy`.

| Field | Type | Default | Description |
| :-- | :-- | :-- | :-- |
| `requireCustomerManagedKeys` | `boolean` | `false` | Require customer-managed KMS keys on resources where AWS supports them, rather than AWS-managed keys or default SSE-S3 encryption. |
| `minBackupRetentionDays` | `number` | `7` | Minimum backup retention period in days for RDS instances and Aurora clusters. |
| `blockOn` | `Severity[]` | `["CRITICAL"]` | Blast-radius severities that set the gate to `block`. Allowed values are `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, and `"INFO"`. |
| `exceptions` | `PolicyException[]` | `[]` | Accepted findings and blast-radius items. Can be set either at the top level of `.terratrust.json`, inside `"policy"` in `.terratrust.json`, or at the top level of a standalone policy JSON file. |

If `CRITICAL` is removed from `blockOn`, unaccepted `CRITICAL` and `HIGH` blast-radius items still set the gate to `review` and never pass silently.

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
2. In live checks such as `terratrust review` and the GitHub Action `pr` and `plan` modes, `expires` is compared with the current UTC date. In `terratrust replay`, `expires` is compared with the commit date of each replayed commit so historical replays reproduce the gate verdict from when the commit was made.
3. If an expired or malformed exception matches a finding or blast-radius item in the current change, the finding is not accepted, the gate becomes at least `review`, and the gate reasons name the expired or malformed exception.

## Application link settings

When `terratrust check-app` or the GitHub Action in `mode: app` runs on an application repository, it reads `.terratrust.json` at the root of the application repository to find the infrastructure and execution context.

| Field | Type | Default | Description |
| :-- | :-- | :-- | :-- |
| `infra.repo` | `string` | same as `--app` | Path to the repository containing Terraform configurations. Relative paths are resolved from the application repository root. Overridden by `--infra` in the CLI or `infra-path` in the Action. |
| `infra.rev` | `string` | working tree | Git revision in the infrastructure repository to evaluate, such as `origin/main` or a commit SHA. When set, TerraTrust reads Terraform files from git objects at that revision without checking it out. Overridden by `--infra-rev` in the CLI. |
| `infra.rootsUnder` | `string` | all roots | Directory prefix inside the infrastructure repository to limit which Terraform roots are evaluated, such as `envs/prod`. Overridden by `--roots-under` in the CLI or `roots-under` in the Action. |
| `roles` | `string[]` | `[]` | IAM role names, `path/name` strings, or role ARNs that the application runs as. Combined with any roles discovered from task definitions or Kubernetes manifests, unless overridden by `--role` in the CLI or `role` in the Action. |
| `env` | `string[]` | `[]` | Environment variable names provided outside Terraform, such as by a deployment pipeline or runtime secret injector. Variables listed here are never reported as `MISSING`. |

## Base-commit protection

TerraTrust prevents a change from relaxing the rules or link settings that judge it:

- In `terratrust replay` and the GitHub Action `pr` mode, `.terratrust.json` and any repository `policy` file are read from the base commit, not the head commit.
- In `terratrust check-app --base <rev>` and the GitHub Action `app` mode, `.terratrust.json` is read from the base commit when one is given.
- In the GitHub Action, a `policy` file path must sit inside the repository without `..` path traversal so its base-commit version can be read.
- Whenever `.terratrust.json` or the `policy` file differs between the base commit and the head commit, TerraTrust raises the gate to at least `review` and notes that the updated configuration applies starting from the next change after this one is reviewed and merged.

## Trusted upload replay settings

The reusable upload workflow reads `replay` from `.terratrust.json` through `git show`. For pull requests it uses the base branch commit from the event. For pushes it uses the pushed commit on the default branch. It never reads these settings from the working tree or workflow inputs.

```json
{
  "replay": {
    "rootsUnder": "infra",
    "policyFile": "policy.json",
    "moduleCache": ".terratrust/modules"
  }
}
```

All three fields are optional paths inside the repository. `rootsUnder` limits the Terraform roots. Without it, TerraTrust discovers roots across the repository. `policyFile` selects a policy JSON file. Without it, TerraTrust uses the policy in `.terratrust.json` and the built-in defaults. `moduleCache` selects an existing verified offline module cache. It does not fetch modules. Without it, TerraTrust uses the default cache. Unknown or unavailable module contents remain visible in the report.

The workflow has no analysis inputs. A pull request cannot narrow its own analysis by editing these settings. Changes take effect after merge. Direct CLI and Action calls still use their explicit flags and inputs.
