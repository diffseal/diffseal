# Diffseal

> **Beta status, v0.4.1-beta.** Diffseal reviews Terraform changes on AWS, checks that application code has the IAM permissions it needs, and writes audit change records. It is a beta validated on one production monorepo. Run the GitHub Action in advisory mode first, with `advisory: 'true'`, and report issues in the [GitHub issue tracker](https://github.com/diffseal/diffseal/issues).

Diffseal reviews Terraform changes on AWS and checks that application code has the IAM permissions it needs. It works from source code and git history. It never asks for cloud credentials and never runs `terraform`.

It answers four questions about a change:

1. **What does it do to infrastructure?** Creates, updates, replacements and deletions, worked out from the configuration at both commits. A replacement names the argument that forced it.
2. **What can break?** Deleting or replacing something stateful (a database, a bucket, a Cognito user pool) blocks the gate. An update that reboots a database or narrows an IAM policy is flagged for review.
3. **Does the code have the permissions it needs?** The AWS SDK calls in Go, TypeScript and Python are matched to the role of the Lambda or ECS task that runs the code. A missing permission comes with the statement to add and the file to add it in.
4. **What evidence does an auditor get?** Each finding cites the ISO/IEC 27001:2022 Annex A control it relates to. A replay of history produces the population of changes an auditor samples from.

## Quick start

```bash
bun install
bun test
bun run demo        # a risky plan, and an app whose role is missing dynamodb:Query
```

## Commands

```bash
# Review a plan (terraform show -json plan.tfplan > plan.json)
diffseal review --plan plan.json [--strict]

# Replay commits of a local clone, without credentials. Reports go to ./dry-runs.
diffseal replay --repo ../infra --commit 1a2b3c4
diffseal replay --repo ../infra --since 2026-09-01

# Check what an application needs from AWS against the IAM in Terraform
diffseal check-app --app . --worktree
diffseal check-app --app ../orders-api --infra ../infra --base origin/main
diffseal check-app --app ../infra --entry services/worker/cmd/worker --role worker-task
```

Exit codes: `0` pass, `1` error, `2` the gate failed.

### What replay does, and what it cannot do

`replay` reads git objects only (`ls-tree`, `cat-file`, `diff`). It never checks out, writes to, or sends anything from the repository, and it refuses to write reports inside it. For each commit it:

- finds the Terraform roots whose module tree the commit touches
- evaluates each root at both commits: local modules, variables, locals, `count`, `for_each`, `dynamic` blocks and policy documents
- compares the two, honouring `moved`, `removed` and `import` blocks
- classifies replacements using a catalogue of the arguments that force a new resource, extracted from the AWS provider's source (`scripts/extract-forcenew.ts`, stamped with the provider commit)

Replay also writes a change record per commit (`records/<sha>.json`, schema `diffseal.change-record/v1`): what changed, the gate, the findings with the controls they relate to, and, with `--approvals`, who approved the change. `summary.csv` is the change population an auditor samples from, and `MANIFEST.sha256` covers every file written. The approvals file maps commit to approvals and can be exported read-only with the GitHub CLI; Diffseal itself makes no network calls.

Without state or provider calls, some values are only known after apply. Changes that depend on them are reported as `likely` rather than `proven`. Data sources resolve to references, not values. Registry and git modules are shown as module calls whose inputs changed, because their source is not available offline.

### How check-app finds the role

1. **By environment variable.** The code reads `ORDERS_TABLE`, and a Lambda or ECS task definition in Terraform sets `ORDERS_TABLE`, so that compute's role runs the code. When several computes match, the one whose environment best matches the package wins.
2. **By deployment files.** An application repository that deploys its own ECS task definition (`taskdef*.json`) names its role in `taskRoleArn`; on EKS, a ServiceAccount manifest or Helm values name it in the `eks.amazonaws.com/role-arn` annotation. Env vars set in those files count as set. A role ARN only matches Terraform roots whose provider targets that account. A policy in another root counts for a role only when both roots' accounts are known statically (a literal `assume_role.role_arn` or `allowed_account_ids`) and match; otherwise it can make the result `UNRESOLVED`, never `GRANTED`, so a policy added in staging does not hide a missing one in production.
3. **By configuration.** Add `.diffseal.json` to the application repository:

```json
{
  "infra": { "repo": "../infra", "rootsUnder": "envs/prod" },
  "roles": ["orders-api-task"],
  "env": ["VARIABLES_SET_OUTSIDE_TERRAFORM"]
}
```

The application repository does not need any Terraform of its own.

Calls through helpers in the same repository are followed. A constructor such as `pubsub.NewSNSPublisher(client, topicARN)` contributes the SDK calls its methods make, with the resource taken from the call site. If the constructed value is passed elsewhere, the operations it might perform can only reach `UNRESOLVED`, never `NOT_GRANTED`.

## Policy checks

The checks cover S3, SQS, SNS, DynamoDB, KMS, RDS and Aurora, Lambda, security groups, Secrets Manager and IAM. The IAM checks include trust policies, GitHub OIDC `sub` conditions, admin-equivalent managed policies, `NotAction`, privilege escalation, and wildcards that span resources.

Each finding is `PASS`, `FAIL`, `WARN`, `UNKNOWN` or `INFO`. `UNKNOWN` is never counted as a pass. A `dynamic` block over a collection that is only known at apply time makes the checks it feeds `UNKNOWN`.

Values marked sensitive (`sensitive()`, `sensitive = true` variables, `after_sensitive` in a plan) are still checked, so wrapping an open CIDR in `sensitive()` does not hide it. They are never printed: reports show `(sensitive)`, and the digest used to detect a change is keyed per run. On an update, a problem that already existed before the change is marked pre-existing and does not fail the gate.

ISO 27001 certifies a management system, not a bucket, and it does not require customer managed keys or point-in-time recovery: your policy does. Thresholds are set in a policy file:

```json
{ "requireCustomerManagedKeys": true, "minBackupRetentionDays": 14, "blockOn": ["CRITICAL"] }
```

### Accepted exceptions

A finding that is intended, such as a port devices connect to from the internet, can be accepted in `.diffseal.json` at the repository root:

```json
{
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

An accepted finding stays in the report and no longer fails the gate. Every exception needs an expiry date; once it passes, the finding counts again and the gate says so. Exceptions are read from the base of a change, so a pull request cannot accept its own findings, and a change to `.diffseal.json` is itself a reason for review. `rule: "blast-radius"` accepts a destructive change.

## GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  diffseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: your-org/diffseal@v0.2
        with:
          mode: pr            # or: plan, app
          roots-under: infra/envs/prod
```

The Action runs bundled JavaScript (`dist/action.js`) on the runner and downloads nothing at run time. It writes the step summary before setting the exit code and updates a single PR comment. `strict: true` also fails the job on `REVIEW`; `advisory: true` never fails the job, even on `BLOCK`.

A pull request is compared with the commit it branched from (the merge base of `HEAD` and the pull request's base), whether the job checks out the merge commit or the head. Settings that judge the change come from that base: the `policy` file, exceptions, and in `app` mode the roles, env vars and infrastructure named in `.diffseal.json`. Changing any of them makes the gate `REVIEW`, and the new version applies once merged. The policy file must be inside the repository.

To check an application repository against an infrastructure repository, check the infrastructure repository out into a path with a token that can read it, and set `mode: app` and `infra-path`.

## Claude Code, Cursor and other MCP clients

```json
{
  "mcpServers": {
    "diffseal": { "command": "bun", "args": ["run", "/path/to/diffseal/src/mcp.ts"] }
  }
}
```

Tools:

- `diffseal_check_app`: after writing code that calls AWS, check that the role allows it.
- `diffseal_review_plan`
- `diffseal_replay_commit`

All three are read-only. HashiCorp's Terraform MCP server complements this one: it supplies registry documentation and provider schemas. Diffseal does not call it.

## Layout

| Path | What it does |
| :-- | :-- |
| `src/hcl` | HCL parser and static expression evaluator |
| `src/terraform` | Module loading and expansion, git snapshots, base/head comparison, replacement catalogue |
| `src/plan` | `terraform show -json` reader: unknown values, sensitive values, configuration references |
| `src/policy` | Policy rules and IAM analysis |
| `src/analysis` | Blast radius, cost, gate |
| `src/app` | Go, TypeScript and Python extraction of AWS SDK calls and env reads |
| `src/reconcile` | Infrastructure index (computes, roles, grants) and reconciliation |
| `src/replay`, `src/report` | Replay runner and Markdown reports |
| `src/cli.ts`, `src/mcp.ts`, `src/action.ts` | Entry points |

`docs/` holds design notes, research and the current status.

## License

[FSL-1.1-ALv2](LICENSE). Diffseal is free to use, including in your company's CI. Offering a competing commercial product or service is not allowed. Each release becomes Apache 2.0 two years after it is published.
