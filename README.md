# Diffseal

> **Beta status, v0.6.4-beta.** Diffseal reviews Terraform changes on AWS and writes audit change records. It is a beta validated on one production monorepo. Run the GitHub Action in advisory mode first, with `advisory: 'true'`, and report issues in the [GitHub issue tracker](https://github.com/diffseal/diffseal/issues).

Diffseal reviews Terraform changes on AWS and records the evidence of each change. It works from Terraform configuration and git history. It never asks for cloud credentials and never runs `terraform`.

It answers three questions about a change:

1. **What does it do to infrastructure?** Creates, updates, replacements and deletions, worked out from the configuration at both commits. A replacement names the argument that forced it.
2. **What can break?** Deleting or replacing something stateful, such as a database, a bucket or a Cognito user pool, blocks the gate. Diffseal flags an update that reboots a database or narrows an IAM policy for review.
3. **What evidence does an auditor get?** Each finding cites the ISO/IEC 27001:2022 Annex A control it relates to. A replay of history produces the population of changes an auditor samples from.

## Install the CLI

```bash
npm install -g diffseal@beta
```

You can also install with Bun, Yarn or pnpm:

```bash
bun install -g diffseal@beta
yarn global add diffseal@beta
pnpm add -g diffseal@beta
```

During the beta, install the `beta` tag as shown. The CLI needs Node.js 18 or later. The package includes the CLI and the MCP server.

For a one-off run without installing:

```bash
npx diffseal@beta verify ./pack --account your-org --period 2026-Q4
```

## Commands

```bash
# Review a plan (terraform show -json plan.tfplan > plan.json)
diffseal review --plan plan.json [--strict]

# Replay commits of a local clone, without credentials. Reports go to ./dry-runs.
diffseal replay --repo ../infra --commit 1a2b3c4
diffseal replay --repo ../infra --since 2026-09-01
```

Exit codes: `0` pass, `1` error, `2` the gate failed.

### What replay does, and what it cannot do

`replay` reads git objects only (`ls-tree`, `cat-file`, `diff`). It never checks out, writes to, or sends anything from the repository, and it refuses to write reports inside it. For each commit it:

- finds the Terraform roots whose module tree the commit touches, following symbolic links that stay inside the repository
- evaluates each root at both commits: local modules, variables, locals, `count`, `for_each`, `dynamic` blocks and policy documents, and again once per var-file found in or below the root
- compares the two, honouring `moved`, `removed` and `import` blocks, and what `null` means for each provider argument (absent, provider default, or kept from state)
- compares a root that moved to a new directory with its old directory, and reviews a deleted root directory instead of treating it as destroyed
- classifies replacements using a catalogue of the arguments that force a new resource, extracted from the AWS provider's source (`scripts/extract-forcenew.ts`, stamped with the provider commit)

Replay also writes a change record per commit (`records/<sha>.json`, schema `diffseal.change-record/v1`): what changed, the gate, the findings with the controls they relate to, and, with `--approvals`, who approved the change. `summary.csv` is the change population an auditor samples from, and `MANIFEST.sha256` covers every file written. The approvals file maps commit to approvals. You can export it read-only with the GitHub CLI; Diffseal itself makes no network calls.

Without state or provider calls, some values are only known after apply. Diffseal reports changes that depend on them as `likely` rather than `proven`. Data sources resolve to references, not values. Diffseal shows registry and git modules as module calls whose inputs changed, because their source is not available offline; a change to their `source` or `version`, or removing one, is reviewed.

## Policy checks

The checks cover S3, SQS, SNS, DynamoDB, KMS, RDS and Aurora, Lambda, security groups, Secrets Manager, IAM, CloudTrail, VPC flow log declarations and CloudWatch log retention. The IAM checks include trust policies, GitHub OIDC `sub` conditions, admin-equivalent managed policies, `NotAction`, privilege escalation, and wildcards that span resources.

Logging checks cover CloudTrail logging, multi-region coverage, log file validation and KMS keys, S3 access log targets, and an optional CloudWatch retention minimum. Change checks flag disabling or deleting CloudTrail, GuardDuty or AWS Config recorder status, and deleting Security Hub enrollment. These evaluate Terraform configuration only; organization-level coverage and live AWS state are outside their scope. Diffseal does not flag a VPC without flow logs, because it cannot always resolve instance relations. See the [rule list and defaults](docs/guide/configuration.md#logging-and-security-service-checks).

Each finding is `PASS`, `FAIL`, `WARN`, `UNKNOWN` or `INFO`. `UNKNOWN` is never counted as a pass. A `dynamic` block over a collection that is only known at apply time makes the checks it feeds `UNKNOWN`.

Diffseal still checks values marked sensitive (`sensitive()`, `sensitive = true` variables, `after_sensitive` in a plan), so wrapping an open CIDR in `sensitive()` does not hide it. It never prints them. Reports show `(sensitive)`, and the digest used to detect a change is keyed per run. On an update, Diffseal marks a problem that already existed before the change as pre-existing, and that problem does not fail the gate.

ISO 27001 certifies a management system, not a bucket, and it does not require customer managed keys or point-in-time recovery. Your policy does. Set thresholds in a policy file:

```json
{ "requireCustomerManagedKeys": true, "minBackupRetentionDays": 14, "minLogRetentionDays": 30, "blockOn": ["CRITICAL"] }
```

### Accepted exceptions

You can accept an intended finding, such as a port devices connect to from the internet, in `.diffseal.json` at the repository root:

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

An accepted finding stays in the report and no longer fails the gate. Every exception needs an expiry date; once it passes, the finding counts again and the gate says so. Diffseal reads exceptions from the base of a change, so a pull request cannot accept its own findings, and a change to `.diffseal.json` is itself a reason for review. `rule: "blast-radius"` accepts a destructive change.

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
      - uses: diffseal/diffseal@v0.6.4-beta
        with:
          mode: pr            # or: plan
          roots-under: infra/envs/prod
          advisory: 'true'    # remove once calibrated
```

The Action runs bundled JavaScript (`dist/action.js`) on the runner and downloads nothing at run time. It writes the step summary before setting the exit code and updates a single PR comment. `strict: true` also fails the job on `REVIEW`; `advisory: true` does not fail the job because of findings, even on `BLOCK`. A configuration or run error can still fail it.

Diffseal compares a pull request with the commit it branched from, the merge base of `HEAD` and the pull request's base, whether the job checks out the merge commit or the head. Settings that judge the change come from that base: the `policy` file and exceptions. Changing either makes the gate `REVIEW`, and the new version applies once merged. The policy file must be inside the repository.

## Claude Code, Cursor and other MCP clients

```json
{
  "mcpServers": {
    "diffseal": { "command": "diffseal-mcp" }
  }
}
```

Tools:

- `diffseal_review_plan`
- `diffseal_replay_commit`

Both are read-only. HashiCorp's Terraform MCP server supplies registry documentation and provider schemas. You can run it next to this one; Diffseal does not call it.

## Develop

Development uses Bun 1.4.4. Clone the repository, then run:

```bash
bun install
bun test
bun run build
bun run typecheck
bun run demo        # review a risky plan
```

The demo uses the example plan in the repository checkout.

## Layout

| Path | What it does |
| :-- | :-- |
| `src/hcl` | HCL parser and static expression evaluator |
| `src/terraform` | Module loading and expansion, git snapshots, base/head comparison, replacement catalogue |
| `src/plan` | `terraform show -json` reader: unknown values, sensitive values, configuration references |
| `src/policy` | Policy rules and IAM analysis |
| `src/analysis` | Blast radius, cost, gate |
| `src/replay`, `src/report` | Replay runner and Markdown reports |
| `src/cli.ts`, `src/mcp.ts`, `src/action.ts` | Entry points |

`docs/` holds design notes, research and the current status.

## License

[FSL-1.1-ALv2](LICENSE). Diffseal is free to use, including in your company's CI. The license forbids offering a competing commercial product or service. Each release becomes Apache 2.0 two years after it is published.
