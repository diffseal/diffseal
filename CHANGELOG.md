# Changelog

## 0.6.4-beta, 2026-11-04

### Changed

- The Action is named "Diffseal Terraform review" in `action.yml`, the name it will have on the GitHub Marketplace, where "DiffSeal" is taken by another account. Its description now reads "Review Terraform changes on AWS without running terraform or holding cloud credentials. Flags data that would be lost." The repository and every `uses: diffseal/diffseal...` reference stay the same.

### Fixed

- An inline user, role or group policy whose owner is named through a reference (`aws_iam_user.b.name`) belongs to that principal only when the principal had the old owner name before the change and has the new one after. Before, a principal with either name was enough. So when user `a` was deleted, user `b` was renamed in place to `a`, and the policy moved from `aws_iam_user.a.name` to `aws_iam_user.b.name`, a narrowed policy kept its least-privilege findings as pre-existing and the change passed. The same happened to an owner that kept the old name of a user renamed in place (`replace(aws_iam_user.app.name, "new", "old")`, or a tag that holds the old name) while a new user took that name. Such a policy now belongs to a new principal and is reviewed.
- A `substr()` of `terraform.workspace` takes the rest of the name only when its length is `-1` or the length of the workspace itself, also through a local or parentheses. Before, any `length()` or a value not known offline counted as the rest, so `substr(terraform.workspace, 0, length(var.app)) == "billing"` built `billing` as a full workspace name: it was evaluated, nothing was reported as missing, and resources limited to the real workspace (`billing-prod`) were never seen. Such a length now builds no name. The root gets a note, and a `count` or `for_each` that depends on the value is reviewed, as for other names that cannot be built.
- A ForceNew attribute read from a map by a key not known statically (`configs[var.env].key_name`) whose value changes for some key keeps its possible replacement, naming those keys, on every resource type. Before, a type that is not stateful (an EC2 instance, a load balancer) had it turned into an `unknown` update, because the expression and what it reads are the same at both commits, so replacing the production instance passed. That downgrade is meant for an unknown value whose expression changed, not for a value that changed for a key.

## 0.6.3-beta, 2026-11-02

### Added

- The Action writes the full reports of each run to a directory and names it in a new `report-dir` output: `report.json` (the JSON that `diffseal replay` writes, or in `plan` mode the analysis result), `report.md` (the Markdown report with every reason, row and diagnostic, where the summary and comment stop at 8 reasons, 40 rows per table and 60,000 characters) and, when the run built a change record to upload, `change-record.json` with every resource. A new `artifact-name` output gives `diffseal-` and the short commit reviewed. The job summary is cut short on a large change and a large change record leaves out rows, so these files are the one place with everything. `docs/guide/action.md` shows the `actions/upload-artifact` step that keeps them as an artifact of the run.
- The trusted upload workflow keeps them as the `diffseal-<short sha>` artifact of the run, for 90 days unless its new `retention-days` input says otherwise. It does so only when a review ran, also when the review failed the step, and needs no new permission. A failed artifact upload warns and does not fail the job.

### Changed

- A root that derives its environment from `terraform.workspace` by removing a part (`trimprefix(terraform.workspace, "${var.app}-")`, `substr(terraform.workspace, length(local.application_name), -1) == "-production"`, `replace`, `trimsuffix`) is evaluated in full workspace names built from that part and the keys the configuration compares it with or looks it up in (`app-production`), also keys of a JSON or YAML file it decodes. A part taken by `split` or `regex` is joined with the prefixes the configuration removes or tests elsewhere and kept only when deriving it again gives the key. Before, the keys were evaluated as bare workspace names (`production`), which do not exist, so environment-gated resources had no instance on either side: a production database deleted in three environments was reviewed for unrelated IAM reasons and never named (modernisation-platform-environments `6f39cc9b9`); it now blocks. When no full name can be built, a note says so and the bare keys are not evaluated; a `count` or `for_each` that depends on such a part compared with keys is reviewed, naming the root.
- Deleting or replacing a resource whose block had `lifecycle { prevent_destroy = true }` at the base and has none at the head is reviewed and says so; a stateful type keeps its stateful rating. Before, the guard was read at the head only, where a removed block has none, so a protected Glue database removed with its block passed (Data-Platform `49acecf1f`).
- Deleting or replacing a Glue catalog database or table is reviewed: its table definitions, partitions and grants go with it, including tables crawlers created outside Terraform. The data in S3 stays, so they are not rated stateful and do not block.
- Replacing an EC2 instance is reviewed: its root volume and instance store are lost unless kept, and it gets a new instance ID and private IP. Before, production Prometheus and Grafana instances replaced by a `key_name` change passed (govwifi-terraform `f3289170e`). A possible replacement only through `root_block_device` or `ebs_block_device`, which the provider decides at plan time, is not reviewed and says what a replacement would lose.
- An engine version change on `aws_db_instance` or `aws_rds_cluster` is rated HIGH and reviewed: an engine cannot be downgraded, and the database restarts during the upgrade. Before, it was MEDIUM and passed unless `apply_immediately` was set.
- When the Action is told that a later step keeps the reports (the new `report-artifact` input, which the trusted upload workflow sets), a change record that leaves out resources to fit the upload limit says the full list is in the `change-record.json` of the `diffseal-<short sha>` artifact of this run, with the file's SHA-256, so a replaced artifact shows, and a link to the run. It still names the replay report too, which can be written again once the artifact has expired. Records written by `diffseal replay` and `diffseal evidence` point only to the replay report, as before.

### Fixed

- A value read from a known map by a key not known statically (`environment_configs[var.environment_name]`, a variable without a default) keeps each key's value. An attribute read through it changes only when that attribute's value changed for some key, and a possible replacement names those keys. Before, the whole map was the value's identity, so any edit anywhere in it made every attribute read through the lookup look changed and kept a possible replacement on every database, bucket and log group (iv-cbv-payroll, 53 unneeded REVIEWs in 75 commits). `lookup()` with an unknown key does the same, with its default.
- `yamldecode()` decodes one plain YAML document with the YAML 1.2 core schema, as Terraform does. Before, its result was always unknown, the same at every commit, so a launch template whose `user_data` and `for_each` read a changed YAML file printed no change (terraform-aws-sponsorship `3ad7d9034`); it now lists the launch template and autoscaling group the change creates. A document with several parts, custom tags or errors stays unknown, with the text as its identity.
- Two unknown values are no longer proven equal when what they come from changed. A `templatefile()` result with unknown parts carries the template's digest, so a changed template is a changed value, and a value that fails to evaluate carries the expression that failed. Before, task definitions that failed with the same error at both commits read as proven no-ops.

## 0.6.2-beta, 2026-11-02

### Added

- A `roots` mapping in `.diffseal.json` says how each root is deployed: per root directory or pattern (`ops/services/*`), the environments with their var-files, loaded in order as repeated `-var-file` options, and their workspace. Exactly those environments are evaluated. A changed var-file that the mapping covers and that was evaluated no longer raises a coverage REVIEW; one that sets a variable no mapped root declares still does. Diffseal reads the mapping from the base commit, so a pull request cannot change how it is reviewed. `docs/guide/configuration.md` has the format.
- Terragrunt configuration is read without running anything. A `terragrunt.hcl` with a local `terraform { source }` is replayed with the module it runs and its `inputs`: literal values and locals built from literals and pure functions, merged with a parent found by `find_in_parent_folders()` or a path, following `merge_strategy`. A file an input reads with `file()` or `read_terragrunt_config()` is tracked, so an edit to it replays the configuration. The inputs come in below `terraform.tfvars`, as `TF_VAR_` variables do. A changed input that needs `dependency` outputs, `get_env`, `run_cmd`, `read_terragrunt_config` or an exposed include, a changed `generate` block, hook or `remote_state`, a remote source, and an input the module does not declare stay a coverage REVIEW, and the line now names them. A parent file such as `root.hcl` counts as Terragrunt configuration when a `terragrunt.hcl` includes it.

### Changed

- A root whose configuration tells Terraform workspaces apart (`terraform.workspace == "prod"`, `contains([...], terraform.workspace)`, `lookup(var.accounts, terraform.workspace)`, also through a local, a module output or a module input) is evaluated once per workspace name found, besides `default`, up to 8. Before, every root was evaluated as `default` only, so a DynamoDB table renamed without `moved` and limited to production by workspace passed (beneficiary-fhir-data `1828a22ba`). The gate is the worst result, and every finding, root name, JSON root (`workspace`) and change record says which workspace it came from. A var-file named like such a workspace is evaluated in it. A root that reads `terraform.workspace` without a name Diffseal can find is still evaluated as `default`, and the report says so.
- The replay JSON names a root's var-files `varFiles` (a list, in load order) instead of `varFile`, and `baseVarFiles` instead of `baseVarFile`. Reports and change records list notes that do not change the gate: workspaces not found or capped, and mapping entries that were ignored.
- Deleting an API Gateway stage (REST or v2) or a load balancer listener is rated HIGH and reviewed: requests fail until it is created again. Before, it was LOW because no data is lost, and a production API Gateway stage deleted next to an unchanged deployment passed. Deleting a CloudFront distribution was already reviewed. Listener rules and replacements are rated as before.
- Two unknown values of a ForceNew argument that differ only in the expression behind them, with the same known text around the unknown parts and reading the same resource and data source instances, are an `unknown` update, not a possible replacement, unless the resource is stateful (a database, bucket, queue, log group and the other types rated for data loss): a changed index or literal inside the expression is not seen, so their possible replacement stays reviewed. A backend role moved into `assume_role` made every security group reading `vpc_id` from remote state "possibly replaced". A replacement is still reported when the value now reads a different resource, instance or data source, one this change creates, replaces or deletes, or a data source whose arguments change (a new AMI filter). Settings of `terraform_remote_state` that only say how to reach the state (`role_arn`, `assume_role`, `profile` and the like) do not count as a change of what it reads. Two earlier fixtures on security group rules expected a likely replacement for such an expression change (a splat attribute, a literal in a `for` body); they now expect an `unknown` update, which still shows the change is detected.

### Fixed

- A `.tf` link whose target has no `.tf` name (`r/table.tf -> ../shared/config`) counts as changed Terraform under the link's name. When no replayed root reads it (a root outside `--roots-under`, or a module no root calls), the change is reviewed and the line names the link. Before, such a change could pass.
- A `.tf` link that was read at the base and whose target is deleted, missing or outside the repository at the head no longer reads as an empty file. Terraform stops with "Failed to read file" there, so the root is reviewed as not evaluable, the line names the link, nothing declared in it, or in a module it calls, is shown as a deletion, and no other change of that root is proven. This holds for a root moved in the same change too. A `.tf` file that a `.tofu` file of the same name shadows is not read, so its link does not count. Before, those resources showed as proven deletions and could block.
- An inline role, user or group policy whose owner is written as a name (`role = "app"`, or its ARN) belongs to a new principal when a role, user or group of that name is created, replaced or deleted in the same change, or one whose name is not known statically. A narrowed document then keeps its least-privilege findings as new, even when the issues it still has read the same as before. A principal whose name is marked sensitive is matched by the name it holds.
- An inline policy's owner is identified the way IAM identifies it. Names are compared without case, so `role = "App"` names a role `app` replaced in the same change, and an owner that only changes case keeps its principal. A user or group renamed in place keeps its inline policy when the policy names it through a reference (`aws_iam_user.app.name` or `.id`); before, a narrowed policy then read as new and the change was reviewed. An owner named through a reference to a principal this change keeps is that principal, and is no longer matched by name against a new principal whose name is not known statically. Principals are still not told apart by AWS account.
- In a plugin-framework resource, a value going to `""` on an Optional and Computed argument is a proven change, because the framework tells `""` from `null`. `null` becoming `""` there is still a possible change.
- A git submodule bump that a root calls modules from is reviewed: the line names the submodule, the old and new commit, the module calls and the roots. Diffseal does not read a submodule's content. Before, a module call into a submodule read nothing, and a bump with no `.tf` edit, or next to unrelated edits, passed.
- A `for_each` built through many nested operations on unknown values no longer runs out of memory. The identity of an unknown value embeds every operand's identity, escaped again at each level; one longer than 256 characters is now kept as a digest.
- A removed resource with `skip_destroy = true` is reported as removed from state, not deleted (a deleted root holding one is still reviewed), for the 20 resource types whose provider schema has `skip_destroy` (log groups, Lambda layer versions, ECS task definitions and others). The provider leaves it in AWS. A planned delete of one is rated LOW without data loss. Before, removing such a log group blocked as losing the logs.
- A module `for_each` over a map with literal keys keeps its keys when a resource with the same `for_each` is evaluated first and the map reads another module. Referring to one module used to expand every module call of that module, which read the map while it was still being evaluated and took that for a reference cycle; the instances became `[*]` and `moved` blocks into `module.x["key"]` matched nothing, so the old resources read as proven deletions. Each module call is now expanded on its own, when first used. Some `count` expressions that were wrongly unknown for the same reason are now known.
- A partly unknown `jsonencode()` result inside a string template, as in `container_definitions = "[${local.app}]"`, is compared by its known parts. Before, it could not be interpolated, read as the same unknown at both commits, and every edit to the container definitions showed as no change.
- A rename hint pairs a deleted instance with the created instance of the same key, and offers each created resource once. Before, `module.eft_bucket["bcda"]` could "look like a rename to" `module.buckets["ab2d"]`.
- A change record whose JSON would be over 900 KiB leaves out resources until it fits, so a large monorepo no longer loses its record to the evidence service's 1 MiB upload limit. The lowest risk go first (a FAIL counts as a HIGH risk), and among those the unchanged ones and those whose action is unknown, each with its risks and findings. A resource that a gate reason names, or that has a new FAIL or a HIGH or CRITICAL risk not accepted, is always kept, as are the gate, its reasons and items, and the roots. A note says how many entries were left out and that the full list is in the replay report. The evidence pack keeps every entry.

## 0.6.1-beta, 2026-10-30

Accuracy fixes from a measurement on 675 commits of 9 public Terraform repositories; `docs/STATUS.md` has the numbers.

### Changed

- A change to the `source` or `version` of a registry or git module that is not in the offline cache, or the removal of such a module call, raises the gate to REVIEW. The line names the module address, the old and new source or version, and the roots that use it. A change to an external module's `count` or `for_each`, and any change to a call of a local module that cannot be read, is reviewed too.
- Before comparing an argument, replay applies what `null` means to the provider: absent and `null` are the same, `null` takes the provider's default, a value going to `null` on an Optional and Computed argument keeps the state value, and `null` becoming a value there is a possible change (`likely`), not a proven one. In SDKv2 resources `""` is `null` for a string without a default. The facts come from the provider source at the catalogue's commit; `aws-replace.json` now records Optional and Computed arguments, literal defaults and which resources use the plugin framework.
- A Terraform root directory that a change moves is compared with its old directory, found by a matching literal state location (backend or cloud block) or by at least half of its files kept or renamed. The move is reviewed when the state location is not fixed in the configuration. A root directory that a change deletes lists its resources as `likely` deletions and says they are destroyed only if someone runs `terraform destroy` against its state; it no longer blocks as if they were destroyed. A root whose state another root takes over in the change keeps its deletions proven, and a root whose bucket and key change is reviewed.
- Var-files in a root directory or in directories below it that hold no Terraform are evaluated with that root, once per var-file present at both commits, in addition to the evaluation without var-files, so a proven replacement through a var-file blocks. A changed var-file still raises a coverage REVIEW that says it was evaluated only in part, because which roots load it, and with which other var-files, is set outside the configuration. A tfvars file no root was evaluated with, a var-file value its root does not declare, and a changed `terragrunt.hcl` keep the coverage REVIEW, now naming the file and the variables it changes. Terragrunt is still not read.
- An inline role, user or group policy, or a managed policy, that grants nothing its previous version did not (same owner, same policy language version, no Deny removed) does not introduce `iam.least-privilege` issues, even when its statement ids change.
- A deleted security group, role or other identity resource reads "whatever still refers to it fails" instead of describing a replacement.

### Fixed

- Symbolic links in the repository are followed at the replayed commit, through linked files and directories and one path component at a time, instead of being parsed as their link text. A change to a link's target, or to any link on the way to it, replays every root that reads through it. A link that leaves the repository or points at nothing is not followed and is reported.
- Reports, JSON output and change records name a root replayed with a var-file, a moved root and a deleted root as such.

## 0.6.0-beta, 2026-10-30

### Removed

- The application code check: the `check-app` command, the Action's `mode: app` and its `infra-path`, `role` and `entry` inputs, and the `diffseal_check_app` MCP tool. Diffseal reviews Terraform only. A workflow that still sets `mode: app` fails with the line "mode: app was removed in v0.6.0-beta; Diffseal reviews Terraform only", and `diffseal check-app` fails with the same message for the command. On public Spring Boot projects the check found 30% of AWS call sites and reached no verdict, and it passed two projects that write to DynamoDB, so it was removed rather than kept as a partial check. `docs/STATUS.md` has the numbers.
- `pr` mode and `replay` no longer scan application code added by a change, so a missing permission in application code no longer raises the gate to REVIEW.
- The parser grammars for Go, TypeScript, Python, Java, Kotlin and C#. The Action bundle falls from 3.1 MB to 1.0 MB.
- The `infra`, `roles` and `env` link settings in `.diffseal.json`. They are ignored if present.
- The `diffseal demo` app example. The demo reviews the example plan only.

### Changed

- Change records keep the required `access` field of `diffseal.change-record/v1`, always as an empty list, so the evidence service accepts records from this version and older ones alike.

## 0.5.5-beta, 2026-10-29

### Added

- Encryption checks in transit and at rest, on the Terraform configuration each change touches: load balancer listeners (HTTPS redirect and TLS policy), CloudFront (viewer protocol and minimum TLS), ElastiCache (transit and at rest, including Memcached clusters), OpenSearch and Elasticsearch domains (node-to-node, HTTPS and at rest), EBS volumes and EBS default encryption, and EFS. They cite SOC 2 CC6.7 or CC6.1 and ISO 27001 A.8.24, and warn at most.
- One decision rule for every encryption check: a result passes only when the configuration explicitly turns encryption on, and warns only when it explicitly turns it off with nothing in the configuration enforcing it. Inferred defaults, computed values, values passing through null or unknown, and attributes under `ignore_changes` give an unknown result. Known limits are listed in `docs/research/known-gaps.md`.

### Changed

- DynamoDB `server_side_encryption { enabled = false }` is reported as an AWS-owned key, not as encryption switched off.
- Plainer README and guides. Advisory mode is described as not failing the job because of findings; configuration or run errors can still fail it.

### Fixed

- `check-app` reports named the infrastructure repository by its absolute local path, in the footer and in the note about a missing role. They now show the repository's folder name, so a pasted report no longer shows the folder layout of the machine that ran it.

## 0.5.4-beta, 2026-10-29

### Added

- Logging and security-service checks, evaluated on the Terraform configuration each change touches: CloudTrail logging, multi-region and log file validation and KMS key; VPC flow logs; CloudWatch log retention (with the `DELIVERY` class's fixed two days, and an optional `minLogRetentionDays` policy); S3 access logging. They cite SOC 2 CC7.2.
- A change that switches off or deletes CloudTrail, GuardDuty, AWS Config or Security Hub is flagged for review. It never blocks by default.

### Changed

- The free evidence pack's findings heading names both frameworks, ISO 27001 and SOC 2.

## 0.5.3-beta, 2026-10-29

### Added

- The CLI is published to npm as `diffseal`. Install it with `npm install -g diffseal@beta` (or Bun, Yarn or pnpm), or run `npx diffseal@beta verify ...` once. It needs Node.js 18 or later.
- `diffseal --version`.

### Changed

- CI and releases build with Bun 1.4.4, and the build refuses any other Bun version, so the committed `dist/` always matches the release build.

## 0.5.2-beta, 2026-10-29

### Changed

- Every configuration check now names its SOC 2 criterion (2022 Trust Services Criteria) next to its ISO 27001 control, in the pull request comment, the job summary and the change record. The mapping and its sources are in `docs/research/compliance-crosswalk.md`.
- The SQS dead-letter queue check no longer cites ISO 27001 A.8.14. Keeping failed messages is neither a backup nor redundant processing.

## 0.5.1-beta, 2026-10-29

### Changed

- A replaced or deleted stateful resource now reads "applying it would lose the database" instead of "loses the database": the review describes a predicted effect, not something that happened.

## 0.5.0-beta, 2026-10-28

### Changed

- TerraTrust is now Diffseal. The repository is `diffseal/diffseal`, the CLI is `diffseal` and `diffseal-mcp`, the service is `api.diffseal.com` and the public key list is `https://diffseal.com/.well-known/diffseal-keys.json`.
- Every format id starts with `diffseal.` (for example `diffseal.pack/v2` and `diffseal.change-record/v1`), the config file is `.diffseal.json`, the module lock is `diffseal.modules.lock.json`, environment variables start with `DIFFSEAL_` and the MCP tools start with `diffseal_`. Rename these files and variables when you upgrade. `.terratrust.json` and `terratrust.modules.lock.json` are still read when the new files are missing, so replays of older commits keep their policy, exceptions and modules, and a PR comment written by TerraTrust is updated in place. Packs signed by TerraTrust are not read by this version.
- `diffseal verify` trusts the Diffseal signing key `d6ceaf99517d3d38`. The TerraTrust key `ac566f5ee309c7e6` is no longer bundled.

## 0.4.1-beta, 2026-10-28

### Fixed

- A rejected upload shows the service's reason and the failing field, not only the status code. Only plain characters are printed, so a response cannot inject a workflow command.
- When the service stores a record as stale, because the pull request or its base branch changed after the run started, the Action says so and explains that a new push refreshes the check. It shows no exception link for that record.

## 0.4.0-beta, 2026-10-28

### Added

- Add structured `gate.items` for risks, controls, access, exceptions, coverage and policy changes. Keep each item aligned with its reason text.
- Upload scrubbed Action change records with opt-in GitHub OIDC authentication. Retry network and server failures once, keep failures advisory and expose `upload-id`.
- Link blocked pull request comments to exception requests on the upload host.
- Add a trusted reusable upload workflow. Read `replay` settings from the base branch and run the release Action in advisory mode.
- Verify signed and unsigned evidence packs offline with `diffseal verify`. Check file coverage, hashes, Ed25519 signatures, key validity and optional account and period scope. Bundle Diffseal's public key list with the first pack signing key, `ac566f5ee309c7e6`.
- Document upload permissions, required check source settings, fork limits and offline verification.

## 0.3.1-beta, 2026-10-27

### Changed

- The report footer is one short line: the version, the two commits compared and a link to the FAQ. A change whose action is likely rather than proven says so in its own row, as `update (likely)` or `update (unknown)`, also when one row stands for several roots. The note about ISO/IEC 27001 control IDs moved to the FAQ.

## 0.3.0-beta, 2026-10-26

### Added

- Parse application code with vendored tree-sitter grammars. Add Java SDK v2, Java v2 calls from Kotlin and AWS SDK for .NET alongside Go, TypeScript and Python.
- Generate AWS operation-to-IAM mappings from pinned AWS models and authorization data. Select common S3 optional and version permissions from request arguments.
- Index rendered Kubernetes workloads, IRSA service accounts, EKS Pod Identity associations, ConfigMap environment values, ko import images and a limited GitHub Actions ECS deployment pattern.
- Export unsigned audit periods with `diffseal evidence`, including change records, an auditor index, approvals coverage, CSV and a SHA-256 manifest.
- Fetch public registry and Git modules explicitly with `diffseal modules fetch`. Record exact versions, commits and hashes in a lock, then analyze verified cached contents offline.
- Add repository CI, a tag-triggered release workflow, issue templates, contribution guidance and a security reporting policy.
- Add a reproducible advisory pilot package and end-to-end tests for the three synthetic demo changes.

### Changed

- Redesign the report and PR comment. The heading states the gate, and a GitHub alert box lists what blocks or needs review. The PR comment no longer shows the merge commit GitHub creates. Granted and unresolved code calls fold into a collapsed table, and the footer is one line.
- Reuse bounded extraction summaries by Git blob identity and extractor version. Release parse trees after extracting facts.
- Load only the grammars used by a scan. Store offline parser assets as gzip files and decompress selected assets locally. Terraform-only analysis loads no parser runtime or grammar.
- Make scan, check-app, replay and evidence APIs asynchronous so grammar initialization happens when needed. CLI, Action and MCP callers await these APIs.
- Add the FSL-1.1-ALv2 licence text, contribution terms and release instructions. The engine remains source-available under that licence.

### Fixed

- Track resource provider aliases and local module provider mappings when matching AWS accounts and roles.
- Load `.tf.json` and select roots when JSON configuration changes.
- Retain `prevent_destroy` when a local module has zero count or an empty for_each.
- Resolve `managed_policy_arns` references to the exact customer-policy instance.
- Preserve request-specific permission choices through Go helpers and the new language adapters.
- Keep module cache visibility changes uncertain, rather than claiming resources were created or destroyed. Review a changed module lock when its contents are unavailable.

### Known limits

- Static analysis cannot replace a Terraform plan or query provider and state values. Such values can remain unknown.
- Thirty-five generated AWS operations remain unresolved with recorded reasons. Optional permissions, request-specific KMS overrides, SQL-based operations and advanced SDK wrappers remain incomplete.
- Native Kotlin SDK DSLs, compiler-wide type analysis and several .NET convenience overloads are unsupported.
- Deployment mapping needs statically readable files. It does not run Helm, Kustomize, build scripts or deployment pipelines.
- Module fetching supports public HTTPS Git, registry discovery and tar/gzip downloads. Private credentials, ZIP, SSH, Git submodules and symlinks need more work. Historic pins must be populated before offline history replay.
- Evidence packs are unsigned. Supplied approvals are assertions from an export, not independently verified GitHub approvals. They do not certify compliance.
- Production replay calibration is not a precision study. Keep the pilot advisory while findings are reviewed.

## 0.2.0-beta

### Added

- Expand local Terraform modules, count, for_each and dynamic blocks for static change review.
- Honor moved, removed and import declarations, and use an AWS replacement catalogue and provider schema snapshot.
- Follow application AWS calls to compute environments, IAM roles, policies and dependent KMS or DynamoDB index permissions.
- Record changes as JSON audit evidence with an optional approvals export, a change-population CSV and SHA-256 manifests.
- Support accepted findings with an owner and expiry, and advisory Action runs for the pilot.

### Changed

- Report fixed charges and pricing-dimension changes separately from usage-based resources.
- Explain policy grant changes, application environment changes and resource blast radius in review reports.
- Replace the earlier raw-resource generation path with read-only review, replay and application checks through the CLI, Action and MCP server.

### Fixed

- Read policy and accepted exceptions from the base snapshot so a change cannot approve itself.
- Preserve sensitive values for policy evaluation and scrub them at report boundaries.
- Correct lifecycle guards, unknown counts and dynamic blocks, indexed policy references, override merges, chained moves and replacement propagation.
- Compare Terraform expression values with the local Terraform console and keep the discovered value fixes as fixtures.
- Add regression coverage for the review findings recorded in docs/STATUS.md and reject stale Action builds.

### Known limits

- Registry and Git module resources are opaque without their source.
- Unknown provider and state values, shallow application data flow and incomplete replacement or authorization models can require manual review.
- The beta is intended for advisory use. It is not a substitute for a Terraform plan or an auditor's judgement.
