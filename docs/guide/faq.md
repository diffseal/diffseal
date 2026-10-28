# Frequently asked questions

## Does Diffseal need AWS credentials?

No. Diffseal works entirely from local files, git history, and saved plan JSON files. It never calls AWS APIs, never reads `~/.aws`, and makes no network requests during analysis. You can run `review`, `replay`, and `check-app` offline or in an unprivileged CI job that has no cloud credentials.

## Does Diffseal run `terraform`?

No. Diffseal never executes `terraform`, `tofu`, or `terragrunt`, and it never downloads providers or modules.

- In `replay`, `check-app`, and the GitHub Action `pr` and `app` modes, Diffseal parses `.tf` and `.tfvars` files directly with its own HCL parser and evaluates variables, locals, local module calls, `count`, `for_each`, `dynamic` blocks, and `aws_iam_policy_document` data sources in memory.
- To coerce boolean and numeric attribute types per resource type up to depth 3 and to classify which attribute changes force resource replacement without running a provider binary, Diffseal uses two embedded snapshots extracted from `hashicorp/aws` `v6.70.0`: `src/terraform/aws-schema.json`, covering 1,742 resource types, and `src/terraform/aws-replace.json`, covering 1,728 resource types.
- In `review --plan` and the GitHub Action `plan` mode, you run `terraform show -json <planfile> > tfplan.json` in your own step and pass the resulting JSON file to Diffseal.

## What is the difference between `proven` and `likely`?

Every resource change and reconciled application link carries a `confidence` field that is `proven`, `likely`, or `unknown`.

### In plan review with `review --plan`

When Diffseal reads `terraform show -json` output, Terraform has already refreshed state, queried providers, and computed the exact action and replacement paths for each resource. All changes from a plan JSON file have `confidence: "proven"`.

### In static replay with `replay` and `mode: pr`

Static replay compares two git commits without Terraform state or live provider calls.

A change is `proven` when:

- A resource block is added, deleted, moved, imported, or forgotten with statically known instance keys.
- A resource is updated or replaced because an attribute whose value is known at both the base and head commits changed. For replacements, at least one changed `ForceNew` attribute or `ForceNew` field inside a nested block must differ in a part that is statically known on both sides.

A change is `likely` when the action depends on a value only known at apply time or on provider logic at plan time:

- A `ForceNew` attribute changed, but one or both sides contain an unknown value such as a reference to another resource's `.arn` or `.id`, so the two sides might evaluate to the same value at apply time.
- A changed attribute is in the conditional replacement list `CONDITIONAL_REPLACE`, where the AWS provider decides at plan time whether to update in place or replace.
- A resource reads a computed attribute of another resource that is being replaced, or references a changed resource through `lifecycle { replace_triggered_by = [...] }` where the referenced attribute is computed.
- A resource is deleted, moved, or updated while its `count` or `for_each` was unknown at the base commit, meaning it may have had zero instances in state.
- A resource's type is not in the replacement catalogue, so Diffseal reports an in-place update with `confidence: "likely"`.

When blast-radius analysis evaluates a `likely` replacement, it scales the severity down from a hard `CRITICAL` block so uncertain static changes trigger human `REVIEW` rather than blocking the gate outright.

### In application reconciliation with `check-app`

In `check-app`, a link is `proven` when the resource expression in the SDK call is traced directly to a literal, a string pattern, or an environment variable read. When checking a diff with `replay` or `check-app --base`, if an SDK call has an unresolved resource expression and the same diff adds a read of a single environment variable whose suffix matches that AWS service, such as `PAYMENT_TABLE_NAME` for a DynamoDB call, Diffseal pairs them and marks the link `confidence: "likely"`.

## Which standard do the control IDs refer to?

Control IDs such as `A.8.32` refer to ISO/IEC 27001:2022 Annex A. The change record and `--json` output also list the matching NIS2 and DORA references for each check. A control ID says which control a check gives evidence for. It does not say the standard requires that check. Your policy file decides which checks block, which need review and which are only recorded.

## How are sensitive values handled?

Diffseal checks sensitive values without ever printing them.

1. **Detection.** Values come into the engine marked sensitive from four sources: the HCL `sensitive` function, `variable` blocks declared with `sensitive = true`, module `output` blocks declared with `sensitive = true`, and the `before_sensitive`, `after_sensitive`, and `sensitive_values` masks in `terraform show -json` plan files. Expressions, templates, and functions derived from a sensitive value also stay sensitive.
2. **Per-run keyed digests.** Each sensitive value is wrapped in a `Redacted` object defined in `src/core/model.ts` and `src/hcl/eval.ts`. At process startup, Diffseal generates a 32-byte random key with `randomBytes(32)` and computes a 16-hex-character HMAC-SHA256 digest of the sensitive value. This allows Diffseal to tell whether a sensitive attribute changed between the base and head commits within a run, while ensuring that nothing printed or logged can be reversed or matched against guesses across runs.
3. **Rule evaluation.** Policy rules and IAM reconciliation call `reveal()` internally to inspect the underlying value inside `Redacted`. Wrapping an open CIDR `0.0.0.0/0`, a wildcard IAM action `*`, or `force_destroy = true` inside `sensitive()` does not hide it from policy or blast-radius checks.
4. **Output scrubbing.** `Redacted.toString()` and `Redacted.toJSON()` return `"(sensitive)"`. In addition, before any result leaves `analyze()` or `reconcile()`, `scrubDeep()` collects every string and number leaf of four characters or longer, excluding IAM grammar keywords such as `Allow`, `Deny`, `true`, `false`, and `2012-10-17`, from inside every sensitive value, including JSON strings and known substrings of partially unknown sensitive templates. It replaces every occurrence of those leaves with `(sensitive)` across all free-text fields: `detail`, `remediation`, `reason`, `reasons`, `note`, `resource`, `access`, and `code`, longest match first. Structural enum fields such as `gate.result` and `status` are never scrubbed, so a secret that happens to spell `block` or `pass` cannot alter a gate verdict.

## What are the known limits?

Diffseal is a `v0.5.0-beta` release. Current limitations are tracked in [`docs/STATUS.md`](../STATUS.md):

- **External modules and remote state.** Registry and git modules are not downloaded; they are evaluated as module calls whose inputs changed, with `confidence: "unknown"`. Data sources resolve to symbolic references rather than live AWS values.
- **Inputs outside the root.** `terragrunt.hcl` files and `.tfvars` files that are not auto-loaded as `terraform.tfvars` or `*.auto.tfvars` are not evaluated during static replay. When a commit modifies them, Diffseal sets the gate to `review` and notes which files changed.
- **HCL JSON configuration.** `.tf.json` files are not loaded by the static evaluator; if a commit modifies a `.tf.json` file, the gate becomes `review`.
- **Module `count` and `prevent_destroy`.** A local module whose `count` drops to zero does not propagate `prevent_destroy` from its child resources.
- **Cross-root scoping.** When `--roots-under` is set, policies in roots outside that prefix are not indexed, which can produce a false `NOT GRANTED` if a role's policy lives in a separate root outside `--roots-under`.
- **Provider aliases in multi-account roots.** The `provider` meta-argument is not tracked per resource, so in a root with provider aliases for multiple AWS accounts, a policy that attaches to a role by name rather than by resource reference is treated as account-uncertain and marked `UNRESOLVED`.
- **Application code languages and patterns.** Application extraction supports Go with AWS SDK v1 and v2, TypeScript with AWS SDK v3, `lib-dynamodb`, and v2, and Python with `boto3`, using pattern and scope analysis rather than full compiler type-checking. Java, Kotlin, and .NET are not supported yet.

See [`docs/STATUS.md`](../STATUS.md) for the full list of open items and validation history.
