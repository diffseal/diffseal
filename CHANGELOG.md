# Changelog

## 0.3.0-beta, 2026-10-26

### Added

- Parse application code with vendored tree-sitter grammars. Add Java SDK v2, Java v2 calls from Kotlin and AWS SDK for .NET alongside Go, TypeScript and Python.
- Generate AWS operation-to-IAM mappings from pinned AWS models and authorization data. Select common S3 optional and version permissions from request arguments.
- Index rendered Kubernetes workloads, IRSA service accounts, EKS Pod Identity associations, ConfigMap environment values, ko import images and a limited GitHub Actions ECS deployment pattern.
- Export unsigned audit periods with `terratrust evidence`, including change records, an auditor index, approvals coverage, CSV and a SHA-256 manifest.
- Fetch public registry and Git modules explicitly with `terratrust modules fetch`. Record exact versions, commits and hashes in a lock, then analyze verified cached contents offline.
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
