# Status of v0.7.0-beta

Diffseal reviews Terraform changes on AWS from source, without a plan or cloud credentials, and writes change records an auditor can sample. This file says what is built, how it is measured and what is still open. `CHANGELOG.md` and `docs/releases/` have every change.

## Built

| Area | State |
| :-- | :-- |
| HCL parsing | A parser for the native syntax and `.tf.json`, with no Terraform binary. |
| Static evaluation | Variables, locals, about 70 functions, local and registry modules, `count`, `for_each`, `dynamic`, workspaces, var-files and Terragrunt inputs. Unknown values keep their references. |
| Replay | Base and head are evaluated per affected root and compared, honouring `moved`, `removed` and `import`. Replacements come from a catalogue extracted from the AWS provider's source. An argument that only sometimes replaces gives a likely replacement, which is reviewed. |
| Plan review | Reads plan JSON that your own Terraform step produces, with `after_unknown`, sensitive masks and `replace_paths`. |
| Configuration checks | Encryption at rest and in transit, backups and deletion protection, public access and network ingress, IAM, keys and secrets, logging and security services. Each cites ISO 27001 and SOC 2. An issue already present before a change is marked pre-existing. |
| Blast radius | Severity depends on statefulness, lifecycle guards and risky in-place updates. IAM policy updates list the grants they add, and the grants they revoke when the new policy no longer allows them. |
| Exceptions | Accepted findings in `.diffseal.json` with owner and expiry, read from the base of a change, so a pull request cannot accept its own findings. |
| Evidence | A change record per replayed commit that names the settings changed in each resource, a change population CSV and a SHA-256 manifest. The evidence service signs quarterly packs with Ed25519, and `diffseal verify` checks them offline. |
| Entry points | `review`, `replay`, `evidence`, `verify` and `modules fetch` in the CLI, two read-only MCP tools, and a GitHub Action. |

## How it is measured

Every change to how gates are decided is replayed on 2,175 real commits: the last 75 commits that touch Terraform in each of 29 public repositories, in three sets. Two of the sets were never used to tune the engine before they were measured. A release ships only when no BLOCK on those commits is judged false.

On v0.7.0-beta the three sets give PASS / REVIEW / BLOCK of 479 / 184 / 12, 543 / 182 / 25 and 567 / 159 / 24. Diffseal was also run on one private production monorepo; its details are not published.

## Open

- **Precision.** BLOCK is checked by hand on the measured commits; there is no labelled precision study yet. Keep the Action advisory while you judge its findings.
- **Replacement catalogue.** It covers the AWS provider services extracted so far, at one provider version. Other versions and other providers are not covered.
- **Known limits.** `docs/research/known-gaps.md` lists cases where a result can be wrong.

## Releases

v0.7.0-beta, 2026-11-04: a change record names the settings that changed in each updated or replaced resource, with old and new values for a short list of operational settings. Gates on the measured commits are unchanged.

v0.6.5-beta, 2026-11-04: an IAM policy update no longer says it revokes a grant that the new policy still allows. The trusted upload workflow reads its settings for a push from the branch head before the push. The verify guide checks a pack without Node.js. Gates on the measured commits are unchanged.

Earlier releases: see `CHANGELOG.md`.
