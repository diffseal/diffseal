# Diffseal engine

The CLI, the GitHub Action and the npm package `diffseal`: Terraform review without a plan, change records and signed evidence packs. The evidence service is `diffseal/cloud`, the site is `diffseal/website`.

## Rules for every Diffseal repository

- The founder is the only person on the project; use they/them.
- Write plainly: short sentences, no em or en dashes, no filler. This holds for code comments, docs, commit messages and product text.
- Commit as `Viktor Voltaire <19266705+viktorvoltaire@users.noreply.github.com>`. Never amend; make new commits.
- Never commit secrets, `node_modules`, `dry-runs/`, or absolute local paths. Never copy from, or name, the founder's employer or its repositories.
- Confirm with the founder before anything outward or hard to undo: making a repository public, changing settings, creating keys, sending messages.
- Merges are squash only.
- Review before merging: Codex, Grok and a fresh Claude reviewer on the same diff (the `local-pr-review` skill, or T3 Code child tasks). Fix P1s, and P2s on security or evidence. Small or mechanical changes may skip review; say so.

## Build and test

- `bun test`, `bun run typecheck`, `bun run build`. `dist/` is committed: rebuild it after any change in `src/` and commit it with the change.
- A change to how gates are decided needs a re-measurement on the three commit sets (2,175 real commits) with no new false BLOCK. `docs/STATUS.md` has the method and the latest numbers.

## Releases

- `main` can be pushed by an agent. Release tags are pushed by the founder only.
- Release commit: bump `package.json`; replace the version in `README.md`, `.github/workflows/upload.yml`, `docs/guide/faq.md`, `docs/guide/action.md`, `src/replay/render.ts` (VERSION) and `src/pilot.test.ts`; set the `docs/STATUS.md` title and add a release line; rename CHANGELOG `## Unreleased` to `## X, date`; add `docs/releases/vX.md`; build, test, commit `Release vX: ...`, push `main`.
- Then give the founder: `git tag -a vX -F docs/releases/vX.md <sha>` and `git push origin vX`. The release workflow publishes to npm under `beta`; moving `latest` needs the founder (`npm dist-tag add diffseal@X latest`).
- After a release, bump the site (`diffseal/website`) and the service's `UPLOAD_WORKFLOW_REF` (`diffseal/cloud`).

## Where things are

- `docs/STATUS.md`: what is built, measured and open. `docs/research/known-gaps.md`: known limits. `CHANGELOG.md`.
- `docs/guide/`: the Action, configuration, FAQ and verify guides that the site links to.
