# GitHub Action reference

The Diffseal GitHub Action runs bundled JavaScript on the `node24` runtime through `dist/action.js` and downloads nothing at run time. It evaluates the change, writes a Markdown report to `$GITHUB_STEP_SUMMARY`, sets the `gate` output, optionally posts or updates a single pull request comment, and exits according to the gate verdict.

## Install the CLI

To run Diffseal locally:

```sh
npm install -g diffseal@beta
```

You can also install with Bun, Yarn or pnpm:

```sh
bun install -g diffseal@beta
yarn global add diffseal@beta
pnpm add -g diffseal@beta
```

The CLI needs Node.js 18 or later. For a one-off run without installing:

```sh
npx diffseal@beta verify ./pack --account your-org --period 2026-Q4
```

## Modes

Set `mode` to select what the Action checks:

- `pr`: Static replay of a pull request or merge group commit range. Evaluates affected Terraform roots at the base and head commits.
- `plan`: Reviews the JSON output of `terraform show -json <planfile>` at the path given by `plan-json`.

`mode: app`, the check of application code against IAM roles, has been removed. A workflow that still sets it fails with exit code `1` and the single line `mode: app was removed in v0.6.0-beta; Diffseal reviews Terraform only`. Remove the step, or switch it to `mode: pr` in the repository that holds the Terraform. The `infra-path`, `role` and `entry` inputs went with it.

## Inputs

| Input | Default | Used in modes | Description |
| :-- | :-- | :-- | :-- |
| `upload` | `'false'` | `pr` | Upload the scrubbed change record for a `pull_request` or `push` event. Requires GitHub OIDC and a trusted reusable workflow. |
| `upload-url` | `https://api.diffseal.com` | `pr` | Service URL. Requires HTTPS. Local tests may use HTTP on localhost or 127.0.0.1. |
| `mode` | `'pr'` | all | Check mode: `pr` or `plan`. Any other value fails with an error. |
| `plan-json` | `'tfplan.json'` | `plan` | Path to the JSON file produced by `terraform show -json <planfile>`. |
| `base` | `''` | `pr`, `plan` | Base git revision to compare against. When omitted on a `pull_request` or `merge_group` event, Diffseal resolves the merge base between the event base SHA and `HEAD`. Requires `fetch-depth: 0` on checkout. Used in `plan` mode only when `policy` is set. |
| `roots-under` | `''` | `pr` | Limit evaluation to Terraform roots under this relative directory path, such as `infra/envs/prod`. |
| `policy` | `''` | all | Path to a policy JSON file inside the repository. Read from the base commit when a base is available so a pull request cannot weaken the policy that judges it. |
| `strict` | `'false'` | all | Set to `'true'` to fail the step with exit code `2` when the gate is `review` as well as when it is `block`. |
| `advisory` | `'false'` | all | Set to `'true'` to always exit with code `0`, even when the gate is `block`. The Action still writes the step summary, pull request comment, and `gate` output. |
| `comment` | `'true'` | all | Set to `'true'` to create or update a pull request comment when running on a `pull_request` event with a valid `github-token`. |
| `comment-author` | `'github-actions[bot]'` | all | GitHub login expected on an existing Diffseal comment. Diffseal updates in place only a comment authored by this login that contains `<!-- diffseal-report -->`. |
| `github-token` | `'${{ github.token }}'` | all | GitHub token used to list, create, or update the pull request comment. |
| `report-artifact` | `'false'` | `pr` | Set to `'true'` when a later step uploads `report-dir` as the artifact named by `artifact-name`. A change record that leaves out resources then says the full list is in that artifact. See [Keep the full report](#keep-the-full-report). |

## Outputs

| Output | Values | Description |
| :-- | :-- | :-- |
| `upload-id` | run id | Set only when the service accepts an upload. |
| `gate` | `pass`, `review`, `block` | Lowercase gate result for the run. |
| `report-dir` | directory path | Directory with the full reports of the run. Set only when the review ran. |
| `artifact-name` | `diffseal-<short sha>` | Name for the report artifact: `diffseal-` and the first 7 characters of the commit reviewed. |

## Exit codes and gate behavior

| Gate | Default exit code | With `strict: 'true'` | With `advisory: 'true'` |
| :-- | :-- | :-- | :-- |
| `pass` | `0` | `0` | `0` |
| `review` | `0` | `2` | `0` |
| `block` | `2` | `2` | `0` |

Uncaught configuration or execution errors exit with code `1`.

## Pull request comments

When `comment` is `'true'`, the event payload includes `pull_request.number`, and `github-token` is non-empty, Diffseal searches up to 50 pages of 100 issue comments for a comment authored by `comment-author` that contains the HTML marker `<!-- diffseal-report -->`. If found, Diffseal updates that comment in place with `PATCH`. Otherwise, it creates a new comment with `POST`.

In `pr` mode, if a pull request produces nothing to report, Diffseal sets `onlyUpdate: true` on the comment request. A report is present when at least one Terraform root is evaluated, at least one gate reason is present, or the `policy` file changed.

When `onlyUpdate` is `true`, Diffseal updates an existing Diffseal comment if one was posted on an earlier commit of the pull request, and posts nothing on pull requests that have no report.

## Keep the full report

The job summary is cut short on a large change, and an uploaded change record over 900 KiB leaves out its lowest-risk resources. To keep everything, the Action writes the full reports of each run to a new directory under `$RUNNER_TEMP` and names it in the `report-dir` output:

- `report.json`: the replay result in `pr` mode, the same JSON that `diffseal replay` writes, or the analysis result in `plan` mode, the same JSON as `diffseal review --json`.
- `report.md`: the Markdown report with every reason, row and diagnostic. The job summary and the comment show at most 8 reasons and 40 rows per table, and are cut at 60,000 characters.
- `change-record.json`: the change record with every resource, when the Action built one to upload.

The Action uploads nothing itself. Add the standard `actions/upload-artifact` step after it to keep the directory as an artifact of the run:

```yaml
      - uses: diffseal/diffseal@v0.6.4-beta
        id: diffseal
        with:
          mode: pr

      - name: Keep the full report
        if: ${{ !cancelled() && steps.diffseal.outputs.report-dir != '' }}
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: ${{ steps.diffseal.outputs.artifact-name }}
          path: ${{ steps.diffseal.outputs.report-dir }}
          retention-days: 90
          overwrite: true
```

The `if` condition uploads the report when the gate fails the step too, and skips it when the Action stopped before reviewing anything, because `report-dir` is then not set. `overwrite: true` lets a re-run of the job replace the artifact of the earlier attempt instead of failing on the same name. Uploading an artifact needs no `permissions:` entry. If one workflow run reviews more than once, for example per root in a matrix, or also calls the trusted upload workflow, give each artifact its own name, such as `${{ steps.diffseal.outputs.artifact-name }}-prod`.

Anyone who can read the repository can download its artifacts. In `plan` mode `report.json` holds the planned attribute values that Terraform does not mark sensitive; sensitive values are written as `(sensitive)`.

The [trusted upload workflow](#upload-to-diffseal) already does this. Its artifact is named `diffseal-<short sha>` after the commit it reviewed, which for a pull request is GitHub's test merge commit, the same commit as the uploaded record. When the record leaves out resources, its note says the full list is in the `change-record.json` of that artifact, gives that file's SHA-256 and links the workflow run. Any job in the same workflow run can replace an artifact, so check the file against the digest before relying on it, for example with `shasum -a 256 change-record.json`. The note also names the replay report for the commit, which `diffseal replay` can write again after the artifact has expired.

## Base commit resolution

In `pr` mode, and in `plan` mode when `policy` is set, Diffseal resolves a base commit:

1. If you set the `base` input, Diffseal resolves that git revision.
2. Otherwise, Diffseal reads `pull_request.base.sha` or `merge_group.base_sha` from the GitHub event file at `$GITHUB_EVENT_PATH` and runs `git merge-base <event-base-sha> HEAD`.

With `git merge-base`, the comparison base is the commit where the pull request branched off, whether the workflow checks out the pull request head branch or GitHub's synthetic merge commit. Check out the repository with `fetch-depth: 0` so both commits and their history are present in the local clone.

Diffseal reads every setting that judges a change from the base commit:

- `.diffseal.json` policy settings and exceptions in `pr` mode.
- The JSON file specified by the `policy` input across all modes.

If a pull request modifies `.diffseal.json` or the `policy` file, the gate becomes at least `review`, and the updated settings take effect after the pull request merges.

## Example workflows

### Pull request static replay with `mode: pr`

Start in advisory mode to review comments without failing builds, then remove `advisory: 'true'` once calibrated.

```yaml
name: Diffseal PR review
on:
  pull_request:

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
          mode: pr
          roots-under: infra/envs/prod
          advisory: 'true'
```

### Terraform plan review with `mode: plan`

Use `mode: plan` when your workflow already runs `terraform plan` and converts the binary plan file with `terraform show -json`.

```yaml
name: Diffseal plan review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  plan-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: Generate plan JSON
        run: |
          terraform init -input=false
          terraform plan -input=false -out=tfplan
          terraform show -json tfplan > tfplan.json

      - uses: diffseal/diffseal@v0.6.4-beta
        with:
          mode: plan
          plan-json: tfplan.json
          policy: policy.json
          advisory: 'true'
```

## Upload to Diffseal

Uploads are off by default. To collect evidence, install the Diffseal GitHub App for your organisation and call the trusted reusable workflow:

```yaml
name: Diffseal evidence upload
on: [pull_request, push]
permissions:
  contents: read
  pull-requests: write
  id-token: write
jobs:
  diffseal:
    uses: diffseal/diffseal/.github/workflows/upload.yml@v0.6.4-beta
```

The workflow checks out GitHub's test merge commit for a pull request. It reads analysis settings from `.diffseal.json` through `git show`: for a pull request at the base branch commit, and for a push at the first parent of the pushed commit, the commit the push is compared with. Only a root commit, which has no parent, is read itself; any other change never chooses its own settings. It accepts no analysis inputs. Use the optional [`replay` settings](configuration.md#trusted-upload-replay-settings) to select roots, a policy file or a verified offline module cache. The workflow runs the Action from the same release tag, with `mode: pr`, `upload: 'true'`, `advisory: 'true'` and `report-artifact: 'true'`, and then keeps the [full report](#keep-the-full-report) of the run as an artifact. A failed artifact upload shows a warning and does not fail the job.

The workflow's one input, `retention-days`, says how many days the artifact is kept. It defaults to 90. GitHub caps it at the retention maximum of the repository or organisation, and `0` uses that setting. To keep reports for a whole audit period, raise the maximum in the repository settings (up to 400 days for a private repository) and pass a larger value:

```yaml
jobs:
  diffseal:
    uses: diffseal/diffseal/.github/workflows/upload.yml@v0.6.4-beta
    with:
      retention-days: 400
```

The service accepts only jobs identified by GitHub OIDC as trusted reusable workflows. Setting `upload: 'true'` in an ordinary pull request workflow does not make it trusted. An organisation owner can register another reusable workflow that pull request authors cannot edit. Uploads use a short-lived GitHub OIDC token with audience `diffseal`.

In branch protection, make **Diffseal evidence** a required check. Select the **Diffseal GitHub App** as its expected source. This prevents another job or app from satisfying the rule by posting the same check name. A missing trusted upload leaves the required check pending. Keep the upload job advisory so the App's check decides whether a blocked change can merge. GitHub treats a neutral check as passing, so use your normal required approving review rule for REVIEW findings.

Pull requests from forks cannot upload. They have no OIDC token for this workflow and receive no Diffseal evidence check. A required evidence check therefore prevents them from merging until your organisation handles the change through a trusted branch.

The Action sends a scrubbed change record: commit metadata, root paths, resource addresses and actions, gate reasons and structured items, risks, control findings and analysis notes. Its `access` list, kept for the record schema, is always empty. It sends no approvals. The service collects approvals from GitHub. The Action never uploads source files, Terraform configuration, plan files, state files or cloud credentials. The Action scrubs values marked sensitive in Terraform from findings. The OIDC token authenticates the request.

Uploads happen before the pull request comment. A blocked run may include a service link where an approver can request an exception for that pull request. An upload error produces a warning and keeps the job's gate and exit code. The Action retries a failed network request or a server error once. The `upload-id` output is present only after a successful upload. The service stores default branch pushes; pushes to other branches do not add evidence.
