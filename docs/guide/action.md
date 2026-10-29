# GitHub Action reference

The Diffseal GitHub Action runs bundled JavaScript on the `node24` runtime through `dist/action.js` and makes no external network downloads at run time. It evaluates the change, writes a Markdown report to `$GITHUB_STEP_SUMMARY`, sets the `gate` output, optionally posts or updates a single pull request comment, and exits according to the gate verdict.

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

Node.js 18 or later is required for the CLI. For a one-off run without installing:

```sh
npx diffseal@beta verify ./pack --account your-org --period 2026-Q4
```

## Modes

Set `mode` to select what the Action checks:

- `pr`: Static replay of a pull request or merge group commit range. Evaluates affected Terraform roots at the base and head commits and checks any added application code in the diff against the Terraform IAM configuration at head.
- `plan`: Reviews the JSON output of `terraform show -json <planfile>` at the path given by `plan-json`.
- `app`: Scans application source code in the repository and checks every discovered AWS SDK call and infrastructure environment variable read against a Terraform repository.

## Inputs

| Input | Default | Used in modes | Description |
| :-- | :-- | :-- | :-- |
| `upload` | `'false'` | `pr` | Upload the scrubbed change record for a `pull_request` or `push` event. Requires GitHub OIDC and a trusted reusable workflow. |
| `upload-url` | `https://api.diffseal.com` | `pr` | Service URL. Requires HTTPS. Local tests may use HTTP on localhost or 127.0.0.1. |
| `mode` | `'pr'` | all | Check mode: `pr`, `plan`, or `app`. Any other value fails with an error. |
| `plan-json` | `'tfplan.json'` | `plan` | Path to the JSON file produced by `terraform show -json <planfile>`. |
| `base` | `''` | `pr`, `app`, `plan` | Base git revision to compare against. When omitted on a `pull_request` or `merge_group` event, Diffseal resolves the merge base between the event base SHA and `HEAD`. Requires `fetch-depth: 0` on checkout. Used in `plan` mode only when `policy` is set. |
| `roots-under` | `''` | `pr`, `app` | Limit evaluation to Terraform roots under this relative directory path, such as `infra/envs/prod`. |
| `infra-path` | `''` | `app` | Path to the Terraform repository when checking an application repository. Overrides `infra.repo` in `.diffseal.json`. |
| `role` | `''` | `app` | IAM role name, `path/name`, or ARN that the application runs as. Accepts comma-separated values and overrides `roles` in `.diffseal.json`. |
| `entry` | `''` | `app` | Entry directory or directories to trace imports from in `app` mode, such as `cmd/worker`. Accepts comma-separated values. |
| `policy` | `''` | all | Path to a policy JSON file inside the repository. Read from the base commit when a base is available so a pull request cannot weaken the policy that judges it. |
| `strict` | `'false'` | all | Set to `'true'` to fail the step with exit code `2` when the gate is `review` as well as when it is `block`. |
| `advisory` | `'false'` | all | Set to `'true'` to always exit with code `0`, even when the gate is `block`. The step summary, pull request comment, and `gate` output are still written. |
| `comment` | `'true'` | all | Set to `'true'` to create or update a pull request comment when running on a `pull_request` event with a valid `github-token`. |
| `comment-author` | `'github-actions[bot]'` | all | GitHub login expected on an existing Diffseal comment. Only comments authored by this login and containing `<!-- diffseal-report -->` are updated in place. |
| `github-token` | `'${{ github.token }}'` | all | GitHub token used to list, create, or update the pull request comment. |

## Outputs

| Output | Values | Description |
| :-- | :-- | :-- |
| `upload-id` | run id | Set only when the service accepts an upload. |
| `gate` | `pass`, `review`, `block` | Lowercase gate result for the run. |

## Exit codes and gate behavior

| Gate | Default exit code | With `strict: 'true'` | With `advisory: 'true'` |
| :-- | :-- | :-- | :-- |
| `pass` | `0` | `0` | `0` |
| `review` | `0` | `2` | `0` |
| `block` | `2` | `2` | `0` |

Uncaught configuration or execution errors exit with code `1`.

## Pull request comments

When `comment` is `'true'`, the event payload includes `pull_request.number`, and `github-token` is non-empty, Diffseal searches up to 50 pages of 100 issue comments for a comment authored by `comment-author` that contains the HTML marker `<!-- diffseal-report -->`. If found, Diffseal updates that comment in place with `PATCH`. Otherwise, it creates a new comment with `POST`.

In `pr` and `app` modes, if a pull request produces nothing to report, Diffseal sets `onlyUpdate: true` on the comment request:

- In `pr` mode, a report is present when at least one Terraform root is evaluated, at least one application access link is found, at least one gate reason is present, or the `policy` file changed.
- In `app` mode, a report is present when at least one application access link is found, at least one gate reason is present, or the `policy` file changed.

When `onlyUpdate` is `true`, Diffseal updates an existing Diffseal comment if one was posted on an earlier commit of the pull request, and posts nothing on pull requests that have no report.

## Base commit resolution

In `pr` and `app` modes, and in `plan` mode when `policy` is set, Diffseal resolves a base commit:

1. If the `base` input is provided, Diffseal resolves that git revision directly.
2. Otherwise, Diffseal reads `pull_request.base.sha` or `merge_group.base_sha` from the GitHub event file at `$GITHUB_EVENT_PATH` and runs `git merge-base <event-base-sha> HEAD`.

Using `git merge-base` ensures that whether the workflow checks out the pull request head branch or GitHub's synthetic merge commit, the comparison base is the exact commit where the pull request branched off. Check out the repository with `fetch-depth: 0` so both commits and their history are present in the local clone.

All settings that judge a change are read from the base commit:

- `.diffseal.json` policy settings and exceptions in `pr` mode.
- `.diffseal.json` link settings, specifically `infra`, `roles`, and `env`, in `app` mode.
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

      - uses: diffseal/diffseal@v0.5.3-beta
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

      - uses: diffseal/diffseal@v0.5.3-beta
        with:
          mode: plan
          plan-json: tfplan.json
          policy: policy.json
          advisory: 'true'
```

### Application IAM check with `mode: app`

Use `mode: app` in an application repository to check that AWS SDK calls in added code are permitted by the IAM roles in your infrastructure repository.

```yaml
name: Diffseal app check
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  app-iam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - uses: actions/checkout@v5
        with:
          repository: your-org/infra
          token: ${{ secrets.INFRA_READ_TOKEN }}
          path: infra

      - uses: diffseal/diffseal@v0.5.3-beta
        with:
          mode: app
          infra-path: infra
          roots-under: envs/prod
          role: orders-api-task
          entry: cmd/orders-api
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
    uses: diffseal/diffseal/.github/workflows/upload.yml@v0.5.3-beta
```

The workflow checks out GitHub's test merge commit for a pull request. It reads analysis settings from `.diffseal.json` on the base branch through `git show`. It accepts no analysis inputs. Use the optional [`replay` settings](configuration.md#trusted-upload-replay-settings) to select roots, a policy file or a verified offline module cache. The workflow runs the Action from the same release tag, with `mode: pr`, `upload: 'true'` and `advisory: 'true'`.

The service accepts only jobs identified by GitHub OIDC as trusted reusable workflows. Setting `upload: 'true'` in an ordinary pull request workflow does not make it trusted. An organisation owner can register another reusable workflow that pull request authors cannot edit. Uploads use a short-lived GitHub OIDC token with audience `diffseal`.

In branch protection, make **Diffseal evidence** a required check. Select the **Diffseal GitHub App** as its expected source. This prevents another job or app from satisfying the rule by posting the same check name. A missing trusted upload leaves the required check pending. Keep the upload job advisory so the App's check decides whether a blocked change can merge. GitHub treats a neutral check as passing, so use your normal required approving review rule for REVIEW findings.

Pull requests from forks cannot upload. They have no OIDC token for this workflow and receive no Diffseal evidence check. A required evidence check therefore prevents them from merging until your organisation handles the change through a trusted branch.

The Action sends a scrubbed change record: commit metadata, root paths, resource addresses and actions, gate reasons and structured items, risks, control findings, access call sites and analysis notes. It sends no approvals. The service collects approvals from GitHub. The Action never uploads source files, Terraform configuration, plan files, state files or cloud credentials. Values marked sensitive in Terraform are scrubbed from findings. The OIDC token authenticates the request.

Uploads happen before the pull request comment. A blocked run may include a service link where an approver can request an exception for that pull request. An upload error produces a warning and preserves the job's gate and exit code. The Action retries a failed network request or a server error once. The `upload-id` output is present only after a successful upload. The service stores default branch pushes; pushes to other branches do not add evidence.
