# GitHub Action reference

The TerraTrust GitHub Action runs bundled JavaScript on the `node24` runtime through `dist/action.js` and makes no external network downloads at run time. It evaluates the change, writes a Markdown report to `$GITHUB_STEP_SUMMARY`, sets the `gate` output, optionally posts or updates a single pull request comment, and exits according to the gate verdict.

## Modes

Set `mode` to select what the Action checks:

- `pr`: Static replay of a pull request or merge group commit range. Evaluates affected Terraform roots at the base and head commits and checks any added application code in the diff against the Terraform IAM configuration at head.
- `plan`: Reviews the JSON output of `terraform show -json <planfile>` at the path given by `plan-json`.
- `app`: Scans application source code in the repository and checks every discovered AWS SDK call and infrastructure environment variable read against a Terraform repository.

## Inputs

| Input | Default | Used in modes | Description |
| :-- | :-- | :-- | :-- |
| `mode` | `'pr'` | all | Check mode: `pr`, `plan`, or `app`. Any other value fails with an error. |
| `plan-json` | `'tfplan.json'` | `plan` | Path to the JSON file produced by `terraform show -json <planfile>`. |
| `base` | `''` | `pr`, `app`, `plan` | Base git revision to compare against. When omitted on a `pull_request` or `merge_group` event, TerraTrust resolves the merge base between the event base SHA and `HEAD`. Requires `fetch-depth: 0` on checkout. Used in `plan` mode only when `policy` is set. |
| `roots-under` | `''` | `pr`, `app` | Limit evaluation to Terraform roots under this relative directory path, such as `infra/envs/prod`. |
| `infra-path` | `''` | `app` | Path to the Terraform repository when checking an application repository. Overrides `infra.repo` in `.terratrust.json`. |
| `role` | `''` | `app` | IAM role name, `path/name`, or ARN that the application runs as. Accepts comma-separated values and overrides `roles` in `.terratrust.json`. |
| `entry` | `''` | `app` | Entry directory or directories to trace imports from in `app` mode, such as `cmd/worker`. Accepts comma-separated values. |
| `policy` | `''` | all | Path to a policy JSON file inside the repository. Read from the base commit when a base is available so a pull request cannot weaken the policy that judges it. |
| `strict` | `'false'` | all | Set to `'true'` to fail the step with exit code `2` when the gate is `review` as well as when it is `block`. |
| `advisory` | `'false'` | all | Set to `'true'` to always exit with code `0`, even when the gate is `block`. The step summary, pull request comment, and `gate` output are still written. |
| `comment` | `'true'` | all | Set to `'true'` to create or update a pull request comment when running on a `pull_request` event with a valid `github-token`. |
| `comment-author` | `'github-actions[bot]'` | all | GitHub login expected on an existing TerraTrust comment. Only comments authored by this login and containing `<!-- terratrust-report -->` are updated in place. |
| `github-token` | `'${{ github.token }}'` | all | GitHub token used to list, create, or update the pull request comment. |

## Outputs

| Output | Values | Description |
| :-- | :-- | :-- |
| `gate` | `pass`, `review`, `block` | Lowercase gate result for the run. |

## Exit codes and gate behavior

| Gate | Default exit code | With `strict: 'true'` | With `advisory: 'true'` |
| :-- | :-- | :-- | :-- |
| `pass` | `0` | `0` | `0` |
| `review` | `0` | `2` | `0` |
| `block` | `2` | `2` | `0` |

Uncaught configuration or execution errors exit with code `1`.

## Pull request comments

When `comment` is `'true'`, the event payload includes `pull_request.number`, and `github-token` is non-empty, TerraTrust searches up to 50 pages of 100 issue comments for a comment authored by `comment-author` that contains the HTML marker `<!-- terratrust-report -->`. If found, TerraTrust updates that comment in place with `PATCH`. Otherwise, it creates a new comment with `POST`.

In `pr` and `app` modes, if a pull request produces nothing to report, TerraTrust sets `onlyUpdate: true` on the comment request:

- In `pr` mode, a report is present when at least one Terraform root is evaluated, at least one application access link is found, at least one gate reason is present, or the `policy` file changed.
- In `app` mode, a report is present when at least one application access link is found, at least one gate reason is present, or the `policy` file changed.

When `onlyUpdate` is `true`, TerraTrust updates an existing TerraTrust comment if one was posted on an earlier commit of the pull request, and posts nothing on pull requests that have no report.

## Base commit resolution

In `pr` and `app` modes, and in `plan` mode when `policy` is set, TerraTrust resolves a base commit:

1. If the `base` input is provided, TerraTrust resolves that git revision directly.
2. Otherwise, TerraTrust reads `pull_request.base.sha` or `merge_group.base_sha` from the GitHub event file at `$GITHUB_EVENT_PATH` and runs `git merge-base <event-base-sha> HEAD`.

Using `git merge-base` ensures that whether the workflow checks out the pull request head branch or GitHub's synthetic merge commit, the comparison base is the exact commit where the pull request branched off. Check out the repository with `fetch-depth: 0` so both commits and their history are present in the local clone.

All settings that judge a change are read from the base commit:

- `.terratrust.json` policy settings and exceptions in `pr` mode.
- `.terratrust.json` link settings, specifically `infra`, `roles`, and `env`, in `app` mode.
- The JSON file specified by the `policy` input across all modes.

If a pull request modifies `.terratrust.json` or the `policy` file, the gate becomes at least `review`, and the updated settings take effect after the pull request merges.

## Example workflows

### Pull request static replay with `mode: pr`

Start in advisory mode to review comments without failing builds, then remove `advisory: 'true'` once calibrated.

```yaml
name: TerraTrust PR review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  terratrust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - uses: TerraTrust/terratrust@v0.3.0-beta
        with:
          mode: pr
          roots-under: infra/envs/prod
          advisory: 'true'
```

### Terraform plan review with `mode: plan`

Use `mode: plan` when your workflow already runs `terraform plan` and converts the binary plan file with `terraform show -json`.

```yaml
name: TerraTrust plan review
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

      - uses: TerraTrust/terratrust@v0.3.0-beta
        with:
          mode: plan
          plan-json: tfplan.json
          policy: policy.json
          advisory: 'true'
```

### Application IAM check with `mode: app`

Use `mode: app` in an application repository to check that AWS SDK calls in added code are permitted by the IAM roles in your infrastructure repository.

```yaml
name: TerraTrust app check
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

      - uses: TerraTrust/terratrust@v0.3.0-beta
        with:
          mode: app
          infra-path: infra
          roots-under: envs/prod
          role: orders-api-task
          entry: cmd/orders-api
          advisory: 'true'
```
