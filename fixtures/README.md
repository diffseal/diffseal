# Executable Specification Fixtures

The JSON files in `fixtures/` define the language-independent specification for Diffseal. Each file is a `FixtureSuite` object with a `suite` name, an optional `description`, and a `cases` array.

In the TypeScript implementation, `src/testing/fixtures.test.ts` loads every `.json` file under `fixtures/` and runs each case through `runFixtureCase` in `src/testing/fixtures.ts`. A port to another language (such as Go on `hashicorp/hcl/v2` and `zclconf/go-cty`) can validate against the same JSON files without reading TypeScript test code.

## Case Kinds

Every case has a `kind` field with one of four values:

1. `"terraform"`
   - Inputs:
     - `head`: map of file paths to file contents for the target revision.
     - `base` (optional): map of file paths to file contents for the base revision.
     - `root` (optional): Terraform root directory to evaluate. When omitted, the runner discovers roots by `backend` block.
     - `policy` (optional): `.diffseal.yml` policy overrides (`rules`, `cost`, `gate`, `exceptions`).
     - `now` (optional): ISO date string used to check exception expiry.
   - Expected outputs (`expect`):
     - `roots`: discovered Terraform root directories.
     - `diagnostics`: parser or evaluator diagnostics.
     - `instanceCount`: number of expanded resource and data instances.
     - `instances`: expected evaluated attributes and reference edges per instance address.
     - `changedAddresses`: sorted list of `<action> <address>` strings for managed resources with changes.
     - `changes`: per-resource change expectations (`address`, `action`, `confidence`, `previousAddress`, `preventDestroy`, `actionReasonContains`, `after`, `references`).
     - `findings`, `noFindingFor`: expected policy findings (`ruleId`, `resource`, `status`, `preExisting`, `detailContains`, `acceptedReasonContains`).
     - `blast`: expected blast-radius entries (`resource`, `action`, `severity`, `dataLoss`, `reasonContains`).
     - `cost`: expected monthly cost delta and per-resource cost items.
     - `gate`: expected gate decision (`pass`, `review`, `block`) and reason substrings.
     - `forbiddenSubstrings`: secret strings or tokens that must never appear in any output or evaluated attributes.

2. `"plan"`
   - Inputs:
     - `plan`: parsed `terraform show -json` plan object.
     - `policy` (optional): policy configuration.
     - `now` (optional): ISO date string.
   - Expected outputs (`expect`):
     - Same `AnalysisExpectation` fields as `"terraform"` (`changedAddresses`, `changes`, `findings`, `noFindingFor`, `blast`, `cost`, `gate`, `forbiddenSubstrings`).

3. `"app"`
   - Inputs:
     - `files`: map of application source files (`.go`, `.ts`, `.py`, `go.mod`).
     - `entryFiles` (optional): subset of files to extract from when the rest of `files` form the Go module index.
     - `goModule` (optional): Go module path when `go.mod` is not in `files`.
     - `addedLines` (optional): map of file path to 1-based line numbers added in a diff.
   - Expected outputs (`expect`):
     - `exactResources`: ordered list of extracted `ResourceRef` objects.
     - `facts`: expected `AccessFact` entries (`service`, `operation`, `actions`, `resource`, `index`, `file`).
     - `envReads`: expected environment variable reads (`name`, `fallback`).
     - `forbiddenResources`, `forbiddenActions`: resources or actions that must not be extracted.

4. `"reconcile"`
   - Inputs:
     - `infra`: map of Terraform files across one or more roots.
     - `roots` (optional): explicit root paths to index.
     - `app` (optional): map of application files to scan via `scanApp`.
     - `facts` (optional): explicit `AccessFact` list when testing reconciliation directly without scanning app source.
     - `envReads` (optional): explicit `EnvRead` list.
     - `options` (optional): `roleNames`, `entries`, `pairWithChangedEnv`, `fileEnv`, `externallyDefinedEnv`.
   - Expected outputs (`expect`):
     - `exactStatuses`: ordered list of link statuses (`GRANTED`, `NOT_GRANTED`, `UNRESOLVED`, `MISSING`).
     - `forbiddenStatuses`: link statuses that must not appear.
     - `links`: per-link assertions (`status`, `access`, `actionContains`, `role`, `root`, `detailContains`, `suggestion`).
