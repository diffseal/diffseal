# Executable Specification Fixtures

The JSON files in `fixtures/` define the language-independent specification for Diffseal. Each file is a `FixtureSuite` object with a `suite` name, an optional `description`, and a `cases` array.

In the TypeScript implementation, `src/testing/fixtures.test.ts` loads every `.json` file under `fixtures/` and runs each case through `runFixtureCase` in `src/testing/fixtures.ts`. A port to another language (such as Go on `hashicorp/hcl/v2` and `zclconf/go-cty`) can validate against the same JSON files without reading TypeScript test code.

## Case Kinds

Every case has a `kind` field with one of two values:

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
