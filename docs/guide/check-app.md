# Checking application IAM permissions with `check-app`

`terratrust check-app` scans Go, TypeScript, and Python source files for AWS SDK calls and environment variable reads, finds the IAM role that runs the code, and checks whether the role's policies in Terraform grant each required action on the target resource.

You can run `check-app` on a whole application or only on the lines added since a base commit:

```bash
# Check the current working tree against Terraform in the same repo
terratrust check-app --app . --worktree

# Check only code added since origin/main against a separate infra repo
terratrust check-app --app ../orders-api --infra ../infra --base origin/main

# Trace from a specific binary entry directory and role name
terratrust check-app --app ../infra --entry services/worker/cmd/worker --role worker-task
```

## How TerraTrust finds the IAM role

TerraTrust links application code to one or more IAM roles in four ways.

### 1. Environment variables set on Lambda or ECS resources

When TerraTrust evaluates the Terraform roots, it indexes every `aws_lambda_function` through its `role` attribute and every `aws_ecs_task_definition` through its `task_role_arn` attribute, along with the environment variables configured on each compute resource.

For each AWS SDK call in application code:

1. If the call gets its target resource from an environment variable such as `process.env.ORDERS_TABLE`, `os.Getenv("ORDERS_TABLE")`, or `os.environ["ORDERS_TABLE"]`, TerraTrust finds every Lambda function or ECS task definition in Terraform that sets `ORDERS_TABLE`.
2. If the call uses a literal resource name, or if the environment variable has a fallback default in code and no compute sets it, TerraTrust looks for computes that define any environment variable read in that same source file.
3. If multiple computes match, TerraTrust scores each candidate by counting how many environment variables from that source file the compute sets, and keeps the highest-scoring compute or computes.
4. From each matched compute, TerraTrust resolves the `aws_iam_role` instance referenced by `role` or `task_role_arn`.

### 2. ECS task definitions in the application repository

Many service repositories keep their ECS task definition JSON in the application repository rather than in Terraform. When scanning the application repository, TerraTrust reads any file whose name matches `*taskdef*.json`, `*task-def*.json`, or `*task-definition*.json`:

- If the JSON has a top-level `taskRoleArn` string, TerraTrust adds that role ARN to the list of roles the application runs as.
- For each entry in `containerDefinitions`, TerraTrust collects the `name` of every item in `environment` and `secrets` and marks those environment variables as defined outside Terraform so they are not flagged as `MISSING`.

### 3. Kubernetes manifests and Helm values for EKS IRSA

TerraTrust scans `.yaml` and `.yml` files in the application repository, skipping `node_modules`, `.github`, `.gitlab`, and `.circleci`:

- In Kubernetes `kind: ServiceAccount` manifests and in `values*.yaml` or `values*.yml` files, TerraTrust looks for the `eks.amazonaws.com/role-arn` annotation and adds the role ARN to the application's roles.
- In Kubernetes workload manifests of kind `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, or `ReplicaSet`, and in `values*.yaml` or `values*.yml` files, TerraTrust collects container `env` variable names from `- name: VAR_NAME` entries and marks them as defined outside Terraform.

### 4. `.terratrust.json` and CLI or Action flags

You can specify roles and external environment variables directly:

- In `.terratrust.json`, set `"roles": ["orders-api-task"]` and `"env": ["EXTERNAL_VAR"]`.
- On the command line, pass `--role <name-or-arn>`, which can be repeated for multiple roles. In the GitHub Action, pass `role: orders-api-task` as a comma-separated list.

When `--role` or `role` is provided, it overrides the roles discovered from `.terratrust.json`, task definitions, and Kubernetes manifests. Even when the role is given by name or ARN, TerraTrust still looks up any Lambda or ECS compute in Terraform that runs as that role to resolve the values of environment variables used by the code.

### Cross-root and multi-account safety

When matching a role by name or ARN across multiple Terraform roots:

- A role ARN containing a 12-digit AWS account ID only matches Terraform roots whose provider targets that account, or roots where the account is not fixed statically. If a root configures providers for multiple AWS accounts, a role matched by ARN in that root is marked account-uncertain, which caps findings at `UNRESOLVED` so a namesake role in another account cannot produce a false `GRANTED` or `NOT GRANTED`.
- Policies defined in another Terraform root only grant access to a role when both roots target the same single, statically known AWS account. If either root's account is unknown or multi-account, a policy in the other root can turn a result into `UNRESOLVED`, never `GRANTED`.

## Result statuses

Every reconciled call site or environment variable read receives one of four statuses.

| Status | Gate effect | Meaning |
| :-- | :-- | :-- |
| `GRANTED` | `pass` | The role's identity policies allow every required action on the target resource, no statement explicitly denies it, the role's `permissions_boundary` allows it when present, and any customer-managed KMS key configured on the target resource permits the required cryptographic actions. |
| `NOT GRANTED` | `review` | At least one required action is not allowed by the role's policies, is blocked by an explicit `Deny` statement or `permissions_boundary`, or requires a customer-managed KMS key that the role or key policy does not permit. In JSON output and gate reasons, this status is written `NOT_GRANTED`. |
| `MISSING` | `review` | Application code reads an environment variable that names an AWS resource, has no fallback default in code, and is not set by any Lambda or ECS task definition in Terraform, any ECS task definition or Kubernetes manifest in the application repository, or the `env` list in `.terratrust.json`. |
| `UNRESOLVED` | `pass` | Static analysis cannot prove that the call succeeds or fails. Reported in the table for visibility without failing the gate. |

### Suggested Terraform statements on `NOT GRANTED`

When a call is `NOT GRANTED` because an `Allow` statement is missing, TerraTrust locates the policy attached to the role in the role's own Terraform root and generates a ready-to-paste statement in that policy's syntax:

- If the role uses `data.aws_iam_policy_document`, TerraTrust formats an HCL `statement { ... }` block and points to the `.tf` file and line of the data source.
- If the role uses `jsonencode` or a JSON policy string, TerraTrust formats a JSON statement object.
- When the target resource exists in the same module as the policy, the suggested `resources` expression uses the Terraform resource reference such as `aws_dynamodb_table.audit.arn`, with `/*` appended for S3 object actions or `/index/<name>` for DynamoDB index queries, instead of a placeholder ARN.

### Which environment variables can be reported as `MISSING`

Application code often reads environment variables for log levels, ports, or feature flags that do not belong in Terraform resource definitions. TerraTrust only reports an unset environment variable as `MISSING` when at least one of the following holds:

1. An AWS SDK call in the scanned code uses that environment variable as its target resource.
2. An unresolved SDK call in the same diff was paired with that environment variable.
3. The variable name ends with an infrastructure suffix: `_ARN`, `_URL`, `_BUCKET`, `_BUCKET_NAME`, `_QUEUE`, `_TOPIC`, `_TABLE`, `_TABLE_NAME`, `_SECRET_NAME`, `_SECRET_ID`, `_STREAM`, `_SFN_NAME`, `_STATE_MACHINE`, or `_PARAMETER`.

### Common causes of `UNRESOLVED`

A call is marked `UNRESOLVED` rather than `NOT GRANTED` whenever static analysis lacks enough information to prove an `AccessDenied`:

- No Lambda or ECS compute sets the environment variables read by the file, and no role was linked via task definitions, Kubernetes manifests, `.terratrust.json`, or `--role`.
- The resource argument passed to the SDK call comes from a function parameter, external helper, or dynamic expression that static analysis cannot trace to a literal, glob pattern, or environment variable. For unscoped operations such as `dynamodb:ListTables` or `sqs:ListQueues`, TerraTrust still checks whether the role grants `Resource: "*"` even when no resource argument is present.
- The matching `Allow` or `Deny` statement in IAM has a `Condition` block or an `Effect` expression that depends on an unknown value.
- An uncatalogued AWS managed policy or an unreadable policy expression is attached to the role or its `permissions_boundary`.
- A helper method in the repository can perform an AWS call that is not permitted by the role, but the constructor value is passed around such that the current binary may never invoke that method.
