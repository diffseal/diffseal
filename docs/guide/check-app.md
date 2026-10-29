# Checking application IAM permissions with `check-app`

`diffseal check-app` scans Go, TypeScript, and Python source files for AWS SDK calls and environment variable reads, finds the IAM role that runs the code, and checks whether the role's policies in Terraform grant each required action on the target resource.

After [installing the CLI](verify.md#install-the-cli), you can run `check-app` on a whole application or only on the lines added since a base commit:

```bash
# From a repository checkout, check the orders-service example against demo-infra
diffseal check-app --app examples/orders-service --infra examples/demo-infra --worktree

# Trace from a specific entry directory and role name
diffseal check-app --app examples/orders-service --infra examples/demo-infra --entry src --role orders-prod-lambda --worktree

# Check only calls added since a base commit
diffseal check-app --app . --base HEAD
```

## How Diffseal finds the IAM role

Diffseal links application code to one or more IAM roles in four ways.

### 1. Environment variables set on Lambda or ECS resources

When Diffseal evaluates the Terraform roots, it indexes every `aws_lambda_function` through its `role` attribute and every `aws_ecs_task_definition` through its `task_role_arn` attribute, along with the environment variables configured on each compute resource.

For each AWS SDK call in application code:

1. If the call gets its target resource from an environment variable such as `process.env.ORDERS_TABLE`, `os.Getenv("ORDERS_TABLE")`, or `os.environ["ORDERS_TABLE"]`, Diffseal finds every Lambda function or ECS task definition in Terraform that sets `ORDERS_TABLE`.
2. If the call uses a literal resource name, or if the environment variable has a fallback default in code and no compute sets it, Diffseal looks for computes that define any environment variable read in that same source file.
3. If multiple computes match, Diffseal scores each candidate by counting how many environment variables from that source file the compute sets, and keeps the highest-scoring compute or computes.
4. From each matched compute, Diffseal resolves the `aws_iam_role` instance referenced by `role` or `task_role_arn`.

### 2. ECS task definitions in the application repository

Many service repositories keep their ECS task definition JSON in the application repository rather than in Terraform. When scanning the application repository, `discoverLink` reads any file outside `node_modules/` whose name matches `*taskdef*.json`, `*task-def*.json`, or `*task-definition*.json`:

- If the JSON has a top-level `taskRoleArn` string that does not contain an unresolved `${` template placeholder, Diffseal adds that role ARN to the list of roles the application runs as.
- For each entry in `containerDefinitions`, Diffseal collects the `name` of every item in `environment` and `secrets` and marks those environment variables as defined outside Terraform, so Diffseal does not report them as `MISSING`.

### 3. Kubernetes manifests and Helm values for EKS IRSA

Diffseal scans `.yaml` and `.yml` files in the application repository, skipping `node_modules`, `.github`, `.gitlab`, and `.circleci`:

- In Kubernetes `kind: ServiceAccount` manifests and in `values*.yaml` or `values*.yml` files, Diffseal looks for the `eks.amazonaws.com/role-arn` annotation and adds the role ARN to the application's roles.
- In Kubernetes workload manifests of kind `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, or `ReplicaSet`, and in `values*.yaml` or `values*.yml` files, Diffseal collects container `env` variable names from `- name: VAR_NAME` entries and marks them as defined outside Terraform.

### 4. `.diffseal.json` and CLI or Action flags

You can specify roles and external environment variables directly:

- In `.diffseal.json`, set `"roles": ["orders-api-task"]` and `"env": ["EXTERNAL_VAR"]`.
- On the command line, pass `--role <name,...>` as a comma-separated list. In the GitHub Action, pass `role: orders-api-task` as a comma-separated list.

When you pass `--role` or `role`, it overrides the roles discovered from `.diffseal.json`, task definitions, and Kubernetes manifests. Even when you give the role by name or ARN, Diffseal still looks up any Lambda or ECS compute in Terraform that runs as that role to resolve the values of environment variables used by the code.

### Cross-root and multi-account safety

When matching a role by name or ARN across multiple Terraform roots:

- A role ARN containing a 12-digit AWS account ID only matches Terraform roots whose provider targets that account, or roots where the account is not fixed statically. If a root configures providers for multiple AWS accounts, Diffseal marks a role matched by ARN in that root as account-uncertain, which caps findings at `UNRESOLVED` so a namesake role in another account cannot produce a false `GRANTED` or `NOT GRANTED`.
- Policies defined in another Terraform root only grant access to a role when both roots target the same single, statically known AWS account. If either root's account is unknown or multi-account, a policy in the other root can turn a result into `UNRESOLVED`, never `GRANTED`.

## Result statuses

Every reconciled call site or environment variable read receives one of four statuses.

| Status | Gate effect | Meaning |
| :-- | :-- | :-- |
| `GRANTED` | `pass` | The role's identity policies allow every required action on the target resource, no statement explicitly denies it, the role's `permissions_boundary` allows it when present, and any customer-managed KMS key configured on the target resource permits the required cryptographic actions. |
| `NOT GRANTED` | `review` | At least one required action is not allowed by the role's policies, is blocked by an explicit `Deny` statement or `permissions_boundary`, or requires a customer-managed KMS key that the role or key policy does not permit. In JSON output and gate reasons, this status is written `NOT_GRANTED`. |
| `MISSING` | `review` | Application code reads an environment variable that names an AWS resource, has no fallback default in code, and is not set by any Lambda or ECS task definition in Terraform, any ECS task definition or Kubernetes manifest in the application repository, or the `env` list in `.diffseal.json`. |
| `UNRESOLVED` | `pass` | Static analysis cannot prove that the call succeeds or fails. Listed in the table, but does not fail the gate. |

### Suggested Terraform statements on `NOT GRANTED`

When a call is `NOT GRANTED` because an `Allow` statement is missing, Diffseal locates the policy attached to the role in the role's own Terraform root and generates a ready-to-paste statement in that policy's syntax:

- If the role uses `data.aws_iam_policy_document`, Diffseal formats an HCL `statement { ... }` block and points to the `.tf` file and line of the data source.
- If the role uses `jsonencode` or a JSON policy string, Diffseal formats a JSON statement object.
- When the target resource exists in the same module as the policy, the suggested `resources` expression uses the Terraform resource reference such as `aws_dynamodb_table.audit.arn`, with `/*` appended for S3 object actions or `/index/<name>` for DynamoDB index queries, instead of a placeholder ARN.

### Which environment variables can be reported as `MISSING`

Application code often reads environment variables for log levels, ports, or feature flags that do not belong in Terraform resource definitions. Diffseal only reports an unset environment variable as `MISSING` when at least one of the following holds:

1. An AWS SDK call in the scanned code uses that environment variable as its target resource.
2. An unresolved SDK call in the same diff was paired with that environment variable.
3. The variable name ends with an infrastructure suffix: `_ARN`, `_URL`, `_BUCKET`, `_BUCKET_NAME`, `_QUEUE`, `_TOPIC`, `_TABLE`, `_TABLE_NAME`, `_SECRET_NAME`, `_SECRET_ID`, `_STREAM`, `_SFN_NAME`, `_STATE_MACHINE`, or `_PARAMETER`.

### Common causes of `UNRESOLVED`

Diffseal marks a call `UNRESOLVED` rather than `NOT GRANTED` when static analysis lacks the information to prove an `AccessDenied`:

- No Lambda or ECS compute sets the environment variables read by the file, and no role was linked via task definitions, Kubernetes manifests, `.diffseal.json`, or `--role`.
- The resource argument passed to the SDK call comes from a function parameter, external helper, or dynamic expression that static analysis cannot trace to a literal, glob pattern, or environment variable. For unscoped operations such as `dynamodb:ListTables` or `sqs:ListQueues`, Diffseal still checks whether the role grants `Resource: "*"` even when no resource argument is present.
- The matching `Allow` or `Deny` statement in IAM has a `Condition` block or an `Effect` expression that depends on an unknown value.
- An uncatalogued AWS managed policy or an unreadable policy expression is attached to the role or its `permissions_boundary`.
- A helper method in the repository can make an AWS call the role does not permit, but the code passes the constructed value around, so the current binary may never invoke that method.
