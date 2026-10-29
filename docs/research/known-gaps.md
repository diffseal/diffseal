# Known limits

What Diffseal does not handle yet.

## Encryption checks: known limits (v0.5.5-beta)

When an existing EFS resource has `encrypted = true` and `ignore_changes = [encrypted]`, changing its tags and adding another EFS resource whose `encrypted` references that ignored value makes static review report UNKNOWN for the existing resource but PASS for the new one. The new resource should also report UNKNOWN because its encryption evidence comes from an ignored attribute.

When an S3 encryption helper has an unresolved configured `bucket` expression, matching planned bucket names can still make `s3.encryption` report PASS. Matching planned listener ARNs can likewise attach a catch-all HTTPS redirect rule with an unresolved configured listener association and make `elb.https` report PASS. Both checks should report UNKNOWN because the configuration does not establish the helper association.

When EFS `encrypted` compares the Effect from `jsondecode(data.aws_iam_policy_document.p.json)` with a string, static review synthesizes the computed policy JSON as encryption evidence. For a document containing Allow, comparison with Allow reports PASS and comparison with Deny reports WARN. Both should report UNKNOWN because computed policy JSON is not configured encryption evidence.

When Memcached version `1.6.12` has `subnet_group_name = false ? aws_elasticache_subnet_group.example.name : null`, the unused reference is treated as evidence of VPC support. The transit encryption check reports WARN for `transit_encryption_enabled = false` and PASS for true. Both should report UNKNOWN because the configuration does not establish the required VPC support.
