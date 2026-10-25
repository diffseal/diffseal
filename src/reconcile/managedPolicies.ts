/**
 * Action patterns granted by common AWS managed policies (all on Resource "*"). Policies not listed
 * here are treated as unknown, so a missing permission is never reported when one is attached.
 */
export const MANAGED_POLICY_ACTIONS: Record<string, string[]> = {
  AWSLambdaBasicExecutionRole: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
  AWSLambdaVPCAccessExecutionRole: [
    'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents', 'ec2:CreateNetworkInterface', 'ec2:DescribeNetworkInterfaces',
    'ec2:DescribeSubnets', 'ec2:DeleteNetworkInterface', 'ec2:AssignPrivateIpAddresses', 'ec2:UnassignPrivateIpAddresses',
  ],
  AWSLambdaSQSQueueExecutionRole: ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
  AWSLambdaKinesisExecutionRole: [
    'kinesis:DescribeStream', 'kinesis:DescribeStreamSummary', 'kinesis:GetRecords', 'kinesis:GetShardIterator', 'kinesis:ListShards',
    'kinesis:ListStreams', 'kinesis:SubscribeToShard', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents',
  ],
  AWSLambdaDynamoDBExecutionRole: [
    'dynamodb:DescribeStream', 'dynamodb:GetRecords', 'dynamodb:GetShardIterator', 'dynamodb:ListStreams',
    'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents',
  ],
  AWSXRayDaemonWriteAccess: ['xray:PutTraceSegments', 'xray:PutTelemetryRecords', 'xray:GetSamplingRules', 'xray:GetSamplingTargets', 'xray:GetSamplingStatisticSummaries'],
  AmazonECSTaskExecutionRolePolicy: [
    'ecr:GetAuthorizationToken', 'ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage', 'logs:CreateLogStream', 'logs:PutLogEvents',
  ],
  CloudWatchLambdaInsightsExecutionRolePolicy: ['logs:CreateLogStream', 'logs:PutLogEvents', 'logs:CreateLogGroup'],
  AmazonPrometheusRemoteWriteAccess: ['aps:RemoteWrite'],
  AWSIoTDataAccess: [
    'iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive', 'iot:GetThingShadow', 'iot:UpdateThingShadow',
    'iot:DeleteThingShadow', 'iot:ListNamedShadowsForThing', 'iot:ListRetainedMessages', 'iot:GetRetainedMessage',
  ],
  AmazonS3ReadOnlyAccess: ['s3:Get*', 's3:List*', 's3:Describe*', 's3-object-lambda:Get*', 's3-object-lambda:List*'],
  AmazonSSMReadOnlyAccess: ['ssm:Describe*', 'ssm:Get*', 'ssm:List*'],
  AmazonEC2ContainerRegistryReadOnly: [
    'ecr:GetAuthorizationToken', 'ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:GetRepositoryPolicy',
    'ecr:DescribeRepositories', 'ecr:ListImages', 'ecr:DescribeImages', 'ecr:BatchGetImage', 'ecr:GetLifecyclePolicy',
    'ecr:GetLifecyclePolicyPreview', 'ecr:ListTagsForResource', 'ecr:DescribeImageScanFindings',
  ],
};

export function managedPolicyName(arn: string): string {
  return arn.split('/').pop() ?? arn;
}
