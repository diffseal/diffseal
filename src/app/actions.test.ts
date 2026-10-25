import { expect, test } from 'bun:test';
import { actionsFor } from './actions.js';

// SDK operation names whose IAM action differs from `<prefix>:<Operation>` (Service Authorization Reference).
const CASES: Array<[string, string, string[]]> = [
  ['lambda', 'Invoke', ['lambda:InvokeFunction']],
  ['lambda', 'InvokeAsync', ['lambda:InvokeAsync']],
  ['lambda', 'InvokeWithResponseStream', ['lambda:InvokeFunction']],
  ['s3', 'ListBuckets', ['s3:ListAllMyBuckets']],
  ['s3', 'ListObjectsV2', ['s3:ListBucket']],
  ['s3', 'HeadObject', ['s3:GetObject']],
  ['s3', 'HeadBucket', ['s3:ListBucket']],
  ['s3', 'ListMultipartUploads', ['s3:ListBucketMultipartUploads']],
  ['s3', 'ListParts', ['s3:ListMultipartUploadParts']],
  ['dynamodb', 'TransactGetItems', ['dynamodb:GetItem']],
  ['apigatewaymanagementapi', 'PostToConnection', ['execute-api:ManageConnections']],
  ['apigatewaymanagementapi', 'GetConnection', ['execute-api:ManageConnections']],
  ['apigatewaymanagementapi', 'DeleteConnection', ['execute-api:ManageConnections']],
  // Unchanged: the operation is the action.
  ['dynamodb', 'BatchGetItem', ['dynamodb:BatchGetItem']],
  ['ssm', 'GetParametersByPath', ['ssm:GetParametersByPath']],
  ['sfn', 'StartExecution', ['states:StartExecution']],
  ['eventbridge', 'PutEvents', ['events:PutEvents']],
  ['sts', 'AssumeRole', ['sts:AssumeRole']],
];

test.each(CASES)('%s %s needs %p (round 7)', (service, operation, actions) => {
  expect(actionsFor(service, operation)).toEqual(actions);
});

// AWS Service Reference maps transaction writes to the actual item operations.
test('TransactWriteItems maps to per-item write actions', () => {
  expect(actionsFor('dynamodb', 'TransactWriteItems')).toEqual([
    'dynamodb:ConditionCheckItem',
    'dynamodb:DeleteItem',
    'dynamodb:PutItem',
    'dynamodb:UpdateItem',
  ]);
});

test('Bedrock Converse uses the permission named in AWS SDK documentation', () => {
  expect(actionsFor('bedrockruntime', 'Converse')).toEqual(['bedrock:InvokeModel']);
  expect(actionsFor('bedrockruntime', 'ConverseStream')).toEqual(['bedrock:InvokeModelWithResponseStream']);
});

test('every unmapped AWS operation records an explanation in the generated data', async () => {
  const data = await import('./aws-actions.json');
  for (const service of Object.values(data.default.services))
    for (const row of Object.values(service.operations)) {
      if (row.actions.length) continue;
      expect(row).toHaveProperty('unresolvedReason');
      expect((row as { unresolvedReason?: string }).unresolvedReason?.length).toBeGreaterThan(20);
    }
});
