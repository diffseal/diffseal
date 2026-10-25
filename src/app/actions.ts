/** IAM metadata generated from pinned AWS API models and Service Authorization Reference. */
import metadata from './aws-actions.json' with { type: 'json' };
import type { AccessFact, ResourceRef } from './facts.js';

/** SDK service package name -> IAM service prefix. */
export const IAM_PREFIX: Record<string, string> = Object.fromEntries(
  Object.entries(metadata.services).map(([name, service]) => [name, service.prefix]),
);

/** @aws-sdk/lib-dynamodb DocumentClient command names. */
export const DOCUMENT_CLIENT: Record<string, string> = {
  Put: 'PutItem',
  Get: 'GetItem',
  Query: 'Query',
  Scan: 'Scan',
  Update: 'UpdateItem',
  Delete: 'DeleteItem',
  BatchWrite: 'BatchWriteItem',
  BatchGet: 'BatchGetItem',
  TransactWrite: 'TransactWriteItems',
  TransactGet: 'TransactGetItems',
};

/** Operations that need some of their actions, not all: the call does not say which. */
export const ANY_OF = new Set(['dynamodb:TransactWriteItems']);

interface ActionService {
  prefix: string;
  operations: Record<
    string,
    {
      actions: string[];
      selection: string;
      authorizedActions: Array<{ Name: string; Service: string }>;
    }
  >;
}
const services: Record<string, ActionService> = metadata.services;
export function actionsFor(service: string, operation: string): string[] {
  const row = services[service]?.operations[operation];
  return row?.actions.length ? [...row.actions] : [`${IAM_PREFIX[service] ?? service}:${operation}`];
}
/** Unsupported mappings must not become a confident grant, even under an IAM wildcard. */
export function conservativeFact(fact: AccessFact): AccessFact {
  const row =
    services[fact.service]?.operations[
      fact.service === 's3' && fact.operation === 'Copy' ? 'CopyObject' : fact.operation
    ];
  // ConditionCheckItem is an IAM-only transaction action, not a standalone SDK API operation.
  const transaction =
    fact.service === 'dynamodb' &&
    fact.via?.includes('TransactWriteItems') &&
    fact.actions.every((action) => services.dynamodb.operations.TransactWriteItems.actions.includes(action));
  if (!row?.actions.length && !transaction)
    return {
      ...fact,
      possible: true,
      resource: {
        kind: 'unresolved',
        text: `unmapped IAM operation ${fact.service}:${fact.operation}`,
      },
    };
  return fact;
}

/** The input field that names the resource an operation acts on, per service. */
export const RESOURCE_FIELDS: Record<string, string[]> = {
  s3: ['Bucket'],
  sqs: ['QueueUrl', 'QueueName'],
  sns: ['TopicArn', 'TargetArn'],
  dynamodb: ['TableName'],
  secretsmanager: ['SecretId'],
  // Go uses StateMachineArn; the JavaScript v3 SDK and boto3 use the API's own camelCase members.
  sfn: ['StateMachineArn', 'ExecutionArn', 'stateMachineArn', 'executionArn'],
  ssm: ['Name', 'Path'],
  lambda: ['FunctionName'],
  kms: ['KeyId'],
  eventbridge: ['EventBusName'],
  scheduler: ['GroupName', 'Name'],
  iotdataplane: ['Topic', 'ThingName'],
  kinesis: ['StreamName', 'StreamARN'],
  firehose: ['DeliveryStreamName'],
  timestreamwrite: ['DatabaseName'],
};

/** Operations that do not act on a named resource (Resource "*" is expected). */
export const UNSCOPED_OPERATIONS = new Set([
  'sts:GetCallerIdentity',
  's3:ListAllMyBuckets',
  'sqs:ListQueues',
  'sns:ListTopics',
  'secretsmanager:ListSecrets',
  'dynamodb:ListTables',
  'lambda:ListFunctions',
  'states:ListStateMachines',
  'ssm:DescribeParameters',
  'cloudwatch:PutMetricData',
  'iot:DescribeEndpoint',
]);

/** Turn a printf-style format into a glob: "provider/%s/creds" -> "provider/*\/creds". */
export function formatToGlob(format: string): string {
  return format.replace(/%[-+# 0-9.*]*[a-zA-Z]/g, '*').replace(/%%/g, '%');
}

const NAME_HINTS: Array<[RegExp, string]> = [
  [/TOPIC/, 'sns'],
  [/QUEUE/, 'sqs'],
  [/BUCKET/, 's3'],
  [/TABLE/, 'dynamodb'],
  [/SECRET/, 'secretsmanager'],
  [/(SFN|STATE_?MACHINE|WORKFLOW)/, 'sfn'],
  [/(PARAM|SSM)/, 'ssm'],
  [/(FUNCTION|LAMBDA)/, 'lambda'],
  [/(EVENT_?BUS)/, 'eventbridge'],
  [/(KMS|KEY_ID|KEY_ARN)/, 'kms'],
  [/STREAM/, 'kinesis'],
];

const ARN_SERVICE: Record<string, string> = {
  states: 'sfn',
  events: 'eventbridge',
  logs: 'cloudwatchlogs',
};

/** Which SDK service a resource reference most likely belongs to, from an env var name or an ARN. */
export function serviceHint(ref: { kind: string; name?: string; value?: string; glob?: string }): string | undefined {
  const text =
    ref.kind === 'env' ? ref.name : ref.kind === 'literal' ? ref.value : ref.kind === 'pattern' ? ref.glob : undefined;
  if (!text) return undefined;
  const arn = text.match(/^arn:aws[\w-]*:([a-z0-9-]+):/);
  if (arn) return ARN_SERVICE[arn[1]] ?? arn[1];
  if (/^https:\/\/sqs\./.test(text)) return 'sqs';
  if (ref.kind !== 'env') return undefined;
  return NAME_HINTS.find(([re]) => re.test(text.toUpperCase()))?.[1];
}

/**
 * The source of CopySource: the bucket of "bucket/key" or "/bucket/key", or an access point ARN with its
 * object key ("arn:...:accesspoint/ap/object/key"), which is the resource IAM checks. A bucket that is
 * entirely unknown (`${b}/${k}`) stays unresolved: a `*` there would claim the code needs every bucket.
 */
export function copySourceBucket(ref: ResourceRef, text: string): ResourceRef {
  const sourceOf = (x: string) => {
    const s = x.split('?')[0];
    return s.startsWith('arn:') ? s : s.replace(/^\//, '').split('/')[0];
  };
  if (ref.kind === 'literal') return { ...ref, value: sourceOf(ref.value) };
  if (ref.kind === 'pattern') {
    const glob = sourceOf(ref.glob);
    return /^\**$/.test(glob) ? { kind: 'unresolved', text } : { ...ref, glob };
  }
  return ref;
}

export const COPY_OPERATIONS = new Set(['CopyObject', 'UploadPartCopy']);
