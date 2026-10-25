import { conditionalFacts } from './conditional.js';
import { transactionFacts } from './transactions.js';
import { RESOURCE_FIELDS, actionsFor, conservativeFact, copySourceBucket } from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead } from './facts.js';
import { indexName, type SourceFile } from './go.js';
import {
  syntax,
  clearSyntax,
  children,
  field,
  args,
  callable,
  member,
  literal,
  enclosingClass,
  enclosingFunction,
  inRange,
  type Node,
} from './syntax.js';

const BOTO_SERVICE: Record<string, string> = {
  stepfunctions: 'sfn',
  events: 'eventbridge',
  'iot-data': 'iotdataplane',
  'bedrock-runtime': 'bedrockruntime',
  'cognito-idp': 'cognitoidentityprovider',
  logs: 'cloudwatchlogs',
};

const TABLE_METHODS: Record<string, string> = {
  put_item: 'PutItem',
  get_item: 'GetItem',
  update_item: 'UpdateItem',
  delete_item: 'DeleteItem',
  query: 'Query',
  scan: 'Scan',
  batch_writer: 'BatchWriteItem',
};

/**
 * boto3's managed transfer helpers on an S3 client: they call GetObject, PutObject (or multipart
 * uploads, which need s3:PutObject too) under the hood, and `copy` also reads the source (handled with
 * CopySource below). `bucketArg` is the bucket's position when it is not passed by keyword.
 */
const S3_TRANSFER: Record<string, { op: string; actions: string[]; bucketArg: number }> = {
  upload_file: { op: 'PutObject', actions: ['s3:PutObject'], bucketArg: 1 },
  upload_fileobj: { op: 'PutObject', actions: ['s3:PutObject'], bucketArg: 1 },
  download_file: { op: 'GetObject', actions: ['s3:GetObject'], bucketArg: 0 },
  download_fileobj: {
    op: 'GetObject',
    actions: ['s3:GetObject'],
    bucketArg: 0,
  },
  copy: { op: 'Copy', actions: ['s3:PutObject'], bucketArg: 1 },
};

/** boto3 client methods that are not API operations: no IAM action, no fact. */
const CLIENT_HELPERS = new Set([
  'generate_presigned_url',
  'generate_presigned_post',
  'get_paginator',
  'get_waiter',
  'can_paginate',
  'close',
]);

const pascal = (snake: string) =>
  snake
    .split('_')
    .map((s) => s[0]?.toUpperCase() + s.slice(1))
    .join('');

export function envReadsPython(src: string, file: string, added?: Set<number>): EnvRead[] {
  clearSyntax();
  const out = syntax('python', src).reads(file, added);
  clearSyntax();
  return out;
}
interface Binding {
  target: Node;
  value: Node;
  kind: 'client' | 'table';
  service?: string;
}
export function extractPython(files: SourceFile[], opts: { addedLines?: AddedLines } = {}): AppScan {
  const facts: AccessFact[] = [],
    envReads: EnvRead[] = [];
  for (const file of files) {
    clearSyntax();
    const added = opts.addedLines?.get(file.path);
    if (opts.addedLines && !added) continue;
    const s = syntax('python', file.content);
    envReads.push(...s.reads(file.path, added));
    const bindings: Binding[] = [];
    for (const b of s.bindings) {
      if (!b.value || b.value.type !== 'call') continue;
      const f = callable(b.value),
        m = member(f);
      if (f?.text === 'boto3.client') {
        const name = literal(args(b.value)[0]);
        if (name)
          bindings.push({
            target: b.target,
            value: b.value,
            kind: 'client',
            service: BOTO_SERVICE[name] ?? name,
          });
      } else if (m?.name === 'Table' && args(b.value)[0])
        bindings.push({
          target: b.target,
          value: args(b.value)[0],
          kind: 'table',
        });
    }
    const classes = s.nodes.filter((n) => n.type === 'class_definition');
    const chain = (cls: Node | undefined): Node[] => {
      const out: Node[] = [],
        queue = cls ? [cls] : [];
      while (queue.length) {
        const c = queue.shift()!;
        if (out.some((n) => n.id === c.id)) continue;
        out.push(c);
        for (const base of children(field(c, 'superclasses'))) {
          const matches = classes.filter((c) => field(c, 'name')?.text === base.text);
          if (matches.length === 1) queue.push(matches[0]);
        }
      }
      return out;
    };
    const bound = (receiver: Node, use: Node): Binding | undefined => {
      const m = member(receiver);
      if (m?.object.text === 'self') {
        const attrs = bindings.filter(
          (b) => b.target.text === receiver.text || (b.target.text === m.name && !enclosingFunction(b.target)),
        );
        for (const cls of chain(enclosingClass(use))) {
          const own = attrs.filter((b) => enclosingClass(b.target)?.id === cls.id);
          if (own.length) return own.at(-1);
        }
        const values = new Set(attrs.map((b) => (b.kind === 'client' ? b.service : b.value.text)));
        return values.size === 1 ? attrs[0] : undefined;
      }
      if (receiver.type === 'identifier') {
        const b = s.binding(receiver.text, use);
        return b && bindings.find((x) => x.target.id === b.target.id);
      }
    };
    for (const n of s.nodes) {
      if (n.type !== 'call' || !inRange(n, added)) continue;
      const method = member(callable(n));
      if (!method) continue;
      const b = bound(method.object, n);
      if (!b) continue;
      const kwargs = new Map<string, Node>(),
        positional: Node[] = [];
      for (const a of args(n)) {
        if (a.type === 'keyword_argument') kwargs.set(field(a, 'name')!.text, field(a, 'value')!);
        else positional.push(a);
      }
      const line = n.startPosition.row + 1;
      if (b.kind === 'client') {
        const service = b.service!;
        if (CLIENT_HELPERS.has(method.name)) continue;
        const transfer = service === 's3' ? S3_TRANSFER[method.name] : undefined,
          operation = transfer?.op ?? pascal(method.name);
        const name = (RESOURCE_FIELDS[service] ?? []).find((k) => kwargs.has(k));
        const resource = name ? kwargs.get(name) : transfer ? positional[transfer.bucketArg] : undefined;
        const base: AccessFact = {
          service,
          operation,
          actions: transfer?.actions ?? actionsFor(service, operation),
          resource: resource ? s.ref(resource) : { kind: 'unresolved', text: '(no resource argument)' },
          file: file.path,
          line,
          ...(kwargs.has('IndexName') ? { index: indexName(s.ref(kwargs.get('IndexName')!)) } : {}),
        };
        const options = transfer ? new Map([...s.fields(kwargs.get('ExtraArgs') ?? positional[3]), ...kwargs]) : kwargs;
        facts.push(...(transactionFacts(base, options, s) ?? conditionalFacts(base, options, s)));
        if (service === 's3' && ['Copy', 'CopyObject', 'UploadPartCopy'].includes(operation)) {
          const source = kwargs.get('CopySource') ?? (operation === 'Copy' ? positional[0] : undefined),
            bucket = s.fields(source).get('Bucket');
          facts.push({
            service: 's3',
            operation: 'GetObject',
            actions: ['s3:GetObject'],
            resource: bucket
              ? s.ref(bucket)
              : source && s.resolve(source).type !== 'dictionary'
                ? copySourceBucket(s.ref(source), source.text)
                : { kind: 'unresolved', text: '(CopySource bucket not found)' },
            file: file.path,
            line,
          });
        }
      } else {
        const operation = TABLE_METHODS[method.name];
        if (!operation) continue;
        facts.push({
          service: 'dynamodb',
          operation,
          actions: actionsFor('dynamodb', operation),
          resource: s.ref(b.value),
          file: file.path,
          line,
          ...(kwargs.has('IndexName') ? { index: indexName(s.ref(kwargs.get('IndexName')!)) } : {}),
        });
      }
    }
  }
  clearSyntax();
  return { facts: facts.map(conservativeFact), envReads };
}
