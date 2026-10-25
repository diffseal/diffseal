/** Regenerate offline IAM metadata from hash-locked AWS sources. No AWS credentials are used. */
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import lock from './aws-actions.sources.json';
const cache = path.resolve(process.env.TT_AWS_MODEL_CACHE ?? 'dry-runs/track-tree-sitter/aws');
const offline = process.argv.includes('--offline');
await mkdir(cache, { recursive: true });
const hash = (data: Uint8Array | string) => createHash('sha256').update(data).digest('hex');
async function source(id: string): Promise<string> {
  const pin = lock.sources[id as keyof typeof lock.sources];
  if (!pin) throw new Error('No source pin: ' + id);
  const file = path.join(cache, id + '.body');
  let body: Uint8Array;
  try {
    body = await readFile(file);
  } catch {
    if (offline) throw new Error('Missing offline source: ' + id);
    const response = await fetch(pin.url);
    if (!response.ok) throw new Error(`${response.status}: ${pin.url}`);
    body = new Uint8Array(await response.arrayBuffer());
  }
  if (hash(body) !== pin.sha256)
    throw new Error('AWS source changed: ' + id + '. Review and update the source lock explicitly.');
  await writeFile(file, body);
  return new TextDecoder().decode(body);
}
interface Shape {
  type: string;
  traits?: Record<string, any>;
  operations?: { target: string }[];
  input?: { target: string };
}
interface AuthorizedAction {
  Name: string;
  Service: string;
  Context?: unknown;
}
interface Reference {
  Name: string;
  Version: string;
  Operations?: { Name: string; AuthorizedActions?: AuthorizedAction[] }[];
  Actions: { Name: string; Resources?: { Name: string }[] }[];
  Resources?: { Name: string; ARNFormats: string[] }[];
}
interface Selector {
  fields: string[];
  actions: string[];
  replaces?: string[];
  source: string;
}
const selector = (fields: string[], actions: string[], replaces?: string[]): Selector => ({
  fields,
  actions,
  ...(replaces ? { replaces } : {}),
  source: 's3-permissions',
});
const selectors: Record<string, Selector[]> = {
  PutObject: [
    selector(['ACL', 'GrantFullControl', 'GrantRead', 'GrantReadACP', 'GrantWriteACP'], ['s3:PutObjectAcl']),
    selector(['Tagging'], ['s3:PutObjectTagging']),
    selector(['ObjectLockLegalHoldStatus'], ['s3:PutObjectLegalHold']),
    selector(['ObjectLockMode', 'ObjectLockRetainUntilDate'], ['s3:PutObjectRetention']),
  ],
  GetObject: [selector(['VersionId'], ['s3:GetObjectVersion'], ['s3:GetObject'])],
};
for (const [op, base] of Object.entries({
  HeadObject: 'GetObject',
  DeleteObject: 'DeleteObject',
  GetObjectAcl: 'GetObjectAcl',
  PutObjectAcl: 'PutObjectAcl',
  GetObjectTagging: 'GetObjectTagging',
  PutObjectTagging: 'PutObjectTagging',
  DeleteObjectTagging: 'DeleteObjectTagging',
})) {
  selectors[op] = [selector(['VersionId'], ['s3:' + base.replace('Object', 'ObjectVersion')], ['s3:' + base])];
}
interface Operation {
  selectors?: Selector[];
  unresolvedReason?: string;
  actions: string[];
  selection: string;
  authorizedActions: AuthorizedAction[];
  input?: string;
}
interface Service {
  prefix: string;
  operations: Record<string, Operation>;
  actionResources: Record<string, string[]>;
  resourceTypes: Record<string, string[]>;
}
// AWS's S3 permissions table explicitly labels required and conditional actions. Parse table rows,
// carrying the operation through continuation rows. Retain every candidate from the JSON separately.
const required = new Map<string, Set<string>>();
let operation: string | undefined;
for (const row of (await source('s3-permissions')).matchAll(/<tr[\s\S]*?<\/tr>/g)) {
  const cells = [...row[0].matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
  if (cells.length < 2) continue;
  const name = cells[0].match(/API_([A-Za-z0-9]+)\.html/);
  if (name) operation = name[1];
  else if (cells[0].replace(/<[^>]+>/g, '').trim()) operation = undefined;
  if (!operation || !cells[1].includes('(Required)')) continue;
  const actions = [...cells[1].matchAll(/<code[^>]*>(s3:[A-Za-z0-9]+)<\/code>/g)].map((m) => m[1]);
  if (!required.has(operation)) required.set(operation, new Set());
  for (const action of actions) required.get(operation)!.add(action);
}
if (required.get('HeadObject')?.has('s3:GetObject') !== true) throw new Error('S3 permissions table layout changed');
const services: Record<string, Service> = {};
for (const [name, pins] of Object.entries(lock.services)) {
  const model = JSON.parse(await source(pins.model)) as {
    shapes: Record<string, Shape>;
  };
  const reference = JSON.parse(await source(pins.reference)) as Reference;
  const service: Service = {
    prefix: reference.Name,
    operations: {},
    actionResources: {},
    resourceTypes: {},
  };
  for (const a of reference.Actions)
    service.actionResources[reference.Name + ':' + a.Name] = (a.Resources ?? []).map((r) => r.Name).sort();
  for (const r of reference.Resources ?? []) service.resourceTypes[r.Name] = r.ARNFormats;
  const entries = Object.entries(model.shapes)
    .filter(([, s]) => s.type === 'operation')
    .sort(([a], [b]) => a.localeCompare(b, 'en'));
  for (const [id, shape] of entries) {
    const operation = id.split('#')[1],
      row = reference.Operations?.find((o) => o.Name === operation),
      authorized = row?.AuthorizedActions ?? [];
    const candidates = [
      ...new Set(authorized.filter((a) => a.Service === reference.Name).map((a) => a.Service + ':' + a.Name)),
    ].sort();
    const trait = shape.traits?.['aws.iam#iamAction'];
    let actions: string[] = [],
      selection = 'unmapped';
    if (trait) {
      const a = reference.Name + ':' + (trait.name ?? operation);
      if (service.actionResources[a]) {
        actions = [a];
        selection = 'smithy-iam-trait';
      }
    }
    if (!actions.length) {
      // Some Smithy models state the required permission in their operation documentation,
      // while the Service Reference omits AuthorizedActions. Accept explicit statements only,
      // and require every action name to exist in the Service Reference's action inventory.
      const documentation = shape.traits?.['smithy.api#documentation'] ?? '';
      const explicit = [
        ...documentation.matchAll(
          /(?:This operation requires permission for the|Requires permission to access the) <(?:code|a)\b[^>]*>([A-Za-z0-9:]+)<\/(?:code|a)> action/gi,
        ),
      ].map((m) => (m[1].includes(':') ? m[1] : reference.Name + ':' + m[1]));
      if (explicit.length && explicit.every((a) => service.actionResources[a])) {
        actions = explicit;
        selection = 'smithy-documentation-required-permission';
      }
    }
    if (
      !actions.length &&
      name === 's3' &&
      ['DeleteObjectAnnotation', 'GetObjectAnnotation', 'ListObjectAnnotations', 'PutObjectAnnotation'].includes(
        operation,
      )
    ) {
      const doc = String(shape.traits?.['smithy.api#documentation'] ?? '');
      const explicit = doc.match(
        /To use this operation, you must have (?:the\s*)?<code>(s3:[A-Za-z0-9]+)<\/code>\s*permission/i,
      )?.[1];
      if (explicit && service.actionResources[explicit]) {
        actions = [explicit];
        selection = 'smithy-documentation-required-permission';
      }
    }
    if (!actions.length && name === 's3' && required.has(operation)) {
      actions = [...required.get(operation)!].filter((a) => candidates.includes(a));
      selection = 's3-required-permissions-table';
      // The table labels version and current-object alternatives as required in separate rows.
      // The base mapping uses the current object. VersionId is interpreted by the extractor.
      actions = actions.filter(
        (a) => !a.includes('ObjectVersion') || !actions.includes(a.replace('ObjectVersion', 'Object')),
      );
      // Source reads have their own resource and are emitted separately by all extractors.
      if (['CopyObject', 'UploadPartCopy'].includes(operation))
        actions = actions.filter((a) => !a.startsWith('s3:GetObject'));
    }
    if (!actions.length && candidates.includes(reference.Name + ':' + operation)) {
      actions = [reference.Name + ':' + operation];
      selection = 'same-name-candidate';
    }
    if (!actions.length && candidates.length === 1) {
      actions = candidates;
      selection = 'single-candidate';
    }
    if (name === 'dynamodb' && operation === 'TransactWriteItems') {
      actions = candidates;
      selection = 'per-transaction-item';
    }
    // The Service Reference omits AuthorizedActions for this API. AWS's websocket guide states
    // that @connections requires ManageConnections. Verify that action exists in AWS's action list.
    if (name === 'apigatewaymanagementapi' && service.actionResources['execute-api:ManageConnections']) {
      actions = ['execute-api:ManageConnections'];
      selection = 'websocket-connections-guide';
    }
    const doc = String(shape.traits?.['smithy.api#documentation'] ?? '');
    let unresolvedReason: string | undefined;
    if (!actions.length) {
      if (
        name === 'dynamodb' &&
        ['ExecuteStatement', 'BatchExecuteStatement', 'ExecuteTransaction'].includes(operation)
      )
        unresolvedReason =
          'PartiQL permissions depend on the SQL statements and tables. A statement selector is not implemented.';
      else if (name === 'kms' && operation === 'ReEncrypt')
        unresolvedReason =
          'AWS lists ReEncryptFrom and ReEncryptTo on separate source and destination keys. This two-resource mapping is not implemented.';
      else if (name === 'timestreamquery')
        unresolvedReason =
          'Query permissions depend on SQL, selected tables and optional UNLOAD output. A query selector is not implemented.';
      else if (name === 'cognitoidentityprovider' && /access token|client ID and secret/.test(doc))
        unresolvedReason =
          'The AWS model describes user-token or client-secret authorization. This operation cannot be verified from the workload role policies alone.';
      else if (name === 'sts')
        unresolvedReason =
          'Federated role assumption depends on the external identity and target trust policy. This authorization flow is not implemented.';
      else if (name === 's3' && doc.includes('s3express:'))
        unresolvedReason =
          'The AWS model describes directory-bucket session authorization through s3express. Directory-bucket authorization is not implemented.';
      else if (authorized.length)
        unresolvedReason =
          'AWS lists multiple candidate permissions without an unconditional required set. An operation-specific selector is not implemented.';
      else
        unresolvedReason =
          'The pinned AWS model and Service Reference do not establish a verified required-action mapping. No IAM action is guessed from the operation name.';
    }
    service.operations[operation] = {
      actions: actions.sort(),
      selection,
      authorizedActions: authorized,
      ...(unresolvedReason ? { unresolvedReason } : {}),
      ...(name === 's3' && selectors[operation] ? { selectors: selectors[operation] } : {}),
      ...(shape.input ? { input: shape.input.target } : {}),
    };
  }
  services[name] = service;
}
for (const service of Object.values(services)) {
  for (const row of Object.values(service.operations)) {
    for (const rule of row.selectors ?? []) {
      for (const action of rule.actions)
        if (!service.actionResources[action]) throw new Error('Selector action absent from AWS inventory: ' + action);
      for (const action of rule.replaces ?? [])
        if (!row.actions.includes(action)) throw new Error('Selector replacement absent from base mapping: ' + action);
    }
  }
}
services.cloudwatchevents = services.eventbridge;
const output = {
  format: 'terratrust.aws-actions/v1',
  generator: 'scripts/generate-aws-actions.ts',
  snapshotDate: lock.snapshotDate,
  modelCommit: lock.modelCommit,
  sourceLockSha256: hash(await readFile(new URL('./aws-actions.sources.json', import.meta.url))),
  sources: lock.sources,
  notes: {
    candidates: 'AuthorizedActions includes conditional permissions. Selected actions cover the base operation only.',
    websocket:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-control-access-iam.html',
  },
  services,
};
await writeFile(new URL('../src/app/aws-actions.json', import.meta.url), JSON.stringify(output, null, 2) + '\n');
const operations = Object.values(services).flatMap((s) => Object.values(s.operations));
console.log(
  `${Object.keys(services).length} SDK services; ${operations.length} operations; ${operations.filter((o) => o.actions.length).length} base mappings; ${operations.filter((o) => !o.actions.length).length} unmapped`,
);
