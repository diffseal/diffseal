/** AWS SDK calls in Java and related statically typed languages. No source is executed. */
import type { AccessFact, AddedLines, AppScan, EnvRead, ResourceRef } from './facts.js';
import { conditionalFacts } from './conditional.js';
import type { SourceFile } from './go.js';
import { actionsFor, conservativeFact, RESOURCE_FIELDS, COPY_OPERATIONS, copySourceBucket } from './actions.js';
import { syntax, clearSyntax, children, field, ancestor, walk, type Node } from './syntax.js';
type Language = 'java' | 'kotlin' | 'csharp';
interface Invocation {
  receiver?: Node;
  name: string;
  args: Node[];
}
interface Binding {
  name: string;
  target: Node;
  value?: Node;
  type?: string;
  scope: Node;
  declaration: boolean;
}
const CS_SERVICES: Record<string, string> = {
  S3: 's3',
  IoT: 'iot',
  IotData: 'iotdataplane',
  BedrockRuntime: 'bedrockruntime',
  ECS: 'ecs',
  Athena: 'athena',
  ApiGatewayManagementApi: 'apigatewaymanagementapi',
  CloudWatchEvents: 'cloudwatchevents',
  SQS: 'sqs',
  SimpleNotificationService: 'sns',
  SimpleSystemsManagement: 'ssm',
  DynamoDBv2: 'dynamodb',
  SecretsManager: 'secretsmanager',
  KeyManagementService: 'kms',
  Lambda: 'lambda',
  StepFunctions: 'sfn',
  EventBridge: 'eventbridge',
  Scheduler: 'scheduler',
  SecurityToken: 'sts',
  CloudWatch: 'cloudwatch',
  CloudWatchLogs: 'cloudwatchlogs',
  Kinesis: 'kinesis',
  KinesisFirehose: 'firehose',
  SimpleEmail: 'ses',
  SimpleEmailV2: 'sesv2',
  CognitoIdentityProvider: 'cognitoidentityprovider',
  ECR: 'ecr',
  TimestreamWrite: 'timestreamwrite',
  TimestreamQuery: 'timestreamquery',
};
const CS_CLASS: Record<string, string> = {
  DynamoDBv2: 'DynamoDB',
  SimpleEmail: 'SimpleEmailService',
  SimpleEmailV2: 'SimpleEmailServiceV2',
  SecurityToken: 'SecurityTokenService',
};
const cap = (s: string) => s[0]?.toUpperCase() + s.slice(1);
const languageOf = (file: string): Language =>
  file.endsWith('.java') ? 'java' : file.endsWith('.kt') ? 'kotlin' : 'csharp';
const SCOPES = new Set([
  'program',
  'source_file',
  'compilation_unit',
  'class_body',
  'class_declaration',
  'declaration_list',
  'method_declaration',
  'constructor_declaration',
  'function_declaration',
  'lambda_expression',
  'lambda_literal',
  'block',
]);
const FUNCTIONS = new Set([
  'method_declaration',
  'constructor_declaration',
  'function_declaration',
  'lambda_expression',
  'lambda_literal',
]);
const within = (a: Node, b: Node) => a.startIndex <= b.startIndex && b.endIndex <= a.endIndex;
const fn = (n: Node) => ancestor(n, (p) => FUNCTIONS.has(p.type));
const assignmentOperator = (n: Node) => field(n, 'operator')?.text ?? n.children.find((c) => c && !c.isNamed)?.text;
class ManagedFile {
  readonly parsed;
  readonly nodes: Node[];
  readonly bindings: Binding[] = [];
  readonly aliases = new Map<string, string>();
  readonly imported = new Map<string, { service: string; client: boolean }>();
  constructor(
    readonly language: Language,
    readonly source: string,
  ) {
    this.parsed = syntax(language, source);
    this.nodes = this.parsed.nodes;
    for (const n of this.nodes) {
      if (n.type === 'using_directive') {
        const alias = n.text.match(/^(?:global\s+)?using\s+(\w+)\s*=\s*((?:global::)?Amazon\.[A-Za-z0-9_.]+)\s*;/);
        if (alias) this.aliases.set(alias[1], alias[2]);
        const match = n.text.match(/^(?:global\s+)?using\s+Amazon\.([A-Za-z0-9]+)\s*;/);
        if (match && CS_SERVICES[match[1]]) {
          const service = CS_SERVICES[match[1]],
            name = CS_CLASS[match[1]] ?? match[1];
          for (const client of [`Amazon${name}Client`, `IAmazon${name}`])
            this.imported.set(client, { service, client: true });
        }
      }

      if (n.type === 'import_declaration' || n.type === 'import') {
        const match = n.text.match(
          /^import\s+software\.amazon\.awssdk\.services\.([a-z0-9]+)\.(?:model\.)?([A-Za-z0-9]+)(?:\s+as\s+([A-Za-z0-9_]+))?\s*;?$/,
        );
        if (match) this.imported.set(match[3] ?? match[2], { service: match[1], client: /Client$/.test(match[2]) });
      }
      if (language === 'kotlin' && n.type === 'parameter') {
        const parts = children(n);
        this.bind(
          parts.find((c) => c.type === 'identifier'),
          undefined,
          parts.find((c) => c.type === 'user_type')?.text,
          n,
          true,
        );
      }
      if (n.type === 'property_declaration') {
        const decl = children(n).find((c) => c.type === 'variable_declaration');
        const target = children(decl).find((c) => c.type === 'identifier');
        const type = children(decl).find((c) => ['user_type', 'nullable_type'].includes(c.type))?.text;
        const value = children(n)
          .filter((c) => c !== decl && !c.type.includes('modifier'))
          .at(-1);
        this.bind(target, value, type, n, true);
      }
      if (n.type === 'variable_declarator')
        this.bind(
          field(n, 'name'),
          field(n, 'value') ??
            (language === 'csharp' ? children(n).find((c) => c.id !== field(n, 'name')?.id) : undefined),
          field(n.parent!, 'type')?.text,
          n,
          true,
        );
      else if (n.type === 'formal_parameter' || (language === 'csharp' && n.type === 'parameter'))
        this.bind(field(n, 'name'), undefined, field(n, 'type')?.text, n, true);
      else if (['assignment_expression', 'assignment'].includes(n.type)) {
        const target = field(n, 'left');
        if (target?.type === 'identifier')
          this.bind(target, assignmentOperator(n) === '=' ? field(n, 'right') : n, undefined, n, false);
      }
    }
  }
  private bind(
    target: Node | undefined,
    value: Node | undefined,
    type: string | undefined,
    n: Node,
    declaration: boolean,
  ) {
    if (target)
      this.bindings.push({
        name: target.text,
        target,
        value,
        type,
        scope: ancestor(n.parent ?? undefined, (p) => SCOPES.has(p.type)) ?? this.parsed.tree.rootNode,
        declaration,
      });
  }
  private binding(name: string, use: Node, fieldOnly = false): Binding | undefined {
    const candidates = this.bindings.filter(
      (b) =>
        b.name === name &&
        within(b.scope, use) &&
        (!fieldOnly || ['class_body', 'declaration_list'].includes(b.scope.type)) &&
        (b.target.startIndex < use.startIndex || ['class_body', 'declaration_list'].includes(b.scope.type)),
    );
    candidates.sort((a, b) => a.scope.startIndex - b.scope.startIndex || a.target.startIndex - b.target.startIndex);
    const last = candidates.at(-1);
    if (!last) return;
    // A later assignment on a conditional path prevents using the earlier known value.
    if (
      this.bindings.some(
        (b) =>
          b.name === name &&
          !b.declaration &&
          b.target.startIndex > last.target.startIndex &&
          b.target.startIndex < use.startIndex &&
          fn(b.target)?.id === fn(use)?.id &&
          !within(b.scope, use),
      )
    )
      return;
    // A parameter with the same name masks a class field, even without an initializer.
    return last;
  }
  invocation(n: Node | undefined): Invocation | undefined {
    if (n?.type === 'invocation_expression') {
      const target = field(n, 'function');
      if (target?.type === 'member_access_expression')
        return {
          receiver: field(target, 'expression'),
          name: field(target, 'name')?.text ?? '',
          args: children(field(n, 'arguments')).map((a) => this.unwrap(a)),
        };
    }

    if (this.language === 'kotlin' && n?.type === 'call_expression') {
      const target = children(n)[0],
        parts = children(target);
      if (target?.type === 'navigation_expression' && parts.length >= 2)
        return {
          receiver: parts[0],
          name: parts.at(-1)!.text,
          args: children(children(n).find((c) => c.type === 'value_arguments')).map((a) => this.unwrap(a)),
        };
    }

    if (n?.type === 'method_invocation')
      return {
        receiver: field(n, 'object'),
        name: field(n, 'name')?.text ?? '',
        args: children(field(n, 'arguments')),
      };
  }
  private unwrap(n: Node): Node {
    while (['parenthesized_expression', 'argument', 'value_argument'].includes(n.type) && children(n).length === 1)
      n = children(n)[0];
    return n;
  }
  private typeService(type: string | undefined): string | undefined {
    if (!type) return;
    let name = type.replace(/<.*>$/, '').replace(/^global::/, '');
    if (
      !name.includes('.') &&
      this.nodes.some(
        (n) => ['class_declaration', 'interface_declaration'].includes(n.type) && field(n, 'name')?.text === name,
      )
    )
      return;
    const imported = this.imported.get(name);
    if (imported?.client) return imported.service;
    for (const [alias, target] of this.aliases)
      if (name === alias || name.startsWith(alias + '.')) name = target + name.slice(alias.length);
    const java = name.match(/^software\.amazon\.awssdk\.services\.([a-z0-9]+)\.[A-Za-z0-9]+Client$/);
    if (java) return java[1];
    const cs = name.match(/^Amazon\.([A-Za-z0-9]+)\.(Amazon[A-Za-z0-9]+Client|IAmazon[A-Za-z0-9]+)$/);
    if (cs) {
      const label = CS_CLASS[cs[1]] ?? cs[1];
      if ([`Amazon${label}Client`, `IAmazon${label}`].includes(cs[2])) return CS_SERVICES[cs[1]] ?? cs[1].toLowerCase();
    }
  }
  private builder(n: Node, depth: number): string | undefined {
    if (depth > 16) return;
    const call = this.invocation(n);
    if (!call?.receiver) return;
    if (call.name === 'builder') return this.typeService(call.receiver.text);
    return this.builder(call.receiver, depth + 1);
  }
  client(n: Node | undefined, use: Node, depth = 0): string | undefined {
    if (!n || depth > 16) return;
    n = this.unwrap(n);
    if (n.type === 'identifier') {
      const binding = this.binding(n.text, use);
      if (!binding) return;
      return (
        this.typeService(binding.type) ??
        (binding.value ? this.client(binding.value, binding.target, depth + 1) : undefined)
      );
    }
    const access = this.access(n);
    if (access?.receiver.text === 'this') return this.typeService(this.binding(access.name, use, true)?.type);
    if (n.type === 'object_creation_expression') return this.typeService(field(n, 'type')?.text);
    const call = this.invocation(n);
    if (call?.receiver) {
      if (call.name === 'create') return this.typeService(call.receiver.text);
      if (call.name === 'build') return this.builder(call.receiver, depth + 1);
    }
  }
  private access(n: Node | undefined): { receiver: Node; name: string } | undefined {
    if (!n) return;
    if (n.type === 'member_access_expression') {
      const receiver = field(n, 'expression'),
        name = field(n, 'name');
      if (receiver && name) return { receiver, name: name.text };
    }
    if (n.type === 'field_access') {
      const receiver = field(n, 'object'),
        name = field(n, 'field');
      if (receiver && name) return { receiver, name: name.text };
    }
    if (n.type === 'navigation_expression') {
      const parts = children(n);
      if (parts.length >= 2) return { receiver: parts[0], name: parts.at(-1)!.text };
    }
  }
  private conditional(n: Node, use: Node): boolean {
    return Boolean(
      ancestor(
        n,
        (p) =>
          [
            'if_statement',
            'if_expression',
            'for_statement',
            'while_statement',
            'when_expression',
            'try_statement',
          ].includes(p.type) && !within(p, use),
      ),
    );
  }
  fields(n: Node | undefined, use: Node, depth = 0): Map<string, Node> {
    if (!n || depth > 20) return new Map();
    n = this.unwrap(n);
    if (n.type === 'identifier') {
      const binding = this.binding(n.text, use);
      const fields = binding?.value ? this.fields(binding.value, binding.target, depth + 1) : new Map<string, Node>();
      if (!binding) return fields;
      const aliases = new Set([n.text]);
      for (let pass = 0; pass < 8; pass++)
        for (const other of this.bindings) {
          if (other.value?.type !== 'identifier' || other.target.startIndex >= use.startIndex) continue;
          if (aliases.has(other.value.text)) aliases.add(other.name);
          if (aliases.has(other.name)) aliases.add(other.value.text);
        }
      for (const write of this.nodes) {
        if (
          write.startIndex <= binding.target.startIndex ||
          write.startIndex >= use.startIndex ||
          fn(write)?.id !== fn(use)?.id
        )
          continue;
        const left = ['assignment_expression', 'assignment'].includes(write.type)
          ? this.access(field(write, 'left'))
          : undefined;
        const call = this.invocation(write),
          target = left?.receiver ?? call?.receiver;
        if (target?.type !== 'identifier' || !aliases.has(target.text)) continue;
        const alias = target.text !== n.text;
        if (!alias && this.binding(target.text, write)?.target.id !== binding.target.id) continue;
        const key = left?.name ?? (call && call.args.length === 1 ? cap(call.name) : undefined);
        const value = left ? field(write, 'right') : call?.args[0];
        if (key && value)
          fields.set(
            key,
            alias || this.conditional(write, use) || (left && assignmentOperator(write) !== '=') ? write : value,
          );
      }
      return fields;
    }
    if (['object_creation_expression', 'implicit_object_creation_expression'].includes(n.type)) {
      const fields = new Map<string, Node>();
      for (const pair of children(field(n, 'initializer')))
        if (pair.type === 'assignment_expression') {
          const key = field(pair, 'left'),
            value = field(pair, 'right');
          if (key && value) fields.set(key.text, value);
        }
      return fields;
    }
    const call = this.invocation(n);
    if (call?.receiver) {
      const fields = this.fields(call.receiver, use, depth + 1);
      if (call.args.length === 1 && !['build', 'builder', 'toBuilder'].includes(call.name))
        fields.set(cap(call.name), call.args[0]);
      return fields;
    }
    return new Map();
  }
  private string(n: Node): string | undefined {
    if (n.type !== 'string_literal' || [...walk(n)].some((c) => c.type === 'interpolation')) return;
    try {
      const value = JSON.parse(n.text);
      return typeof value === 'string' ? value : undefined;
    } catch {
      return;
    }
  }
  env(n: Node): string | undefined {
    const call = this.invocation(n);
    if (
      call &&
      ((call.name === 'getenv' && ['System', 'java.lang.System'].includes(call.receiver?.text ?? '')) ||
        (call.name === 'GetEnvironmentVariable' &&
          ['Environment', 'System.Environment'].includes(call.receiver?.text ?? '')))
    ) {
      if (
        ['System', 'Environment'].includes(call.receiver?.text ?? '') &&
        (this.binding(call.receiver!.text, n) ||
          this.nodes.some((p) => p.type === 'class_declaration' && field(p, 'name')?.text === call.receiver!.text))
      )
        return;
      return call.args[0] ? this.string(this.unwrap(call.args[0])) : undefined;
    }
  }
  hasDefault(n: Node): boolean {
    let child = n;
    while (child.parent && ['argument', 'value_argument', 'parenthesized_expression'].includes(child.parent.type))
      child = child.parent;
    const p = child.parent;
    if (p?.type !== 'binary_expression') return false;
    const op = field(p, 'operator')?.text ?? p.children.find((c) => c && !c.isNamed)?.text;
    const left = field(p, 'left');
    return Boolean(left && within(left, n) && ['??', '?:'].includes(op ?? ''));
  }
  resolve(n: Node, use: Node, depth = 0): Node {
    n = this.unwrap(n);
    if (depth > 20 || n.type !== 'identifier') return n;
    const binding = this.binding(n.text, use);
    return binding?.value ? this.resolve(binding.value, binding.target, depth + 1) : n;
  }
  ref(n: Node, use: Node, depth = 0): ResourceRef {
    n = this.unwrap(n);
    const unresolved = (): ResourceRef => ({ kind: 'unresolved', text: n.text });
    if (depth > 20) return unresolved();
    const env = this.env(n);
    if (env) return { kind: 'env', name: env };
    const text = this.string(n);
    if (text !== undefined) return { kind: 'literal', value: text };
    if (n.type === 'identifier') {
      const binding = this.binding(n.text, use);
      return binding?.value ? this.ref(binding.value, binding.target, depth + 1) : unresolved();
    }
    if (n.type === 'binary_expression') {
      const op = field(n, 'operator')?.text ?? n.children.find((c) => c && !c.isNamed)?.text;
      const left = field(n, 'left'),
        right = field(n, 'right');
      if (left && right && ['??', '?:'].includes(op ?? '')) {
        const a = this.ref(left, use, depth + 1),
          b = this.ref(right, use, depth + 1);
        if (a.kind === 'env') return { ...a, ...(b.kind === 'literal' ? { fallback: b.value } : {}) };
        if (a.kind === 'literal') return a;
        return unresolved();
      }
    }
    if (
      n.type === 'binary_expression' &&
      (field(n, 'operator')?.text ?? n.children.find((c) => c && !c.isNamed)?.text) === '+'
    ) {
      const left = field(n, 'left'),
        right = field(n, 'right');
      if (!left || !right) return unresolved();
      const a = this.ref(left, use, depth + 1),
        b = this.ref(right, use, depth + 1);
      if (a.kind === 'literal' && b.kind === 'literal') return { kind: 'literal', value: a.value + b.value };
      if (a.kind === 'literal' || b.kind === 'literal')
        return {
          kind: 'pattern',
          glob: [a, b].map((v) => (v.kind === 'literal' ? v.value : v.kind === 'pattern' ? v.glob : '*')).join(''),
        };
    }
    return unresolved();
  }
}
export function extractManaged(files: SourceFile[], opts: { addedLines?: AddedLines } = {}): AppScan {
  const facts: AccessFact[] = [],
    envReads: EnvRead[] = [];
  for (const file of files) {
    const added = opts.addedLines?.get(file.path);
    if (opts.addedLines && !added) continue;
    clearSyntax();
    try {
      const parsed = new ManagedFile(languageOf(file.path), file.content);
      const broken = parsed.parsed.tree.rootNode.hasError;
      for (const n of parsed.nodes) {
        const line = n.startPosition.row + 1;
        const selected = !added || [...added].some((l) => l >= line && l <= n.endPosition.row + 1);
        if (!selected) continue;
        const env = parsed.env(n);
        if (env)
          envReads.push({ name: env, file: file.path, line, ...(parsed.hasDefault(n) ? { hasDefault: true } : {}) });
        const call = parsed.invocation(n);
        if (!call?.receiver) continue;
        const service = parsed.client(call.receiver, n);
        if (
          !service ||
          ['close', 'serviceName', 'utilities', 'waiter', 'serviceClientConfiguration'].includes(call.name)
        )
          continue;
        let operation = parsed.language === 'csharp' ? call.name.replace(/Async$/, '') : cap(call.name);
        if (service === 's3' && parsed.language !== 'csharp' && operation === 'GetObjectAsBytes')
          operation = 'GetObject';
        const fields = parsed.fields(call.args[0], n);
        if (service === 's3' && fields.has('BucketName')) fields.set('Bucket', fields.get('BucketName')!);
        if (service === 's3' && COPY_OPERATIONS.has(operation) && fields.has('DestinationBucket'))
          fields.set('Bucket', fields.get('DestinationBucket')!);
        if (service === 's3' && parsed.language === 'csharp') {
          operation =
            (
              {
                GetObjectMetadata: 'HeadObject',
                ListVersions: 'ListObjectVersions',
                PutBucket: 'CreateBucket',
              } as Record<string, string>
            )[operation] ?? operation;
          if (['GetACL', 'PutACL'].includes(operation) && fields.has('Bucket')) {
            const key = fields.get('Key');
            const ref = key ? parsed.ref(key, n) : undefined;
            if (!key || ref?.kind === 'literal')
              operation = operation.startsWith('Get')
                ? ref?.kind === 'literal' && ref.value
                  ? 'GetObjectAcl'
                  : 'GetBucketAcl'
                : ref?.kind === 'literal' && ref.value
                  ? 'PutObjectAcl'
                  : 'PutBucketAcl';
          }
        }

        if (service === 's3') {
          for (const alias of ['Acl', 'CannedACL'])
            if (fields.has(alias)) fields.set('ACL', fields.get(alias)!);
        }
        const name = (RESOURCE_FIELDS[service] ?? []).find((k) => fields.has(k));
        const index = fields.has('IndexName') ? parsed.ref(fields.get('IndexName')!, n) : undefined;
        facts.push(
          ...conditionalFacts(
            {
              service,
              operation,
              actions: actionsFor(service, operation),
              ...(index ? { index: index.kind === 'literal' ? index.value : '*' } : {}),
              ...(broken ? { possible: true } : {}),
              resource: broken
                ? { kind: 'unresolved', text: `${parsed.language} source contains parse errors` }
                : name
                  ? parsed.ref(fields.get(name)!, n)
                  : { kind: 'unresolved', text: 'SDK request resource is not statically known' },
              file: file.path,
              line,
            },
            fields,
            {
              resolve: (value) => parsed.resolve(value, n),
              ref: (value) => parsed.ref(value, n),
            },
          ).map(conservativeFact),
        );
        if (service === 's3' && COPY_OPERATIONS.has(operation)) {
          const source = fields.get('SourceBucket') ?? fields.get('CopySource');
          const resource: ResourceRef = broken
            ? { kind: 'unresolved', text: `${parsed.language} source contains parse errors` }
            : source
              ? fields.has('SourceBucket')
                ? parsed.ref(source, n)
                : copySourceBucket(parsed.ref(source, n), source.text)
              : { kind: 'unresolved', text: 'Copy source bucket is not statically known' };
          facts.push({
            service: 's3',
            operation: 'GetObject',
            actions: ['s3:GetObject'],
            resource,
            file: file.path,
            line,
          });
        }
      }
    } finally {
      clearSyntax();
    }
  }
  return { facts, envReads };
}
export function envReadsManaged(source: string, file: string): EnvRead[] {
  return extractManaged([{ path: file, content: source }]).envReads;
}
