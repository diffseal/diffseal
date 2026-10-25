import { transactionFacts } from './transactions.js';
import {
  COPY_OPERATIONS,
  DOCUMENT_CLIENT,
  RESOURCE_FIELDS,
  actionsFor,
  conservativeFact,
  copySourceBucket,
} from './actions.js';
import type { AccessFact, AddedLines, AppScan, EnvRead } from './facts.js';
import { indexName, type SourceFile } from './go.js';
import {
  syntax,
  clearSyntax,
  children,
  field,
  walk,
  callable,
  args,
  member,
  literal,
  inRange,
  type Node,
} from './syntax.js';
const packageService = (pkg: string): string | undefined =>
  pkg.startsWith('@aws-sdk/client-')
    ? pkg.slice(16).replaceAll('-', '')
    : pkg === '@aws-sdk/lib-dynamodb'
      ? 'dynamodb-doc'
      : undefined;
export function envReadsTs(src: string, file: string, added?: Set<number>): EnvRead[] {
  clearSyntax();
  const out = syntax(file.endsWith('.tsx') ? 'tsx' : 'typescript', src).reads(file, added);
  clearSyntax();
  return out;
}
export function extractTs(files: SourceFile[], opts: { addedLines?: AddedLines } = {}): AppScan {
  const facts: AccessFact[] = [],
    envReads: EnvRead[] = [];
  for (const file of files) {
    clearSyntax();
    const added = opts.addedLines?.get(file.path);
    if (opts.addedLines && !added) continue;
    const s = syntax(file.path.endsWith('.tsx') ? 'tsx' : 'typescript', file.content);
    envReads.push(...s.reads(file.path, added));
    const commands = new Map<string, { service: string; exported: string }>();
    let v2 = false;
    for (const n of s.nodes) {
      if (n.type === 'import_statement') {
        const pkg = literal(field(n, 'source'));
        if (pkg === 'aws-sdk') v2 = true;
        const service = pkg && packageService(pkg);
        if (!service) continue;
        for (const spec of walk(n))
          if (spec.type === 'import_specifier') {
            const name = field(spec, 'name'),
              alias = field(spec, 'alias');
            if (name)
              commands.set(alias?.text ?? name.text, {
                service,
                exported: name.text,
              });
          }
      }
      if (n.type === 'variable_declarator') {
        const value = field(n, 'value'),
          name = field(n, 'name');
        if (value && callable(value)?.text === 'require') {
          const pkg = literal(args(value)[0]);
          if (pkg === 'aws-sdk') v2 = true;
          const service = pkg && packageService(pkg);
          if (!service) continue;
          for (const spec of children(name)) {
            if (spec.type === 'pair_pattern')
              commands.set(field(spec, 'value')!.text, {
                service,
                exported: field(spec, 'key')!.text,
              });
            if (spec.type === 'shorthand_property_identifier_pattern')
              commands.set(spec.text, { service, exported: spec.text });
          }
        }
      }
    }
    const push = (service: string, operation: string, n: Node, input: Node | undefined) => {
      if (!inRange(n, added)) return;
      const fields = s.fields(input),
        name = (RESOURCE_FIELDS[service] ?? []).find((k) => fields.has(k));
      const base: AccessFact = {
        service,
        operation,
        actions: actionsFor(service, operation),
        resource: name ? s.ref(fields.get(name)!) : { kind: 'unresolved', text: '(no resource field)' },
        file: file.path,
        line: n.startPosition.row + 1,
        ...(fields.has('IndexName') ? { index: indexName(s.ref(fields.get('IndexName')!)) } : {}),
      };
      facts.push(...(transactionFacts(base, fields, s) ?? [base]));
      if (service === 's3' && COPY_OPERATIONS.has(operation)) {
        const source = fields.get('CopySource');
        facts.push({
          service: 's3',
          operation: 'GetObject',
          actions: ['s3:GetObject'],
          resource: source
            ? copySourceBucket(s.ref(source), source.text)
            : { kind: 'unresolved', text: '(no CopySource)' },
          file: file.path,
          line: n.startPosition.row + 1,
        });
      }
    };
    for (const n of s.nodes) {
      if (n.type === 'new_expression') {
        const imported = commands.get(callable(n)?.text ?? '');
        if (!imported || !imported.exported.endsWith('Command')) continue;
        const name = imported.exported.slice(0, -7),
          doc = imported.service === 'dynamodb-doc';
        push(doc ? 'dynamodb' : imported.service, doc ? (DOCUMENT_CLIENT[name] ?? name) : name, n, args(n)[0]);
      } else if (v2 && n.type === 'call_expression') {
        const m = member(callable(n));
        if (!m) continue;
        const fields = s.fields(args(n)[0]);
        const hit = Object.entries(RESOURCE_FIELDS).find(([, names]) => names.some((k) => fields.has(k)));
        if (!hit) continue;
        const name = m.name[0].toUpperCase() + m.name.slice(1),
          op = hit[0] === 'dynamodb' ? (DOCUMENT_CLIENT[name] ?? name) : name;
        push(hit[0], op, n, args(n)[0]);
      }
    }
  }
  clearSyntax();
  return { facts: facts.map(conservativeFact), envReads };
}
