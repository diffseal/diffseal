/**
 * Extract, from a terraform-provider-aws source checkout, which top-level arguments of each resource
 * force replacement. Reads files only; never builds or runs anything from the checkout.
 *
 *   bun run scripts/extract-forcenew.ts <provider-checkout> <commit> > src/terraform/aws-replace.json
 *
 * SDKv2 resources: top-level schema entries with `ForceNew: true`. For a ForceNew nested block (a list or
 * set of `&schema.Resource`), SDKv2 forces replacement on the element count only, so the block's own
 * ForceNew fields are recorded under `nested`; its other fields update in place. Plugin-framework resources:
 * top-level attributes with a `RequiresReplace()` plan modifier. `RequiresReplaceIf*` and ForceNew on
 * nested block attributes are recorded as conditional: a change there may or may not replace.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

const root = process.argv[2];
if (!root) {
  console.error('usage: extract-forcenew.ts <terraform-provider-aws checkout>');
  process.exit(2);
}

const constants = new Map<string, string>();
const namesFile = path.join(root, 'names', 'attr_consts_gen.go');
for (const m of fs.readFileSync(namesFile, 'utf8').matchAll(/^\s*(Attr\w+)\s*=\s*"([^"]+)"/gm)) constants.set(`names.${m[1]}`, m[2]);

function matchBrace(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '"') {
      for (i++; i < src.length && src[i] !== '"'; i++) if (src[i] === '\\') i++;
    } else if (c === '`') {
      i = src.indexOf('`', i + 1);
    } else if (c === '/' && src[i + 1] === '/') {
      i = src.indexOf('\n', i);
    } else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
    if (i < 0) return src.length - 1;
  }
  return src.length - 1;
}

/** Top-level `key: {...}` or `key: schema.XAttribute{...}` entries of a map literal body. */
function entries(body: string): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  const re = /(?:^|\n)\s*("[a-z0-9_]+"|names\.Attr\w+)\s*:\s*(?:&?[\w.]+)?\{/g;
  let m: RegExpExecArray | null;
  let from = 0;
  while ((m = re.exec(body))) {
    if (m.index < from) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBrace(body, open);
    const key = m[1].startsWith('"') ? m[1].slice(1, -1) : constants.get(m[1]);
    if (key) out.push({ key, value: body.slice(open + 1, close) });
    from = close;
    re.lastIndex = close;
  }
  return out;
}

/** The value body with nested braces removed, so only its own top-level fields remain. */
/**
 * The ForceNew fields inside a nested block schema (`Elem: &schema.Resource{Schema: ...}`), with fields
 * of its sub-blocks as dotted paths (`encryption_in_transit.in_cluster`). Undefined when the value has
 * no nested resource.
 */
function nestedForceNew(value: string): string[] | undefined {
  const elem = value.match(/Elem\s*:\s*&schema\.Resource\s*\{[\s\S]*?Schema\s*:\s*map\[string\]\*schema\.Schema\s*\{/);
  if (!elem) return undefined;
  const open = elem.index! + elem[0].length - 1;
  const out: string[] = [];
  for (const f of entries(value.slice(open + 1, matchBrace(value, open)))) {
    if (/ForceNew\s*:\s*true/.test(ownFields(f.value))) out.push(f.key);
    else for (const sub of nestedForceNew(f.value) ?? []) out.push(`${f.key}.${sub}`);
  }
  return out;
}

function ownFields(value: string): string {
  let out = '';
  let depth = 0;
  for (const c of value) {
    if (c === '{') depth++;
    if (depth === 0) out += c;
    if (c === '}') depth--;
  }
  return out;
}

interface Entry {
  replace: string[];
  /** ForceNew fields inside a ForceNew nested block, by block name; fields of sub-blocks as dotted paths. */
  nested?: Record<string, string[]>;
  /** ForceNew nested blocks that are sets (no order). */
  sets?: string[];
  conditional: string[];
}

const result: Record<string, Entry> = {};
const serviceDir = path.join(root, 'internal', 'service');

function goFiles(dir: string): string[] {
  return fs.readdirSync(dir).filter((f) => f.endsWith('.go') && !f.endsWith('_test.go')).map((f) => path.join(dir, f));
}

for (const svc of fs.readdirSync(serviceDir)) {
  const dir = path.join(serviceDir, svc);
  if (!fs.statSync(dir).isDirectory()) continue;
  const files = goFiles(dir);
  const pkgSrc = files.map((f) => fs.readFileSync(f, 'utf8')).join('\n');

  for (const file of files) {
    const src = fs.readFileSync(file, 'utf8');

    for (const ann of src.matchAll(/@SDKResource\("(aws_[a-z0-9_]+)"/g)) {
      const type = ann[1];
      const fn = src.slice(ann.index!).match(/func\s+(\w+)\(\)\s*\*schema\.Resource\s*\{/);
      if (!fn) continue;
      const start = ann.index! + fn.index! + fn[0].length - 1;
      const body = src.slice(start, matchBrace(src, start));
      let schemaBody: string | undefined;
      const inline = body.match(/Schema(?:Func)?\s*:\s*(?:func\(\)\s*map\[string\]\*schema\.Schema\s*\{\s*return\s*)?map\[string\]\*schema\.Schema\s*\{/);
      if (inline) {
        const open = inline.index! + inline[0].length - 1;
        schemaBody = body.slice(open + 1, matchBrace(body, open));
      } else {
        // Schema: name, Schema: maps.Clone(name), SchemaFunc: name, where name is a func or a package var.
        const named = body.match(/Schema(?:Func)?\s*:\s*(?:maps\.Clone\()?(\w+)\(?\)?\)?\s*,/);
        const def =
          named &&
          (pkgSrc.match(new RegExp(`func\\s+${named[1]}\\(\\)\\s*map\\[string\\]\\*schema\\.Schema\\s*\\{[\\s\\S]*?return\\s*map\\[string\\]\\*schema\\.Schema\\s*\\{`)) ??
            pkgSrc.match(new RegExp(`\\b${named[1]}\\s*=\\s*map\\[string\\]\\*schema\\.Schema\\s*\\{`)));
        if (def) {
          const open = def.index! + def[0].length - 1;
          schemaBody = pkgSrc.slice(open + 1, matchBrace(pkgSrc, open));
        }
      }
      if (!schemaBody) continue;
      const entry: Entry = { replace: [], conditional: [] };
      for (const { key, value } of entries(schemaBody)) {
        if (/ForceNew\s*:\s*true/.test(ownFields(value))) {
          entry.replace.push(key);
          const fields = nestedForceNew(value);
          if (fields) {
            (entry.nested ??= {})[key] = [...new Set(fields)].sort();
            // A set has no order: reordering its blocks is no change.
            if (/Type\s*:\s*schema\.TypeSet/.test(ownFields(value))) (entry.sets ??= []).push(key);
          }
        } else if (/ForceNew\s*:\s*true/.test(value)) entry.conditional.push(key);
      }
      result[type] = entry;
    }

    for (const ann of src.matchAll(/@FrameworkResource\("(aws_[a-z0-9_]+)"/g)) {
      const type = ann[1];
      const attrs = src.match(/Attributes\s*:\s*map\[string\]schema\.Attribute\s*\{/);
      if (!attrs) continue;
      const open = attrs.index! + attrs[0].length - 1;
      const body = src.slice(open + 1, matchBrace(src, open));
      const entry: Entry = { replace: [], conditional: [] };
      for (const { key, value } of entries(body)) {
        if (/planmodifier\.RequiresReplace\(\)/.test(value)) entry.replace.push(key);
        else if (/RequiresReplaceIf/.test(value)) entry.conditional.push(key);
      }
      const blocks = src.match(/Blocks\s*:\s*map\[string\]schema\.Block\s*\{/);
      if (blocks) {
        const bo = blocks.index! + blocks[0].length - 1;
        for (const { key, value } of entries(src.slice(bo + 1, matchBrace(src, bo)))) {
          if (/RequiresReplace/.test(value)) entry.conditional.push(key);
        }
      }
      result[type] = entry;
    }
  }
}

const sorted = Object.fromEntries(
  Object.keys(result)
    .sort()
    .map((k) => [
      k,
      {
        replace: [...new Set(result[k].replace)].sort(),
        conditional: [...new Set(result[k].conditional)].sort(),
        ...(result[k].nested ? { nested: Object.fromEntries(Object.keys(result[k].nested!).sort().map((b) => [b, result[k].nested![b]])) } : {}),
        ...(result[k].sets ? { sets: [...new Set(result[k].sets)].sort() } : {}),
      },
    ])
);
const commit = process.argv[3] ?? 'unknown';
const version = process.argv[4]?.replace(/^v/, '');
process.stdout.write(
  JSON.stringify(
    {
      source: 'hashicorp/terraform-provider-aws',
      ...(version ? { version } : {}),
      commit,
      resources: sorted,
    },
    null,
    1
  ) + '\n'
);
