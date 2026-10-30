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
 *
 * It also records, for top-level arguments, the facts that decide what `null` means in a plan: which
 * arguments are Optional and Computed (null keeps the value in state), and literal provider defaults
 * (SDKv2 `Default:`, framework `stringdefault.StaticString(...)` and friends), with package constants
 * resolved when they are string, number or bool literals. `terraform providers schema -json` carries
 * neither defaults nor the SDK a resource is written in.
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
  // Braces inside strings, raw strings and comments (a regular expression such as `[^}]+`) do not nest.
  let out = '';
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    let end = i;
    if (c === '"') {
      for (end = i + 1; end < value.length && value[end] !== '"'; end++) if (value[end] === '\\') end++;
    } else if (c === '`') {
      end = value.indexOf('`', i + 1);
    } else if (c === '/' && value[i + 1] === '/') {
      end = value.indexOf('\n', i);
    }
    if (end < 0) end = value.length - 1;
    if (end !== i) {
      if (depth === 0) out += value.slice(i, end + 1);
      i = end;
      continue;
    }
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
  /** Top-level arguments that are both Optional and Computed: null in configuration keeps the state value. */
  optionalComputed?: string[];
  /** Literal provider defaults of top-level arguments. */
  defaults?: Record<string, string | number | boolean>;
  /** Written with the plugin framework (not SDKv2). */
  framework?: boolean;
}

/** A Go literal or package constant as a JSON value, or undefined when it is not a plain literal. */
function goLiteral(expr: string, pkgSrc: string, depth = 0): string | number | boolean | undefined {
  const e = expr.trim();
  if (e === 'true' || e === 'false') return e === 'true';
  if (/^-?\d+(\.\d+)?$/.test(e)) return Number(e);
  if (/^"(?:[^"\\]|\\.)*"$/.test(e)) {
    try {
      return JSON.parse(e) as string;
    } catch {
      return undefined;
    }
  }
  const framework = e.match(/^(?:string|bool|int64|int32|float64|float32|number)default\.Static(?:String|Bool|Int64|Int32|Float64|Float32)\((.*)\)$/s);
  if (framework) return goLiteral(framework[1], pkgSrc, depth + 1);
  if (/^[a-zA-Z_]\w*$/.test(e) && depth < 3) {
    const m = pkgSrc.match(new RegExp(`(?:^|\\n)\\s*(?:const\\s+)?${e}(?:\\s+\\w+)?\\s*=\\s*([^\\n]+)`));
    if (m) return goLiteral(m[1].replace(/\/\/.*$/, ''), pkgSrc, depth + 1);
  }
  return undefined;
}

/** The value expression of a top-level `Default:` field, up to its closing comma. */
function defaultExpr(own: string): string | undefined {
  const m = own.match(/(?:^|\n)\s*Default\s*:\s*/);
  if (!m) return undefined;
  const rest = own.slice(m.index! + m[0].length);
  let depth = 0;
  for (let i = 0; i < rest.length; i++) {
    const c = rest[i];
    if (c === '"') {
      for (i++; i < rest.length && rest[i] !== '"'; i++) if (rest[i] === '\\') i++;
    } else if (c === '(') depth++;
    else if (c === ')') depth--;
    else if ((c === ',' || c === '\n') && depth === 0) return rest.slice(0, i);
  }
  return rest;
}

/** Records Optional+Computed and the literal default of one top-level argument. */
function recordArgumentFacts(entry: Entry, key: string, value: string, pkgSrc: string) {
  const own = ownFields(value);
  // Fields only: text in strings and comments ("Computed: true when ...") is not a schema field.
  const code = own.replace(/\/\/[^\n]*/g, '').replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/`[^`]*`/g, '``');
  if (/(?:^|[\s,{])Optional\s*:\s*true/.test(code) && /(?:^|[\s,{])Computed\s*:\s*true/.test(code)) (entry.optionalComputed ??= []).push(key);
  const expr = defaultExpr(own);
  if (expr === undefined) return;
  const v = goLiteral(expr, pkgSrc);
  if (v !== undefined) (entry.defaults ??= {})[key] = v;
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
        recordArgumentFacts(entry, key, value, pkgSrc);
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
      const entry: Entry = { replace: [], conditional: [], framework: true };
      for (const { key, value } of entries(body)) {
        recordArgumentFacts(entry, key, value, pkgSrc);
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
        ...(result[k].optionalComputed ? { optional_computed: [...new Set(result[k].optionalComputed)].sort() } : {}),
        ...(result[k].defaults ? { defaults: Object.fromEntries(Object.keys(result[k].defaults!).sort().map((a) => [a, result[k].defaults![a]])) } : {}),
        ...(result[k].framework ? { framework: true } : {}),
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
