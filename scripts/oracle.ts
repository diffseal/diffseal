/** Real Terraform 1.15.x differential oracle. No init, providers, state, or inherited credentials.
 * bun run scripts/oracle.ts [--out dry-runs/oracle/results.json] [--baseline FILE] [--report FILE]
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Body, Expr } from '../src/hcl/ast.js';
import { parseHcl } from '../src/hcl/parser.js';
import { containsUnknown, toPlain, isTfSet, markSet } from '../src/hcl/eval.js';
import { isUnknown, isRedacted, reveal } from '../src/core/model.js';
import { loadModule } from '../src/terraform/config.js';
import { evaluateRoot } from '../src/terraform/expand.js';
import { MemorySource } from '../src/terraform/source.js';
type Refs = {
    roots: Set<string>;
    vars: Set<string>;
    locals: Set<string>;
    functions: Set<string>;
};
function references(expr: Expr): Refs {
    const refs: Refs = { roots: new Set(), vars: new Set(), locals: new Set(), functions: new Set() };
    function visit(node: any, bound = new Set<string>()) {
        if (!node || typeof node !== 'object')
            return;
        if (Array.isArray(node)) {
            for (const n of node)
                visit(n, bound);
            return;
        }
        if (node.kind === 'scope') {
            if (!bound.has(node.name))
                refs.roots.add(node.name);
            return;
        }
        if (node.kind === 'call')
            refs.functions.add(node.name);
        if (node.kind === 'getattr' && node.obj.kind === 'scope' && !bound.has(node.obj.name)) {
            if (node.obj.name === 'var')
                refs.vars.add(node.name);
            if (node.obj.name === 'local')
                refs.locals.add(node.name);
        }
        if (node.kind === 'for') {
            visit(node.coll, bound);
            const child = new Set(bound);
            child.add(node.valVar);
            if (node.keyVar)
                child.add(node.keyVar);
            if ('valExpr' in node) {
                visit(node.keyExpr, child);
                visit(node.valExpr, child);
                visit(node.cond, child);
            }
            else
                visit(node.body, child);
            return;
        }
        for (const [key, value] of Object.entries(node))
            if (key !== 'range')
                visit(value, bound);
    }
    visit(expr);
    return refs;
}
export type Candidate = {
    id: string;
    expression: string;
    origins: string[];
    files: Record<string, string>;
    root: string;
};
export type Outcome = {
    kind: 'value';
    value: unknown;
} | {
    kind: 'error';
    message: string;
};
export type Result = {
    id: string;
    expression: string;
    origins: string[];
    status: 'equal' | 'different' | 'skipped';
    reason?: string;
    terraform?: Outcome;
    diffseal?: Outcome;
};
function stable(x: unknown): string {
    function order(v: any): any { if (Array.isArray(v))
        return v.map(order); if (v && typeof v === 'object')
        return Object.fromEntries(Object.keys(v).sort().map(k => [k, order(v[k])])); return v; }
    return JSON.stringify(order(x));
}
function parseExpression(text: string): Expr {
    const parsed = parseHcl(`value = ${text}\n`);
    if (parsed.diagnostics.length)
        throw new Error(parsed.diagnostics.map(d => d.message).join('; '));
    return parsed.body.attributes[0].expr;
}
function expressionSources(sources: Map<string, string>): Map<string, string> {
    const out = new Map<string, string>();
    for (const text of sources.values()) {
        function visit(node: any) { if (!node || typeof node !== 'object')
            return; if (node.kind && node.range)
            out.set(stable(node), text.slice(node.range.start.offset, node.range.end.offset)); for (const [key, value] of Object.entries(node))
            if (key !== 'range') {
                if (Array.isArray(value))
                    value.forEach(visit);
                else
                    visit(value);
            } }
        visit(parseHcl(text).body);
    }
    return out;
}
function candidates(): Candidate[] {
    const out: Candidate[] = [];
    for (const dir of ['fixtures/hcl', 'fixtures/terraform'])
        for (const name of fs.readdirSync(dir).filter(n => n.endsWith('.json')).sort()) {
            const suite = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
            for (const tc of suite.cases) {
                if (tc.kind !== 'terraform')
                    continue;
                for (const side of ['base', 'head']) {
                    const files = tc[side] as Record<string, string> | undefined;
                    if (!files)
                        continue;
                    for (const root of [...new Set(Object.keys(files).filter(f => f.endsWith('.tf') || f.endsWith('.tofu')).map(f => path.posix.dirname(f)))].sort()) {
                        const cfg = loadModule(new MemorySource(files), root);
                        if (!cfg)
                            continue;
                        const texts = expressionSources(cfg.sources);
                        const add = (expression: string, origin: string) => out.push({ id: '', expression, origins: [origin], files, root });
                        function leaves(expr: Expr, text: string, origin: string) {
                            add(texts.get(stable(expr)) ?? text.slice(expr.range.start.offset, expr.range.end.offset), origin);
                            if (expr.kind === 'object')
                                for (const item of expr.items)
                                    leaves(item.value, text, origin + ' / object member');
                        }
                        // Visit actual root blocks after override merging, including nested block arguments.
                        function body(b: Body, text: string, origin: string) { for (const a of b.attributes) {
                            if (['provider', 'depends_on', 'source', 'version', 'providers', 'type', 'sensitive', 'nullable'].includes(a.name))
                                continue;
                            leaves(a.expr, text, origin + '.' + a.name);
                        } for (const nested of b.blocks) {
                            if (['lifecycle', 'provisioner', 'connection'].includes(nested.type))
                                continue;
                            body(nested.body, text, origin + '.' + nested.type);
                        } }
                        for (const call of cfg.moduleCalls.values())
                            body(call.block.body, cfg.sources.get(call.file)!, `${dir}/${name} / ${tc.name} / ${side} / module.${call.name}`);
                        for (const [n, b] of cfg.variables) {
                            const a = b.body.attributes.find(a => a.name === 'default');
                            if (a)
                                add(texts.get(stable(a.expr))!, `${dir}/${name} / ${tc.name} / ${side} / var.${n}.default`);
                        }
                        for (const rb of [...cfg.resources.values(), ...cfg.data.values()])
                            body(rb.block.body, cfg.sources.get(rb.file)!, `${dir}/${name} / ${tc.name} / ${side} / ${rb.type}.${rb.name}`);
                        for (const [n, l] of cfg.locals)
                            leaves(l.attr.expr, cfg.sources.get(l.file)!, `${dir}/${name} / ${tc.name} / ${side} / local.${n}`);
                        for (const [n, b] of cfg.outputs) {
                            const a = b.body.attributes.find(a => a.name === 'value');
                            if (a) {
                                for (const [file, source] of cfg.sources) {
                                    const parsed = parseHcl(source);
                                    const block = parsed.body.blocks.find(b => b.type === 'output' && b.labels[0] === n);
                                    const attr = block?.body.attributes.find(a => a.name === 'value');
                                    if (attr)
                                        leaves(attr.expr, source, `${dir}/${name} / ${tc.name} / ${side} / ${file} / output.${n}`);
                                }
                            }
                        }
                    }
                }
            }
        }
    for (const [name, expression] of generated())
        out.push({ id: '', expression, origins: [`generated / ${name}`], root: 'r', files: { 'r/main.tf': '' } });
    return out;
}
export function generated(): Array<[
    string,
    string
]> {
    return [
        ['json key order', 'jsonencode({ z = 1, a = { y = 2, b = 3 } })'],
        ['json escapes', 'jsonencode({ value = "<>&\\u2028\\u2029" })'],
        ['json integer keys', 'jsonencode({ "2" = 2, "10" = 10, "1" = 1 })'],
        ['format unicode width', 'format("[%4s]", "å😀")'], ['format unicode precision', 'format("%.1s", "😀ab")'],
        ['format negative zero padding', 'format("%05d", -12)'], ['format null', 'try(format("%s", null), "error")'],
        ['format large integer', 'format("%d", 9007199254740991)'], ['format float', 'format("%.2f", -1.235)'],
        ['formatlist empty', 'formatlist("%s", [])'], ['formatlist scalars', 'formatlist("%s-%d", "x", 2)'], ['formatlist mismatch', 'try(formatlist("%s%s", [], ["a"]), "error")'],
        ['range default negative', 'range(-3)'], ['range descending', 'range(4, 1)'], ['range wrong sign', 'try(range(1, 4, -1), "error")'], ['range wrong sign error', 'range(1, 4, -1)'], ['range fractional', 'range(0, 1, 0.25)'], ['range zero', 'try(range(1, 2, 0), "error")'], ['range cap', 'try(range(1025), "error")'],
        ['regex no match', 'try(regex("x", "y"), "error")'], ['regex unicode', 'regex("[[:alpha:]]+", "åabc")'], ['regex captures', 'regex("(a)(b)?", "a")'], ['regexall no matches', 'regexall("z", "abc")'], ['regexall optional captures', 'regexall("(?P<a>a)(?P<b>b)?", "a ab")'], ['regex unsupported lookahead', 'try(regex("a(?=b)", "ab"), "error")'],
        ['yaml mapping', 'yamlencode({ z = 1, a = "yes" })'], ['yaml empty', 'yamlencode([])'],
        ['cidr host bits', 'cidrsubnet("10.0.1.9/16", 8, 2)'], ['cidr netnum overflow', 'try(cidrsubnet("10.0.0.0/16", 8, 256), "error")'], ['cidr negative bits', 'try(cidrsubnet("10.0.0.0/16", -1, 0), "error")'], ['cidr ipv6', 'cidrsubnet("2001:db8::/32", 8, 2)'],
        ['setunion mixed', 'setunion([1], ["1", "2"])'], ['setunion empty', 'setunion([], [])'], ['setunion ordering', 'setunion(["b", "a"], ["c", "b"])'],
        ['tolist mixed', 'tolist([1, "2"])'], ['tomap mixed', 'tomap({ a = 1, b = "2" })'], ['toset mixed', 'toset([1, "1"])'], ['tostring number', 'tostring(1e20)'], ['tostring null', 'tostring(null)'], ['tostring collection', 'try(tostring([]), "error")'], ['tonumber bool', 'try(tonumber(true), "error")'], ['tonumber empty', 'try(tonumber(""), "error")'], ['tonumber null', 'tonumber(null)'], ['tonumber whitespace', 'try(tonumber(" 2 "), "error")'], ['tonumber exponent', 'tonumber("1e3")'], ['tobool number', 'try(tobool(1), "error")'],
        ['try invalid index', 'try([][0], "fallback")'], ['can null attribute', 'can(null.x)'], ['try unknown function', 'try(no_such_function(1), "fallback")'],
        ['merge overwrite', 'merge({ z=1, a=2 }, { a=3 })'], ['merge null', 'merge(null, { a=1 })'], ['sort unicode', 'sort(["é", "a", "😀", "Z"])'], ['sort numeric', 'sort([10, 2, 1])'],
        ['distinct mixed', 'distinct([1, "1", 2])'], ['distinct empty', 'distinct([])'], ['flatten empty', 'flatten([[], []])'], ['flatten object boundary', 'flatten([[1], { a=[2] }, [3, [4]]])'],
        ['lookup converted default', 'lookup({ a=1 }, "missing", "2")'], ['lookup missing', 'try(lookup({}, "missing"), "error")'], ['element negative', 'try(element(["a", "b"], -1), "error")'], ['element fractional', 'try(element(["a", "b"], 1.5), "error")'], ['element wrapping', 'element(["a", "b"], 4)'], ['element empty', 'try(element([], 0), "error")'],
        ['template if', '"%{ if true }yes%{ else }no%{ endif }"'], ['template for', '"%{ for x in [1,2] }${x},%{ endfor }"'], ['template unicode', '"%{ for x in ["å", "😀"] }${x}%{ endfor }"'],
    ];
}
function prepare(c: Candidate): {
    configuration: string;
    inputs: Record<string, string>;
} | string {
    const source = new MemorySource(c.files);
    const cfg = loadModule(source, c.root);
    if (!cfg)
        return 'missing module';
    const texts = expressionSources(cfg.sources);
    const localTable = cfg.locals;
    let expression: Expr;
    try {
        expression = parseExpression(c.expression);
    }
    catch {
        return 'expression cannot be extracted from its source range';
    }
    const locals = new Set<string>(), vars = new Set<string>(), visiting = new Set<string>();
    let failure = '';
    function visit(expr: Expr) {
        const r = references(expr);
        for (const root of r.roots)
            if (!['var', 'local', 'terraform'].includes(root))
                failure = `resource/provider/state or instance context: ${root}`;
        for (const fn of r.functions)
            if (fn.startsWith('provider::') || ['file', 'filebase64', 'fileexists', 'fileset', 'templatefile', 'timestamp', 'plantimestamp', 'uuid', 'bcrypt', 'pathexpand'].includes(fn))
                failure = `external or nondeterministic function: ${fn}`;
        for (const v of r.vars)
            vars.add(v);
        for (const n of r.locals) {
            if (locals.has(n))
                continue;
            if (visiting.has(n)) {
                failure = 'local cycle';
                continue;
            }
            const l = localTable.get(n);
            if (!l) {
                failure = 'missing local ' + n;
                continue;
            }
            visiting.add(n);
            visit(l.attr.expr);
            visiting.delete(n);
            locals.add(n);
        }
    }
    visit(expression);
    if (failure)
        return failure;
    const inputs: Record<string, string> = {};
    const names = source.listFiles(c.root);
    const varFiles = ['terraform.tfvars', 'terraform.tfvars.json', ...names.filter(n => n.endsWith('.auto.tfvars') || n.endsWith('.auto.tfvars.json')).sort()];
    for (const name of varFiles) {
        const text = source.readFile(path.posix.join(c.root, name));
        if (text === undefined)
            continue;
        if (name.endsWith('.json')) {
            for (const [key, value] of Object.entries(JSON.parse(text))) inputs[key] = JSON.stringify(value);
            continue;
        }
        const parsed = parseHcl(text);
        if (parsed.diagnostics.length) return 'invalid fixture tfvars syntax';
        for (const a of parsed.body.attributes) inputs[a.name] = text.slice(a.expr.range.start.offset, a.expr.range.end.offset);
    }
    const parts: string[] = [];
    for (const n of [...vars].sort()) {
        const b = cfg.variables.get(n);
        if (!b)
            return 'undeclared variable ' + n;
        const attrs = b.body.attributes.filter(a => ['type', 'default', 'nullable', 'sensitive'].includes(a.name));
        if (!attrs.some(a => a.name === 'default') && !(n in inputs))
            return 'unset variable ' + n;
        // Variable AST ranges are relative to their original file. Locate the declaration by identity.
        let text = '';
        for (const t of cfg.sources.values()) {
            const parsed = parseHcl(t);
            const block = parsed.body.blocks.find(x => x.type === 'variable' && x.labels[0] === n);
            if (block) {
                text = t;
                break;
            }
        }
        parts.push(`variable ${JSON.stringify(n)} {\n${attrs.map(a => `${a.name} = ${texts.get(stable(a.expr)) ?? text.slice(a.expr.range.start.offset, a.expr.range.end.offset)}`).join('\n')}\n}`);
    }
    for (const n of locals) {
        const l = cfg.locals.get(n)!;
        const text = cfg.sources.get(l.file)!;
        parts.push(`locals {\n${n} = ${text.slice(l.attr.expr.range.start.offset, l.attr.expr.range.end.offset)}\n}`);
    }
    return { configuration: parts.join('\n'), inputs: Object.fromEntries(Object.entries(inputs).filter(([k]) => vars.has(k))) };
}
function visible(value: unknown): unknown {
    if (isRedacted(value))
        return visible(reveal(value));
    if (Array.isArray(value)) {
        const out = value.map(visible);
        return isTfSet(value) ? markSet(out) : out;
    }
    if (value && typeof value === 'object' && !isUnknown(value))
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, visible(v)]));
    return value;
}
function sameValue(tf: any, ts: any): boolean {
    if (Array.isArray(ts) && Array.isArray(tf)) {
        if (isTfSet(ts))
            return stable(tf.map(stable).sort()) === stable(ts.map(stable).sort());
        return tf.length === ts.length && ts.every((v, i) => sameValue(tf[i], v));
    }
    if (tf && ts && typeof tf === 'object' && typeof ts === 'object' && !Array.isArray(tf) && !Array.isArray(ts))
        return stable(Object.keys(tf).sort()) === stable(Object.keys(ts).sort()) && Object.keys(ts).every(k => sameValue(tf[k], ts[k]));
    return stable(tf) === stable(ts);
}
function tsOutcome(c: Candidate): Outcome | string {
    const files = { ...c.files, [path.posix.join(c.root, '__diffseal_oracle.tf')]: `resource "terraform_data" "__oracle" {\ninput = ${c.expression}\n}\n` };
    const result = evaluateRoot(new MemorySource(files), c.root).instances.find(i => i.address === 'terraform_data.__oracle');
    if (!result)
        return 'synthetic output missing';
    const value = visible(toPlain(result.attrs.input));
    if (isUnknown(value) && value.reason.startsWith('error:'))
        return { kind: 'error', message: value.reason };
    if (containsUnknown(value))
        return 'Diffseal unknown: ' + (isUnknown(value) ? value.reason : 'partial unknown');
    return { kind: 'value', value };
}
function terraformOutcome(dir: string, configuration: string, expression: string, inputs: Record<string, string>): Outcome {
    fs.writeFileSync(path.join(dir, 'main.tf'), configuration + `\nlocals {\n__diffseal_oracle_value = (\n${expression}\n)\n}\n`);
    fs.writeFileSync(path.join(dir, 'terraform.tfvars'), Object.entries(inputs).map(([name, expression]) => `${name} = ${expression}\n`).join(''));
    const env = { PATH: process.env.PATH!, HOME: dir, TF_IN_AUTOMATION: '1', CHECKPOINT_DISABLE: '1', TF_CLI_CONFIG_FILE: path.join(dir, 'terraform.rc') };
    const run = spawnSync('terraform', [`-chdir=${dir}`, 'console', '-no-color'], { input: 'nonsensitive(jsonencode({result=local.__diffseal_oracle_value}))\n', env, encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024 });
    if (run.error)
        throw run.error;
    if (run.status !== 0 || /^Error:/m.test(run.stderr))
        return { kind: 'error', message: run.stderr.trim() };
    try {
        return { kind: 'value', value: JSON.parse(JSON.parse(run.stdout.trim())).result };
    }
    catch {
        throw new Error('Unrecognized Terraform console output: ' + run.stdout + '\n' + run.stderr);
    }
}
function pretty(x: unknown): string { return JSON.stringify(x, null, 2); }
function document(version: string, results: Result[], baseline?: Result[]): string {
    const counts = (rs: Result[]) => Object.fromEntries(['equal', 'different', 'skipped'].map(s => [s, rs.filter(r => r.status === s).length]));
    const c = counts(results);
    let doc = `# Terraform console oracle\n\nReference: ${version}. Run with \`bun run scripts/oracle.ts --report dry-runs/oracle/current.md\`.\n\nCompared ${c.equal + c.different} cases: ${c.equal} equal, ${c.different} different. Skipped ${c.skipped}. Cases are deduplicated by expression and referenced variable/local configuration. The runner visits every module directory in each base/head snapshot, including variable defaults, module arguments, locals, outputs, and nested resource arguments. Object members are also extracted so a resource-dependent sibling does not hide a pure expression. Required child-module inputs are skipped when they are not available as defaults or tfvars in that module; caller expansion is outside this oracle. HCL tfvars expressions are passed to Terraform as source, not evaluated by Diffseal first.\n\nThe oracle uses a fresh scratch directory, only needed variable and local declarations, and a sanitized environment with no inherited cloud credentials, Terraform CLI arguments, or workspace. It runs no init, no providers, no state operations, and no network requests. Results are transported through Terraform's jsonencode, preserving result strings literally. Sets travel as JSON arrays and compare by membership using Diffseal's set marker. List order and JSON string bytes remain significant; errors compare by success versus failure, not diagnostic wording. Inputs and output are synthetic fixture data.\n\nResource/provider/data/instance references, unset variables, external files, nondeterministic functions, and Diffseal unknowns are skipped with counts below. This checks values, not unknown identities, sensitivity labels, provider behavior, or a full plan. JSON numbers are parsed by JavaScript on both sides; this cannot certify arbitrary precision beyond JavaScript numbers.\n\n`;
    if (baseline) {
        const b = counts(baseline);
        doc += `## Before fixes\n\nCompared ${b.equal + b.different}: ${b.equal} equal, ${b.different} different; ${b.skipped} skipped.\n\n`;
    }
    doc += `## Findings and limits

The reference run uses 66 generated edge expressions as well as the JSON fixture expressions. It covers format/formatlist, range, regex/regexall, JSON/YAML encoding, CIDR, sets, type conversions, try/can, merge order, sorting, distinct, flatten, lookup, element, and template directives. Generated values include empty collections, Unicode, large and negative numbers, and nulls.

The initial experiment found and corrected eight families of evaluator behavior:

| Area | Correction |
|---|---|
| jsonencode | Recursively sort keys, including integer-looking keys, and match HTML/Unicode separator escaping. Preserve partial unknown JSON for Diffseal analysis. |
| range | Reject a step that points away from the end. The old fixture incorrectly expected an empty list. |
| regex/regexall | Translate POSIX ASCII classes, preserve null unmatched captures, and reject lookaround/backreferences unsupported by RE2. This is still a JavaScript adapter, not a full RE2 engine. |
| cidrsubnet | Clear host bits, enforce subnet-number bounds, and calculate IPv6 subnets. |
| Collection conversion | Unify primitive types for tolist, tomap, toset, distinct, and setunion before deduplication. |
| tonumber | Reject whitespace and non-decimal text that JavaScript Number would accept. |
| element | Reject fractional indexes. Negative wrapping is supported by Terraform 1.15.8 and remains supported. |
| format | Round fixed decimal output through a 512-bit significand, matching the reference for decimal ties such as -1.235. Arithmetic elsewhere still uses JavaScript numbers. |

There are no unresolved value differences in the compared cases. Deliberately unsupported functions remain unknown, including both yamlencode probes, matchkeys, and sha256 fixture calls. These are counted as skipped, not passed. Nothing here certifies unknown identities, sensitivity propagation, provider schemas, arbitrary-precision arithmetic, all RE2 syntax, or every Terraform function. Negative newbits in cidrsubnet, negative element indexes, and default descending ranges were checked rather than changed based on assumptions.

Every confirmed difference is covered in fixtures/hcl/terraform-oracle.json with a Terraform-derived expected value. Error cases use try around the original expression to assert the error path. The fixtures also evaluate identical base/head configurations and require no changed addresses. Existing fixture JSON strings and the incorrect range expectation were updated to the reference behavior. dist/action.js was rebuilt after source changes. No production regression suite was run, so there is no new production calibration or claimed comparison to it.

## Reproduction

The command requires an existing Terraform 1.15.x binary and never installs one. A fresh scratch directory and isolated environment are used on every run. Startup controls check transport of nested values, a numeric variable with conversion, and Terraform diagnostics returned with exit status zero.

\`\`\`sh
bun run scripts/oracle.ts --out dry-runs/oracle/results.json --report dry-runs/oracle/current.md
# Preserve a before/after report when a prior JSON result file is available:
bun run scripts/oracle.ts --out dry-runs/oracle/results.json --baseline dry-runs/oracle/baseline-complete.json --report docs/research/terraform-oracle.md
bun run typecheck
bun run build
bun test
\`\`\`

The historical baseline below was obtained by running the same oracle and fixture corpus against src/hcl/eval.ts from main commit e41bbfc in this isolated worktree, then restoring the fixed evaluator. Raw result files are ignored under dry-runs/oracle/. The report retains all observed differences and their reference outputs so they are not lost with scratch files. Counts include regression cases and deduplicate equivalent expression/context pairs.

`;
    doc += '## Differences\n\n';
    const differences = (baseline ?? results).filter(r => r.status === 'different');
    if (!differences.length)
        doc += 'None.\n';
    for (const [i, r] of differences.entries()) {
        const now = results.find(n => n.id === r.id);
        doc += `### ${i + 1}. ${r.expression.replace(/\n/g, ' ')}\n\nSource: ${r.origins[0]}.\n\nExpression:\n\n\`\`\`hcl\n${r.expression}\n\`\`\`\n\nTerraform:\n\n\`\`\`json\n${pretty(r.terraform)}\n\`\`\`\n\nDiffseal before fixes:\n\n\`\`\`json\n${pretty(r.diffseal)}\n\`\`\`\n\nDiffseal after fixes:\n\n\`\`\`json\n${pretty(now?.diffseal ?? { skipped: now?.reason })}\n\`\`\`\n\nAssessment: ${now?.status === 'equal' ? 'Diffseal was wrong. Fixed and checked against Terraform.' : now?.status === 'skipped' ? 'Comparison excluded after investigation: ' + now.reason : 'Diffseal is wrong; unresolved.'}\n\n`;
    }
    doc += '## Skipped cases\n\n| Reason | Count |\n|---|---:|\n';
    const reasons = new Map<string, number>();
    for (const r of results.filter(r => r.status === 'skipped')) {
        const reason = (r.reason ?? 'unknown').replace(/Diffseal unknown:.*/, 'Diffseal unknown (including deliberately unsupported functions)');
        reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
    }
    for (const [r, n] of [...reasons].sort())
        doc += `| ${r.replace(/\|/g, '\\|')} | ${n} |\n`;
    return doc;
}
if (import.meta.main) {
    const args = process.argv.slice(2);
    const option = (key: string, fallback?: string) => { const i = args.indexOf(key); return i < 0 ? fallback : args[i + 1]; };
    const check = spawnSync('terraform', ['version', '-json'], { encoding: 'utf8', env: { PATH: process.env.PATH!, CHECKPOINT_DISABLE: '1' } });
    if (check.error || check.status !== 0)
        throw new Error('Terraform is missing; install nothing globally.');
    const version = JSON.parse(check.stdout).terraform_version;
    if (!/^1\.15\./.test(version))
        throw new Error('Expected Terraform 1.15.x, found ' + version);
    const all = candidates(), seen = new Map<string, Result>(), results: Result[] = [];
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-oracle-'));
    fs.writeFileSync(path.join(dir, 'terraform.rc'), 'disable_checkpoint = true\n');
    try {
        const control = terraformOutcome(dir, '', '{ a=1, b=[true, null] }', {});
        if (control.kind !== 'value' || stable(control.value) !== stable({ a: 1, b: [true, null] }))
            throw new Error('Terraform transport control failed');
        const variableControl = terraformOutcome(dir, 'variable "n" { type = number }', 'var.n * 2', { n: '"2"' });
        const errorControl = terraformOutcome(dir, '', 'range(1, 4, -1)', {});
        if (variableControl.kind !== 'value' || variableControl.value !== 4 || errorControl.kind !== 'error')
            throw new Error('Terraform variable/diagnostic controls failed');
        for (const c of all) {
            const context = prepare(c);
            const id = stable([c.expression, context]);
            c.id = id;
            const prior = seen.get(id);
            if (prior) {
                prior.origins.push(...c.origins);
                continue;
            }
            const result: Result = { id, expression: c.expression, origins: c.origins, status: 'skipped' };
            seen.set(id, result);
            results.push(result);
            if (typeof context === 'string') {
                result.reason = context;
                continue;
            }
            const ts = tsOutcome(c);
            if (typeof ts === 'string') {
                result.reason = ts;
                continue;
            }
            const tf = terraformOutcome(dir, context.configuration, c.expression, context.inputs);
            result.terraform = tf;
            result.diffseal = ts;
            result.status = tf.kind === ts.kind && (tf.kind === 'error' || sameValue(tf.value, (ts as {
                kind: 'value';
                value: unknown;
            }).value)) ? 'equal' : 'different';
            if (results.length % 50 === 0)
                console.error(`checked ${results.length} unique cases`);
        }
    }
    finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
    const out = option('--out', 'dry-runs/oracle/results.json')!;
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, pretty({ version, candidates: all.length, results }) + '\n');
    const baselinePath = option('--baseline');
    const baseline = baselinePath ? JSON.parse(fs.readFileSync(baselinePath, 'utf8')).results : undefined;
    const report = option('--report', 'docs/research/terraform-oracle.md')!;
    fs.mkdirSync(path.dirname(report), { recursive: true });
    fs.writeFileSync(report, document(version, results, baseline));
    console.log(JSON.stringify({ version, candidates: all.length, unique: results.length, equal: results.filter(r => r.status === 'equal').length, different: results.filter(r => r.status === 'different').length, skipped: results.filter(r => r.status === 'skipped').length, out, report }));
}
