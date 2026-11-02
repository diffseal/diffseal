import * as path from 'node:path';
import { UNKNOWN_PART, Unknown, hasRedacted, isRedacted, isUnknown, reveal, type Attrs, type SourceRef } from '../core/model.js';
import type { Block, Body, Expr } from '../hcl/ast.js';
import { EvalError, LazyMap, ResourceValue, childScope, containsUnknown, evaluate, identifyUnknown, isTfSet, markSet, redact, stableKey, toPlain, type EvalScope } from '../hcl/eval.js';
import { parseHcl } from '../hcl/parser.js';
import { loadModule, type ModuleCall, type ModuleConfig, type ResourceBlock } from './config.js';
import { normalize, type FileSource } from './source.js';

/** A resource or data source instance after static evaluation. */
export interface StaticInstance {
  address: string;
  configAddress: string;
  type: string;
  name: string;
  mode: 'managed' | 'data';
  moduleAddress?: string;
  attrs: Attrs;
  /** Values evaluated without erasing null/unknown dependencies. Used only for policy evidence. */
  configuredAttrs?: Attrs;
  /** Top-level attribute or block type -> referenced resource addresses (config addresses). */
  references: Record<string, string[]>;
  source: SourceRef;
  preventDestroy: boolean;
  /** Selected provider configuration and its statically known account constraints. */
  providerAddress?: string;
  providerAccounts?: string[];
  createBeforeDestroy: boolean;
  /** Attribute paths excluded from comparison: `[["tags"], ["ingress", 0, "description"]]`, or every attribute. */
  ignoreChanges: Array<Array<string | number>> | 'all';
  /** Set for calls to registry or git modules, whose resources cannot be seen offline. */
  externalModule?: { source?: string; version?: string };
  /** lifecycle replace_triggered_by, resolved for this instance (count.index and each.key applied). */
  replaceTriggeredBy?: ReplaceTrigger[];
  /**
   * For a symbolic instance (`[*]`), the identity of the count or for_each value that is not known
   * statically, so a changed expression (`var.n` to `var.n - 1`) is a change. Never printed.
   */
  expansion?: string;
}

/**
 * One entry of replace_triggered_by: a managed resource, one of its instances, or an attribute of an
 * instance. Terraform replaces the resource when the referenced resource or instance is updated or
 * replaced, or when the referenced attribute's value changes.
 */
export interface ReplaceTrigger {
  /** Module-qualified address: `aws_x.y` for every instance, `aws_x.y[0]` for one. */
  address: string;
  /** True when the reference names one instance (or the resource has no count/for_each). */
  instance: boolean;
  /** Attribute path after the instance, when the reference names an attribute. */
  attr?: string[];
  /** As written, for the report. */
  label: string;
}

export interface RootEvaluation {
  root: string;
  instances: StaticInstance[];
  /** Module-qualified moved/removed/import addresses. */
  moved: Array<{ from: string; to: string }>;
  removed: Array<{ from: string; destroy: boolean }>;
  imports: string[];
  diagnostics: string[];
  /** AWS accounts the root's provider targets, when configured literally. */
  accounts: string[];
  /** Repository paths read with file(), templatefile() and friends while evaluating. */
  readFiles: Set<string>;
  /** Config addresses of resource blocks with prevent_destroy, whether or not they expand to any instance. */
  preventDestroy: Set<string>;
}

const RESOURCE_META = new Set(['count', 'for_each', 'depends_on', 'provider', 'lifecycle', 'provisioner', 'connection']);
const MODULE_META = new Set(['source', 'version', 'count', 'for_each', 'providers', 'depends_on']);
const MAX_DEPTH = 25;

/**
 * Evaluate a root module. `varFiles` are repository paths passed as `-var-file`, in order; they take
 * precedence over terraform.tfvars and *.auto.tfvars, and `rootVars` over all of them.
 */
export function evaluateRoot(source: FileSource, rootDir: string, rootVars: Record<string, unknown> = {}, varFiles: string[] = []): RootEvaluation {
  const root = normalize(rootDir);
  const cfg = loadModule(source, root);
  const result: RootEvaluation = { root, instances: [], moved: [], removed: [], imports: [], diagnostics: [], accounts: [], readFiles: new Set(), preventDestroy: new Set() };
  if (!cfg) return result;
  result.accounts = [...new Set(cfg.providerAccounts)];

  const fromFiles = (evidence: boolean) => Object.assign({}, ...varFiles.map((f) => readVarFile(source, f, evidence, evidence ? undefined : result.diagnostics))) as Record<string, unknown>;
  const vars = { ...readTfvars(source, root, false, result.diagnostics), ...fromFiles(false), ...rootVars };
  const inputs = new Map<string, () => unknown>(Object.entries(vars).map(([k, v]) => [k, () => v]));
  const top = new ModuleInstance(source, cfg, '', '', inputs, new Map(), root, 0, result.readFiles);
  top.collect(result);
  const evidence: RootEvaluation = { ...result, instances: [], diagnostics: [], moved: [], removed: [], imports: [], preventDestroy: new Set() };
  const evidenceVars = { ...readTfvars(source, root, true), ...fromFiles(true), ...rootVars };
  const evidenceInputs = new Map<string, () => unknown>(Object.entries(evidenceVars).map(([k, v]) => [k, () => v]));
  new ModuleInstance(source, cfg, '', '', evidenceInputs, new Map(), root, 0, result.readFiles, undefined, true).collect(evidence);
  const byAddress = new Map(evidence.instances.map((i) => [i.address, i.attrs]));
  for (const instance of result.instances) instance.configuredAttrs = byAddress.get(instance.address) ?? {};
  return result;
}

function readTfvars(source: FileSource, root: string, configurationEvidence = false, diagnostics?: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  // Terraform loads terraform.tfvars(.json) first, then *.auto.tfvars(.json) in lexical order; later files win.
  const names = source.listFiles(root);
  const files = [
    ...['terraform.tfvars', 'terraform.tfvars.json'].filter((f) => names.includes(f)),
    ...names.filter((f) => f.endsWith('.auto.tfvars') || f.endsWith('.auto.tfvars.json')).sort(),
  ];
  for (const f of files) Object.assign(out, readVarFile(source, path.posix.join(root, f), configurationEvidence, diagnostics));
  return out;
}

/** The variables a tfvars file sets. An unreadable file leaves its variables unset (unknown), never guessed. */
export function readVarFile(source: FileSource, file: string, configurationEvidence = false, diagnostics?: string[]): Record<string, unknown> {
  const raw = source.readFile(file);
  if (raw === undefined) {
    diagnostics?.push(`${file}:1: ${source.linkProblem?.(file) ?? 'the var-file cannot be read'}`);
    return {};
  }
  const text = raw;
  if (file.endsWith('.json')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
      diagnostics?.push(`${file}:1: a JSON var-file must hold an object`);
      return {};
    } catch {
      // The parser's message can quote the file, and a var-file may hold secrets.
      diagnostics?.push(`${file}:1: the var-file is not valid JSON`);
      return {};
    }
  }
  const out: Record<string, unknown> = {};
  const { body, diagnostics: parsed } = parseHcl(text, file);
  // Content-free: a var-file may hold secrets, and parser messages can quote the text.
  for (const d of parsed) diagnostics?.push(`${file}:${d.range.start.line}: the var-file does not parse here`);
  for (const a of body.attributes) out[a.name] = toPlain(evaluate(a.expr, { root: () => undefined, configurationEvidence }));
  return out;
}

interface Expansion {
  key: string;
  vars: Record<string, unknown>;
}

/** count / for_each -> instance keys and the each/count variables for each instance. */
function expand(body: Body, scope: EvalScope): Expansion[] | Unknown {
  const count = body.attributes.find((a) => a.name === 'count');
  const forEach = body.attributes.find((a) => a.name === 'for_each');
  if (count) {
    // Terraform accepts a sensitive count and converts a numeric string, as for any number argument.
    const raw = reveal(evaluate(count.expr, scope));
    const n = typeof raw === 'string' && /^\s*\d+\s*$/.test(raw) ? Number(raw) : raw;
    if (isUnknown(n) || typeof n !== 'number' || !Number.isInteger(n) || n < 0) {
      return identifyUnknown(new Unknown('count is not known statically', undefined, isUnknown(n) ? n.refs : []), `count:${stableKey(n)}`);
    }
    return Array.from({ length: n }, (_, i) => ({ key: `[${i}]`, vars: { count: { index: i } } }));
  }
  if (forEach) {
    const v = toPlain(evaluate(forEach.expr, scope));
    if (isUnknown(v) || containsUnknownKeys(v)) {
      return identifyUnknown(new Unknown('for_each is not known statically', undefined, isUnknown(v) ? v.refs : []), `for_each:${stableKey(v)}`);
    }
    // Terraform refuses a sensitive for_each; its instances cannot be named.
    if (isRedacted(v)) return new Unknown('for_each is sensitive');
    if (Array.isArray(v)) {
      return v.map((item) => ({ key: `[${JSON.stringify(String(item))}]`, vars: { each: { key: item, value: item } } }));
    }
    if (v && typeof v === 'object') {
      return Object.keys(v).sort().map((k) => ({ key: `[${JSON.stringify(k)}]`, vars: { each: { key: k, value: (v as Attrs)[k] } } }));
    }
    return new Unknown('for_each is not a map or set');
  }
  return [{ key: '', vars: {} }];
}

function containsUnknownKeys(v: unknown): boolean {
  if (Array.isArray(v)) return v.some((x) => isUnknown(x) || typeof x === 'object');
  return false;
}

/** Symbolic single instance used when count/for_each cannot be resolved. */
const SYMBOLIC: Expansion = {
  key: '[*]',
  vars: {
    count: { index: new Unknown('count.index') },
    each: { key: new Unknown('each.key'), value: new Unknown('each.value') },
  },
};

interface ProviderBinding {address:string;accounts:string[];}
function providerName(expr:Expr|undefined):string|undefined {
 if(!expr)return;
 if(expr.kind==='scope')return expr.name;
 if(expr.kind==='getattr'){const base=providerName(expr.obj);return base?base+'.'+expr.name:undefined;}
 if(expr.kind==='paren')return providerName(expr.expr);
 if(expr.kind==='literal'&&typeof expr.value==='string')return expr.value;
 if(expr.kind==='template'&&expr.parts.every(p=>p.kind==='text'))return expr.parts.map(p=>p.kind==='text'?p.value:'').join('');
}

interface ChildModule {
  call: ModuleCall;
  instances: Array<{ key: string; mod: ModuleInstance }> | Unknown;
  /** For a call with no instances: a symbolic instance whose lifecycle guards still apply. */
  dormant?: ModuleInstance;
}

class ModuleInstance {
  readonly scope: EvalScope;
  private readonly reads?: Set<string>;
  private readonly roots = new Map<string, unknown>();
  private readonly resourceValues = new Map<string, LazyMap>();
  private readonly refMemo = new Map<string, string[]>();
  private readonly refInProgress = new Set<string>();
  private providerMemo?: Map<string, ProviderBinding>;
  /** Module calls instantiated so far, each on first use, so one call's for_each never waits on another. */
  private readonly children = new Map<string, ChildModule>();
  private readonly childrenInProgress = new Set<string>();

  constructor(
    private readonly source: FileSource,
    readonly cfg: ModuleConfig,
    /** Instance path, e.g. `module.a["x"].` (with trailing dot) or ''. */
    readonly prefix: string,
    /** Config path without instance keys, e.g. `module.a.`. */
    readonly cfgPrefix: string,
    private readonly inputs: Map<string, () => unknown>,
    private readonly inputRefs: Map<string, () => string[]>,
    private readonly rootDir: string,
    private readonly depth: number,
    reads?: Set<string>,
    private readonly inheritedProviders?: Map<string,ProviderBinding>,
    private readonly configurationEvidence = false
  ) {
    const self = this;
    this.reads = reads;
    this.scope = {
      configurationEvidence,
      root(name) {
        return self.rootValue(name);
      },
      // Terraform resolves relative paths against the root module's directory; path.module gives repo paths.
      // Relative paths resolve from the root module's directory, Terraform's working directory.
      readFile(p) {
        if (p.startsWith('/')) return undefined;
        const candidate = normalize(path.posix.join(rootDir, p));
        if (candidate === '..' || candidate.startsWith('../')) return undefined;
        reads?.add(candidate);
        return source.readFile(candidate);
      },
    };
  }

  private providers():Map<string,ProviderBinding> {
    if(this.providerMemo)return this.providerMemo;
    const out=new Map(this.inheritedProviders??[['aws',{address:`${this.rootDir}::aws`,accounts:[]}]]);
    this.providerMemo=out;
    for(const [name,block] of this.cfg.providers){
      const attr=(n:string)=>block.body.attributes.find(a=>a.name===n);
      const allowed=attr('allowed_account_ids');
      const raw=allowed?reveal(toPlain(evaluate(allowed.expr,this.scope))):[];
      const accounts=Array.isArray(raw)?raw.filter((v):v is string=>typeof v==='string'&&/^\d{12}$/.test(v)):[];
      const assume=block.body.blocks.find(b=>b.type==='assume_role')?.body.attributes.find(a=>a.name==='role_arn');
      const arn=assume?reveal(evaluate(assume.expr,this.scope)):undefined;
      const account=typeof arn==='string'?arn.match(/^arn:aws[\w-]*:iam::(\d{12}):/)?.[1]:undefined;
      out.set(name,{address:`${this.rootDir}::${this.prefix}${name}`,accounts:account?[account]:[...new Set(accounts)]});
    }
    return out;
  }

  private resourceProvider(rb:ResourceBlock):Partial<Pick<StaticInstance,'providerAddress'|'providerAccounts'>> {
    if(!rb.type.startsWith('aws_'))return {};
    const name=providerName(rb.block.body.attributes.find(a=>a.name==='provider')?.expr)??'aws';
    const binding=this.providers().get(name);
    return {providerAddress:binding?.address??`${this.rootDir}::${this.prefix}${name}`,providerAccounts:binding?.accounts??[]};
  }

  private childProviders(call:ModuleCall):Map<string,ProviderBinding> {
    const parent=this.providers();
    const mapping=call.block.body.attributes.find(a=>a.name==='providers')?.expr;
    if(!mapping)return new Map([...parent].filter(([name])=>!name.includes('.')));
    const out=new Map<string,ProviderBinding>();
    if(mapping.kind==='object')for(const item of mapping.items){
      const child=providerName(item.key),selected=providerName(item.value);
      if(child&&selected){const binding=parent.get(selected);out.set(child,binding??{address:`${this.rootDir}::${this.prefix}${selected}`,accounts:[]});}
    }
    return out;
  }

  private rootValue(name: string): unknown {
    if (this.roots.has(name)) return this.roots.get(name);
    let v: unknown;
    switch (name) {
      case 'var':
        v = new LazyMap(
          new Map(
            [...this.cfg.variables.entries()].map(([k, block]) => [
              k,
              () => {
                const attr = (n: string) => block.body.attributes.find((a) => a.name === n);
                const literalFalse = (n: string) => { const a = attr(n); return a?.expr.kind === 'literal' && a.expr.value === false; };
                const literalTrue = (n: string) => { const a = attr(n); return a?.expr.kind === 'literal' && a.expr.value === true; };
                const input = this.inputs.get(k);
                let value: unknown;
                // An explicit null stays null unless the variable says nullable = false.
                if (input) value = input();
                if (this.configurationEvidence && input && value === null && literalFalse('nullable')) return new Unknown('variable input passed through null');
                if (!input || (value === null && literalFalse('nullable'))) {
                  const def = attr('default');
                  value = def ? toPlain(evaluate(def.expr, this.scope)) : input ? null : new Unknown(`variable "${k}" has no value in this configuration`);
                }
                const type = attr('type');
                if (type) value = convertType(type.expr, typeDefaults(type.expr, value, this.scope));
                return literalTrue('sensitive') ? redact(value) : value;
              },
            ])
          )
        );
        break;
      case 'local':
        v = new LazyMap(new Map([...this.cfg.locals.entries()].map(([k, l]) => [k, () => evaluate(l.attr.expr, this.scope)])));
        break;
      case 'path':
        // As in Terraform: relative to the root module's directory, which is the working directory.
        v = { module: path.posix.relative(this.rootDir, this.cfg.dir) || '.', root: '.', cwd: '.' };
        break;
      case 'terraform':
        v = { workspace: 'default' };
        break;
      case 'module':
        v = new LazyMap(new Map([...this.cfg.moduleCalls.keys()].map((k) => [k, () => this.moduleValue(k)])));
        break;
      case 'data': {
        const byType = new Map<string, Map<string, () => unknown>>();
        for (const rb of this.cfg.data.values()) {
          const m = byType.get(rb.type) ?? new Map();
          m.set(rb.name, () => this.blockValue(rb));
          byType.set(rb.type, m);
        }
        v = new LazyMap(new Map([...byType.entries()].map(([t, m]) => [t, () => new LazyMap(m)])));
        break;
      }
      default: {
        const byName = this.resourcesOfType(name);
        v = byName;
      }
    }
    if (v !== undefined) this.roots.set(name, v);
    return v;
  }

  private resourcesOfType(type: string): LazyMap | undefined {
    if (this.resourceValues.has(type)) return this.resourceValues.get(type);
    const thunks = new Map<string, () => unknown>();
    for (const rb of this.cfg.resources.values()) if (rb.type === type) thunks.set(rb.name, () => this.blockValue(rb));
    if (!thunks.size) return undefined;
    const lm = new LazyMap(thunks);
    this.resourceValues.set(type, lm);
    return lm;
  }

  private address(rb: ResourceBlock, key: string): string {
    return `${this.prefix}${rb.mode === 'data' ? 'data.' : ''}${rb.type}.${rb.name}${key}`;
  }

  private configAddress(rb: ResourceBlock): string {
    return `${this.cfgPrefix}${rb.mode === 'data' ? 'data.' : ''}${rb.type}.${rb.name}`;
  }

  private readonly valueMemo = new Map<string, ResourceValue>();

  private instanceValue(rb: ResourceBlock, exp: Expansion): ResourceValue {
    const address = this.address(rb, exp.key);
    const memo = this.valueMemo.get(address);
    if (memo) return memo;
    const scope = childScope(this.scope, exp.vars);
    let attrs: Attrs | undefined;
    let evaluating = false;
    const getAttrs = () => {
      if (attrs) return attrs;
      if (evaluating) return {};
      evaluating = true;
      attrs = evalBody(rb.block.body, scope, RESOURCE_META);
      if (rb.mode === 'data' && rb.type === 'aws_iam_policy_document') attrs.json = policyDocumentJson(attrs);
      evaluating = false;
      return attrs;
    };
    const rv = new ResourceValue(address, getAttrs, (name) => this.configurationEvidence ? undefined : computedAttr(rb, name, getAttrs, address));
    this.valueMemo.set(address, rv);
    return rv;
  }

  /** The value of `type.name` as seen by expressions: one instance, a list (count), a map (for_each), or unknown. */
  private blockValue(rb: ResourceBlock): unknown {
    const exps = expand(rb.block.body, this.scope);
    if (isUnknown(exps)) return new Unknown(exps.reason, UNKNOWN_PART, [this.configAddress(rb)]);
    const hasCount = rb.block.body.attributes.some((a) => a.name === 'count');
    const hasForEach = rb.block.body.attributes.some((a) => a.name === 'for_each');
    if (hasCount) return exps.map((e) => this.instanceValue(rb, e));
    if (hasForEach) return Object.fromEntries(exps.map((e) => [(e.vars.each as Attrs).key as string, this.instanceValue(rb, e)]));
    return this.instanceValue(rb, exps[0]);
  }

  /**
   * The instances of one module call, made on first use. Expanding every call at once made a reference
   * to one module evaluate the count or for_each of all the others, which could read the local still
   * being evaluated and turn a known for_each into a false reference cycle.
   */
  private childModule(name: string): ChildModule | undefined {
    const hit = this.children.get(name);
    if (hit) return hit;
    const call = this.cfg.moduleCalls.get(name);
    if (!call || this.childrenInProgress.has(name)) return undefined;
    const childCfg = call.localDir && this.depth < MAX_DEPTH ? loadModule(this.source, call.localDir) : undefined;
    if (!childCfg) {
      const entry = { call, instances: new Unknown(`module "${call.name}" (${call.source ?? 'unknown source'}) is not available offline`) };
      this.children.set(name, entry);
      return entry;
    }
    this.childrenInProgress.add(name);
    try {
      let exps = expand(call.block.body, this.scope);
      if (isUnknown(exps)) exps = [SYMBOLIC];
      const instantiate = (exp: Expansion) => {
        const scope = childScope(this.scope, exp.vars);
        const args = call.block.body.attributes.filter((a) => !MODULE_META.has(a.name));
        const inputs = new Map(args.map((a) => [a.name, () => evaluate(a.expr, scope)] as const));
        const inputRefs = new Map(args.map((a) => [a.name, () => this.refsOf(a.expr)] as const));
        const mod = new ModuleInstance(
          this.source,
          childCfg,
          `${this.prefix}module.${call.name}${exp.key}.`,
          `${this.cfgPrefix}module.${call.name}.`,
          inputs,
          inputRefs,
          this.rootDir,
          this.depth + 1,
          this.reads,
          this.childProviders(call),
          this.configurationEvidence
        );
        return { key: exp.key, mod };
      };
      const instances = exps.map(instantiate);
      const entry: ChildModule = { call, instances, ...(instances.length ? {} : { dormant: instantiate(SYMBOLIC).mod }) };
      this.children.set(name, entry);
      return entry;
    } finally {
      this.childrenInProgress.delete(name);
    }
  }

  /** Every module call, in configuration order. */
  private childInstances(): ChildModule[] {
    return [...this.cfg.moduleCalls.keys()].map((name) => this.childModule(name)).filter((c): c is ChildModule => c !== undefined);
  }

  private moduleValue(name: string): unknown {
    if (this.childrenInProgress.has(name)) return new Unknown(`reference cycle through module "${name}"`);
    const child = this.childModule(name);
    if (!child) throw new EvalError(`no module "${name}"`);
    if (isUnknown(child.instances)) return new Unknown(child.instances.reason, UNKNOWN_PART, [`${this.cfgPrefix}module.${name}`]);
    const outputs = (mod: ModuleInstance) =>
      new LazyMap(new Map([...mod.cfg.outputs.entries()].map(([k, b]) => [k, () => {
        const value = b.body.attributes.find((a) => a.name === 'value');
        const sensitive = b.body.attributes.find((a) => a.name === 'sensitive');
        const v = value ? evaluate(value.expr, mod.scope) : null;
        return sensitive?.expr.kind === 'literal' && sensitive.expr.value === true ? redact(toPlain(v)) : v;
      }])));
    const call = child.call.block.body;
    if (child.instances.length === 1 && child.instances[0].key === '[*]') {
      return new Unknown(`module "${name}" instances are not known statically`, UNKNOWN_PART, [`${this.cfgPrefix}module.${name}`]);
    }
    if (call.attributes.some((a) => a.name === 'count')) return child.instances.map((i) => outputs(i.mod));
    if (call.attributes.some((a) => a.name === 'for_each')) {
      return Object.fromEntries(child.instances.map((i) => [JSON.parse(i.key.slice(1, -1)), outputs(i.mod)]));
    }
    return outputs(child.instances[0].mod);
  }

  // ---------------------------------------------------------------- references

  /** Resource addresses an expression depends on, following locals, variables and module outputs. */
  refsOf(expr: Expr): string[] {
    const out = new Set<string>();
    for (const chain of traversals(expr)) for (const r of this.resolveChain(chain)) out.add(r);
    return [...out];
  }

  private memoRefs(key: string, compute: () => string[]): string[] {
    if (this.refMemo.has(key)) return this.refMemo.get(key)!;
    if (this.refInProgress.has(key)) return [];
    this.refInProgress.add(key);
    const v = compute();
    this.refInProgress.delete(key);
    this.refMemo.set(key, v);
    return v;
  }

  private resolveChain(chain: string[]): string[] {
    const [root, a, b] = chain;
    if (root === 'data' && a && b) return [`${this.cfgPrefix}data.${a}.${b}`];
    if (root === 'local' && a) {
      const l = this.cfg.locals.get(a);
      return l ? this.memoRefs(`local.${a}`, () => this.refsOf(l.attr.expr)) : [];
    }
    if (root === 'var' && a) {
      const r = this.inputRefs.get(a);
      return r ? this.memoRefs(`var.${a}`, r) : [];
    }
    if (root === 'module' && a) {
      const child = this.childModule(a);
      if (!child || isUnknown(child.instances) || !child.instances.length || !b) return [`${this.cfgPrefix}module.${a}`];
      const mod = child.instances[0].mod;
      const output = mod.cfg.outputs.get(b);
      const value = output?.body.attributes.find((x) => x.name === 'value');
      return value ? this.memoRefs(`module.${a}.${b}`, () => mod.refsOf(value.expr)) : [];
    }
    if (a && this.cfg.resources.has(`${root}.${a}`)) return [`${this.cfgPrefix}${root}.${a}`];
    return [];
  }

  // ---------------------------------------------------------------- instances

  collect(result: RootEvaluation, lifecycleOnly = false) {
    for (const d of this.cfg.diagnostics) result.diagnostics.push(`${d.file}:${d.range.start.line}: ${d.message}`);
    const qualify = (addr: string) => `${this.prefix}${addr}`;
    if (!lifecycleOnly) for (const m of this.cfg.moved) result.moved.push({ from: qualify(m.from), to: qualify(m.to) });
    if (!lifecycleOnly) for (const r of this.cfg.removed) result.removed.push({ from: qualify(r.from), destroy: r.destroy });
    if (!lifecycleOnly) for (const i of this.cfg.imports) result.imports.push(qualify(i.to));

    for (const rb of [...this.cfg.resources.values(), ...this.cfg.data.values()]) {
      const lifecycle = rb.block.body.blocks.find((b) => b.type === 'lifecycle');
      if (lifecycleFlag(lifecycle, 'prevent_destroy', this.scope)) result.preventDestroy.add(this.configAddress(rb));
      if (lifecycleOnly) continue;
      let exps = expand(rb.block.body, this.scope);
      const expansion = isUnknown(exps) ? stableKey(exps) : undefined;
      if (isUnknown(exps)) exps = [SYMBOLIC];
      const references = this.blockReferences(rb.block.body);
      for (const exp of exps) {
        const rv = this.instanceValue(rb, exp);
        const attrs = { ...(rv.entries() ? Object.fromEntries(rv.entries()) : {}) };
        result.instances.push({
          address: this.address(rb, exp.key),
          configAddress: this.configAddress(rb),
          type: rb.type,
          name: rb.name,
          mode: rb.mode,
          moduleAddress: this.prefix ? this.prefix.slice(0, -1) : undefined,
          attrs,
          references,
          source: { file: rb.file, line: rb.block.range.start.line },
          preventDestroy: lifecycleFlag(lifecycle, 'prevent_destroy', this.scope),
          ...this.resourceProvider(rb),
          createBeforeDestroy: lifecycleFlag(lifecycle, 'create_before_destroy', this.scope),
          ignoreChanges: ignoreChanges(lifecycle),
          ...this.replaceTriggers(lifecycle, exp),
          ...(expansion ? { expansion } : {}),
        });
      }
    }

    const children = this.childInstances();
    for (const { call, instances } of children) {
      if (isUnknown(instances)) {
        if (lifecycleOnly) continue;
        const args = call.block.body.attributes.filter((a) => !MODULE_META.has(a.name));
        const attrs: Attrs = { source: call.source ?? null, version: call.version ?? null };
        // Instances of an unavailable module: changing count or for_each adds or removes all of its resources.
        for (const meta of ['count', 'for_each']) {
          const a = call.block.body.attributes.find((x) => x.name === meta);
          if (a) attrs[meta] = toPlain(evaluate(a.expr, this.scope));
        }
        const references: Record<string, string[]> = {};
        for (const a of args) {
          attrs[a.name] = toPlain(evaluate(a.expr, this.scope));
          const r = this.refsOf(a.expr);
          if (r.length) references[a.name] = r;
        }
        result.instances.push({
          address: `${this.prefix}module.${call.name}`,
          configAddress: `${this.cfgPrefix}module.${call.name}`,
          type: 'terraform_module_call',
          name: call.name,
          mode: 'managed',
          moduleAddress: this.prefix ? this.prefix.slice(0, -1) : undefined,
          attrs,
          references,
          source: { file: call.file, line: call.block.range.start.line },
          preventDestroy: false,
          createBeforeDestroy: false,
          ignoreChanges: [],
          externalModule: { source: call.source, version: call.version },
          providerAddress: this.childProviders(call).get('aws')?.address,
          providerAccounts: this.childProviders(call).get('aws')?.accounts ?? [],
        });
        continue;
      }
      for (const { mod } of instances) mod.collect(result,lifecycleOnly);
    }
    for (const { dormant } of children) dormant?.collect(result,true);
  }

  private replaceTriggers(lifecycle: Block | undefined, exp: Expansion): { replaceTriggeredBy?: ReplaceTrigger[] } {
    const attr = lifecycle?.body.attributes.find((a) => a.name === 'replace_triggered_by');
    if (!attr) return {};
    const scope = childScope(this.scope, exp.vars);
    const items = attr.expr.kind === 'tuple' ? attr.expr.items : [attr.expr];
    const out: ReplaceTrigger[] = [];
    for (const item of items) {
      const chain = triggerChain(item, scope);
      if (!chain || typeof chain[0] !== 'string' || typeof chain[1] !== 'string') continue;
      // Only managed resources can trigger a replacement.
      const rb = this.cfg.resources.get(`${chain[0]}.${chain[1]}`);
      if (!rb) continue;
      const keyed = chain[2] !== undefined && typeof chain[2] !== 'string';
      const key = keyed ? (chain[2] as { key: unknown }).key : undefined;
      const known = keyed && (typeof key === 'number' || typeof key === 'string');
      const multi = rb.block.body.attributes.some((a) => a.name === 'count' || a.name === 'for_each');
      const base = `${this.prefix}${rb.type}.${rb.name}`;
      const address = known ? `${base}[${typeof key === 'number' ? key : JSON.stringify(key)}]` : base;
      const rest = chain.slice(keyed ? 3 : 2).map((x) => (typeof x === 'string' ? x : String((x as { key: unknown }).key)));
      out.push({ address, instance: known || !multi, ...(rest.length ? { attr: rest } : {}), label: address + (rest.length ? `.${rest.join('.')}` : '') });
    }
    return out.length ? { replaceTriggeredBy: out } : {};
  }

  private blockReferences(body: Body): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    const add = (key: string, refs: string[]) => {
      if (!refs.length) return;
      out[key] = [...new Set([...(out[key] ?? []), ...refs])];
    };
    for (const a of body.attributes) if (!RESOURCE_META.has(a.name) || a.name === 'for_each' || a.name === 'count') add(a.name, this.refsOf(a.expr));
    for (const b of body.blocks) {
      if (b.type === 'lifecycle') continue;
      const key = b.type === 'dynamic' ? b.labels[0] ?? 'dynamic' : b.type;
      add(key, Object.values(this.blockReferences(b.body)).flat());
    }
    return out;
  }
}

function lifecycleFlag(lifecycle: Block | undefined, name: string, scope: EvalScope): boolean {
  const a = lifecycle?.body.attributes.find((x) => x.name === name);
  return a ? evaluate(a.expr, scope) === true : false;
}

function ignoreChanges(lifecycle: Block | undefined): Array<Array<string | number>> | 'all' {
  const a = lifecycle?.body.attributes.find((x) => x.name === 'ignore_changes');
  if (!a) return [];
  if (a.expr.kind === 'scope' && a.expr.name === 'all') return 'all';
  if (a.expr.kind !== 'tuple') return [];
  return a.expr.items.flatMap((i) => {
    const p = ignorePath(i);
    return p ? [p] : [];
  });
}

/** `ingress[0].description` -> ["ingress", 0, "description"]; a non-literal index ends the path there. */
function ignorePath(e: Expr): Array<string | number> | undefined {
  if (e.kind === 'scope') return [e.name];
  if (e.kind === 'template' && e.parts.length === 1 && e.parts[0].kind === 'text') return [e.parts[0].value];
  if (e.kind === 'getattr') {
    const inner = ignorePath(e.obj);
    return inner ? [...inner, e.name] : undefined;
  }
  if (e.kind === 'index') {
    const inner = ignorePath(e.obj);
    if (!inner) return undefined;
    if (e.key.kind === 'literal' && (typeof e.key.value === 'number' || typeof e.key.value === 'string')) return [...inner, e.key.value];
    if (e.key.kind === 'template' && e.key.parts.length === 1 && e.key.parts[0].kind === 'text') return [...inner, e.key.parts[0].value];
    return inner;
  }
  return undefined;
}

/** Evaluate a block body into plan-JSON-shaped attributes: nested blocks become lists of objects. */
function evalBody(body: Body, scope: EvalScope, skip: Set<string>): Attrs {
  const out: Attrs = {};
  for (const a of body.attributes) {
    if (skip.has(a.name)) continue;
    out[a.name] = toPlain(evaluate(a.expr, scope));
  }
  for (const b of body.blocks) {
    if (skip.has(b.type)) continue;
    if (b.type === 'dynamic') {
      const label = b.labels[0];
      if (!label) continue;
      const forEach = b.body.attributes.find((a) => a.name === 'for_each');
      const iteratorAttr = b.body.attributes.find((a) => a.name === 'iterator');
      const iterator = iteratorAttr?.expr.kind === 'scope' ? iteratorAttr.expr.name : label;
      const content = b.body.blocks.find((x) => x.type === 'content');
      if (!forEach || !content) continue;
      let coll = toPlain(evaluate(forEach.expr, scope));
      // A sensitive collection is expanded by its values; each generated value stays sensitive.
      let sensitive = false;
      if (isRedacted(coll) && coll.revealed) {
        sensitive = true;
        coll = toPlain(coll.revealed.value);
      }
      if (isRedacted(coll)) coll = new Unknown(`dynamic "${label}" over a sensitive collection that is not available`);
      if (isUnknown(coll)) {
        // Keep blocks written before it; the unknown ones are an Unknown element, not an empty list.
        const list = (Array.isArray(out[label]) ? out[label] : []) as unknown[];
        // Its identity is the collection and the content evaluated with placeholder elements, so editing
        // the content (a CIDR) is a change although the collection is not known.
        const placeholder = { [iterator]: { key: new Unknown('key'), value: new Unknown('element') } };
        let contentKey: string;
        try {
          contentKey = stableKey(evalBody(content.body, childScope(scope, placeholder), new Set()));
        } catch {
          contentKey = '?';
        }
        list.push(identifyUnknown(new Unknown(`dynamic "${label}" over a collection not known statically`, undefined, coll.refs), `dynamic:${label}:${stableKey(coll)}:${contentKey}`));
        out[label] = list;
        continue;
      }
      // A set's iterator key is the element itself, as in Terraform.
      const items: Array<[unknown, unknown]> = isTfSet(coll)
        ? coll.map((v) => [v, v])
        : Array.isArray(coll)
        ? coll.map((v, i) => [i, v])
        : coll && typeof coll === 'object'
          ? Object.keys(coll).sort().map((k) => [k, (coll as Attrs)[k]])
          : [];
      const list = (out[label] as Attrs[] | undefined) ?? [];
      for (const [k, v] of items) {
        const it = sensitive ? { key: redact(k), value: redact(v) } : { key: k, value: v };
        list.push(evalBody(content.body, childScope(scope, { [iterator]: it }), new Set()));
      }
      out[label] = list;
      continue;
    }
    const list = (Array.isArray(out[b.type]) ? out[b.type] : []) as Attrs[];
    list.push(evalBody(b.body, scope, new Set()));
    out[b.type] = list;
  }
  return out;
}

/** Provider-computed attributes that can be derived from configuration. */
function computedAttr(rb: ResourceBlock, name: string, attrs: () => Attrs, address: string): unknown {
  if (rb.mode === 'data' && rb.type === 'aws_iam_policy_document' && (name === 'json' || name === 'minified_json')) {
    return attrs().json;
  }
  if (rb.type === 'aws_s3_bucket' && (name === 'id' || name === 'bucket')) {
    const b = attrs().bucket;
    if (typeof b === 'string') return b;
  }
  if ((rb.type === 'aws_sqs_queue' || rb.type === 'aws_sns_topic' || rb.type === 'aws_iam_role' || rb.type === 'aws_lambda_function') && name === 'name') {
    const n = attrs()[rb.type === 'aws_lambda_function' ? 'function_name' : 'name'];
    if (typeof n === 'string') return n;
  }
  void address;
  return undefined;
}

/** Build the JSON document an aws_iam_policy_document data source produces. Keeps objects when parts are unknown. */
export function policyDocumentJson(attrs: Attrs): unknown {
  // Provider semantics: statements from source documents first; this document's statements replace
  // source statements with the same Sid; override documents then replace by Sid or are appended.
  const merged: unknown[] = [];
  const bySid = new Map<string, number>();
  const put = (st: unknown, replace: boolean) => {
    const sid = st && typeof st === 'object' ? (st as Attrs).Sid : undefined;
    if (typeof sid === 'string' && sid && bySid.has(sid) && replace) {
      merged[bySid.get(sid)!] = st;
      return;
    }
    if (typeof sid === 'string' && sid) bySid.set(sid, merged.length);
    merged.push(st);
  };
  let sensitive = false;
  const statementsOf = (given: unknown): unknown[] => {
    // A list that is sensitive as a whole is unwrapped one level, like an operand; the result is sensitive.
    let docs = given;
    if (isRedacted(docs) && docs.revealed) {
      sensitive = true;
      docs = docs.revealed.value;
    }
    return (Array.isArray(docs) ? docs : docs ? [docs] : []).flatMap((given) => {
      // A sensitive document is merged by its content; the merged document is sensitive too.
      const doc = hasRedacted(given) && !hasRedacted(reveal(given)) ? ((sensitive = true), reveal(given)) : given;
      const parsed = typeof doc === 'string' ? safeJson(doc) : doc;
      // An unknown document may allow or deny anything.
      if (isUnknown(doc) || isUnknown(parsed)) return [{ Effect: doc, Action: doc, Resource: doc, Principal: doc }];
      const st = (parsed as { Statement?: unknown })?.Statement;
      return Array.isArray(st) ? st : st ? [st] : [];
    });
  };

  for (const st of statementsOf(attrs.source_policy_documents)) put(st, false);
  for (const st of statementsOf(attrs.source_json)) put(st, false);
  // A dynamic statement over an unknown collection: any actions on any resources, for any principal.
  // Its effect is unknown too: it may be a Deny.
  if (isUnknown(attrs.statement)) put({ Effect: attrs.statement, Action: attrs.statement, Resource: attrs.statement, Principal: attrs.statement }, false);
  for (const s of (Array.isArray(attrs.statement) ? attrs.statement : []) as Attrs[]) {
    if (isUnknown(s)) {
      put({ Effect: s, Action: s, Resource: s, Principal: s }, false);
      continue;
    }
    const st: Attrs = { Effect: s.effect ?? 'Allow' };
    if (s.sid !== undefined) st.Sid = s.sid;
    if (s.actions !== undefined) st.Action = s.actions;
    if (s.not_actions !== undefined) st.NotAction = s.not_actions;
    if (s.resources !== undefined) st.Resource = s.resources;
    if (s.not_resources !== undefined) st.NotResource = s.not_resources;
    const principal = principalsOf(s.principals);
    if (principal !== undefined) st.Principal = principal;
    // not_principals: the statement applies to everyone except these (NotPrincipal).
    const notPrincipal = principalsOf(s.not_principals);
    if (notPrincipal !== undefined) st.NotPrincipal = notPrincipal;
    const conditions = (Array.isArray(s.condition) ? s.condition : []) as Attrs[];
    // A dynamic block over an unknown collection, or a test or variable not known statically, makes the
    // whole Condition unknown: it may or may not narrow the statement.
    const unknownCondition =
      conditions.find(isUnknown) ??
      (conditions.some((c) => typeof c.test !== 'string' || typeof c.variable !== 'string')
        ? new Unknown('condition operator or key not known statically', undefined, conditions.flatMap((c) => [c.test, c.variable]).filter(isUnknown).flatMap((u) => u.refs))
        : undefined);
    if (unknownCondition) {
      st.Condition = unknownCondition;
    } else if (conditions.length) {
      const c: Record<string, Attrs> = {};
      // Blocks with the same test and variable add up their values, as the provider appends them.
      for (const cond of conditions) {
        const test = String(cond.test);
        const variable = String(cond.variable);
        const prev = c[test]?.[variable];
        const values = prev === undefined ? cond.values : [...asList(prev), ...asList(cond.values)];
        c[test] = { ...(c[test] ?? {}), [variable]: values };
      }
      st.Condition = c;
    }
    put(st, true);
  }
  for (const st of statementsOf(attrs.override_policy_documents)) put(st, true);
  for (const st of statementsOf(attrs.override_json)) put(st, true);

  const doc = { Version: '2012-10-17', Statement: merged };
  const out = containsUnknown(doc) ? doc : JSON.stringify(doc);
  return sensitive ? redact(out) : out;
}

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : [v]);

/**
 * The Principal (or NotPrincipal) value of `principals` blocks: `"*"` for type `*`, otherwise type ->
 * identifiers, several blocks of one type adding up. A dynamic block over an unknown collection makes
 * the whole value unknown.
 */
function principalsOf(blocks: unknown): unknown {
  const list = (Array.isArray(blocks) ? blocks : []) as Attrs[];
  const unknown = list.find(isUnknown);
  if (unknown) return unknown;
  if (!list.length) return undefined;
  // A principal type not known statically: who the statement names is not known.
  const unknownType = list.find((pr) => typeof pr.type !== 'string');
  if (unknownType) return new Unknown('principal type not known statically', undefined, isUnknown(unknownType.type) ? unknownType.type.refs : []);
  const p: Attrs = {};
  for (const pr of list) {
    if (pr.type === '*') return '*';
    const prev = p[String(pr.type)];
    const ids = asList(pr.identifiers);
    p[String(pr.type)] = prev === undefined ? ids : [...asList(prev), ...ids];
  }
  return p;
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/** All maximal traversals (root, attr, attr...) in an expression; index keys are not part of the chain. */
function traversals(expr: Expr): string[][] {
  const out: string[][] = [];
  const visit = (e: Expr | undefined): void => {
    if (!e) return;
    const chain = traversalChain(e);
    if (chain) {
      out.push(chain);
      visitIndexKeys(e);
      return;
    }
    switch (e.kind) {
      case 'paren':
        return visit(e.expr);
      case 'template':
        for (const p of e.parts) visitPart(p);
        return;
      case 'tuple':
        return e.items.forEach(visit);
      case 'object':
        return e.items.forEach((i) => (visit(i.key), visit(i.value)));
      case 'getattr':
        return visit(e.obj);
      case 'index':
        return (visit(e.obj), visit(e.key));
      case 'splat':
        return (visit(e.obj), visit(e.each));
      case 'call':
        return e.args.forEach(visit);
      case 'for':
        return (visit(e.coll), visit(e.keyExpr), visit(e.valExpr), visit(e.cond));
      case 'unary':
        return visit(e.operand);
      case 'binary':
        return (visit(e.left), visit(e.right));
      case 'conditional':
        return (visit(e.cond), visit(e.then), visit(e.else));
    }
  };
  const visitPart = (p: import('../hcl/ast.js').TemplatePart) => {
    if (p.kind === 'interp') visit(p.expr);
    else if (p.kind === 'if') (visit(p.cond), p.then.forEach(visitPart), p.else.forEach(visitPart));
    else if (p.kind === 'for') (visit(p.coll), p.body.forEach(visitPart));
  };
  const visitIndexKeys = (e: Expr) => {
    if (e.kind === 'index') {
      visit(e.key);
      visitIndexKeys(e.obj);
    } else if (e.kind === 'getattr') visitIndexKeys(e.obj);
    else if (e.kind === 'splat') (visitIndexKeys(e.obj), visit(e.each));
  };
  visit(expr);
  return out;
}

/** `aws_x.y[count.index].attr` as ["aws_x", "y", { key: 1 }, "attr"], with index keys evaluated. */
function triggerChain(e: Expr, scope: EvalScope): Array<string | { key: unknown }> | undefined {
  if (e.kind === 'scope') return [e.name];
  if (e.kind === 'paren') return triggerChain(e.expr, scope);
  if (e.kind === 'getattr') {
    const inner = triggerChain(e.obj, scope);
    return inner ? [...inner, e.name] : undefined;
  }
  if (e.kind === 'index') {
    const inner = triggerChain(e.obj, scope);
    return inner ? [...inner, { key: evaluate(e.key, scope) }] : undefined;
  }
  return undefined;
}

function traversalChain(e: Expr): string[] | undefined {
  if (e.kind === 'scope') return [e.name];
  if (e.kind === 'getattr') {
    const inner = traversalChain(e.obj);
    return inner ? [...inner, e.name] : undefined;
  }
  if (e.kind === 'index') return traversalChain(e.obj);
  if (e.kind === 'splat') return traversalChain(e.obj);
  return undefined;
}

/**
 * Fill `optional(T, default)` attributes of an object type constraint that the value omits or sets
 * to null, through nested objects, maps and lists, as Terraform does when it converts a variable.
 */
function typeDefaults(type: Expr, v: unknown, scope: EvalScope): unknown {
  if (type.kind !== 'call') return v;
  // A sensitive value gets its defaults too, and stays sensitive.
  if (isRedacted(v)) return v.revealed ? redact(typeDefaults(type, v.revealed.value, scope)) : v;
  const [inner] = type.args;
  if (type.name === 'optional' && inner) return typeDefaults(inner, v, scope);
  const plain = (x: unknown): x is Attrs => Boolean(x) && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype;
  if (type.name === 'object' && inner?.kind === 'object') {
    if (!plain(v)) return v;
    const out: Attrs = { ...v };
    for (const item of inner.items) {
      const key = staticKey(item.key);
      if (key === undefined) continue;
      const at = item.value;
      if ((out[key] === undefined || out[key] === null) && at.kind === 'call' && at.name === 'optional') {
        out[key] = scope.configurationEvidence ? new Unknown('optional object attribute is null or unset')
          : at.args.length > 1 ? toPlain(evaluate(at.args[1], scope)) : null;
      }
      out[key] = typeDefaults(at, out[key], scope);
    }
    return out;
  }
  if (type.name === 'map' && inner && plain(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, typeDefaults(inner, x, scope)]));
  if ((type.name === 'list' || type.name === 'set') && inner && Array.isArray(v)) return v.map((x) => typeDefaults(inner, x, scope));
  return v;
}

/**
 * Convert a value to a variable's type constraint the way Terraform does for inputs: "1" to 1 for a
 * number, "true" to true for a bool, numbers and bools to strings for a string, through lists, sets
 * (deduplicated and sorted), maps, objects and tuples. A type it cannot read leaves the value alone.
 */
function convertType(type: Expr, v: unknown): unknown {
  if (v === null || v === undefined || isUnknown(v)) return v;
  if (isRedacted(v)) return v.revealed ? redact(convertType(type, v.revealed.value)) : v;
  if (type.kind === 'scope') {
    if (type.name === 'number' && typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
    if (type.name === 'bool' && (v === 'true' || v === 'false')) return v === 'true';
    if (type.name === 'string' && (typeof v === 'number' || typeof v === 'boolean')) return String(v);
    return v;
  }
  if (type.kind !== 'call') return v;
  const [inner] = type.args;
  const plain = (x: unknown): x is Attrs => Boolean(x) && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype;
  if (type.name === 'optional' && inner) return convertType(inner, v);
  if (type.name === 'list' && inner && Array.isArray(v)) return v.map((x) => convertType(inner, x));
  if (type.name === 'set' && inner && Array.isArray(v)) {
    const seen = new Set<string>();
    const items = v.map((x) => convertType(inner, x)).filter((x) => (seen.has(stableKey(x)) ? false : (seen.add(stableKey(x)), true)));
    const ordered = items.every((x) => typeof x === 'string')
      ? [...items].sort()
      : items.every((x) => typeof x === 'number')
        ? [...items].sort((a, b) => (a as number) - (b as number))
        : items;
    return markSet(ordered);
  }
  if (type.name === 'map' && inner && plain(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, convertType(inner, x)]));
  if (type.name === 'object' && inner?.kind === 'object' && plain(v)) {
    const keys = inner.items.map((item) => staticKey(item.key));
    // An attribute the object type does not declare is dropped by the conversion, as in Terraform.
    if (keys.some((k) => k === undefined)) return { ...v };
    const out: Attrs = {};
    inner.items.forEach((item, i) => {
      const key = keys[i]!;
      if (key in v) out[key] = convertType(item.value, v[key]);
    });
    return out;
  }
  if (type.name === 'tuple' && inner?.kind === 'tuple' && Array.isArray(v)) return v.map((x, i) => (inner.items[i] ? convertType(inner.items[i], x) : x));
  return v;
}

function staticKey(e: Expr): string | undefined {
  if (e.kind === 'literal' && typeof e.value === 'string') return e.value;
  if (e.kind === 'scope') return e.name;
  if (e.kind === 'template' && e.parts.length === 1 && e.parts[0].kind === 'text') return e.parts[0].value;
  return undefined;
}

