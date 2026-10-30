import { defaultModuleCache, readModuleLock } from '../terraform/moduleCache.js';
import * as path from 'node:path';
import { analyze } from '../analysis/analyze.js';
import { addGateItem, type GateItem, type AnalysisResult, type Gate, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots, isConfigFile, loadModule, moduleClosure } from '../terraform/config.js';
import { parseHcl } from '../hcl/parser.js';
import { evaluateRoot } from '../terraform/expand.js';
import { GitSource, changedPaths, commitInfo, type ChangedPath, type CommitInfo } from '../terraform/source.js';
import { CONFIG_FILE, LEGACY_CONFIG_FILE, readConfigFile } from '../configFile.js';

export interface ReplayOptions {
  repo: string;
  moduleCache?: string;
  /** Commit to replay. */
  head: string;
  /** Defaults to the first parent of head. */
  base?: string;
  policy?: PolicyConfig;
  /** Limit to roots under this path (e.g. `infra/envs/prod`). */
  rootsUnder?: string;
  /** A policy JSON inside the repository: read from the base commit, and a change to it is reviewed. */
  policyFile?: string;
  /**
   * When exceptions are judged. A live check (the Action) uses the current time; replaying history
   * defaults to each change's commit date, so it reproduces the gate the change had.
   */
  now?: Date;
}

export interface RootReplay {
  root: string;
  changes: ResourceChange[];
  result: AnalysisResult;
  diagnostics: string[];
  /** The directory this root had at the base, when the change moved it. */
  movedFrom?: string;
  /** True when the change deleted the root's directory. */
  deleted?: boolean;
  /** The var-file (environment) this replay of the root was evaluated with. */
  varFile?: string;
  /** The base's var-file for this environment, when git renamed it. */
  baseVarFile?: string;
}

/** actionReason of the resources of an environment whose var-file the change deleted. */
export const DELETED_VAR_FILE_REASON = 'its var-file is deleted; it is destroyed only if someone runs terraform destroy with that var-file';

/** actionReason of the resources of a root whose directory the change deleted. */
export const DELETED_ROOT_REASON = 'its root directory is deleted; it is destroyed only if someone runs terraform destroy against that state';

export interface ReplayResult {
  commit: CommitInfo;
  base: string;
  head: string;
  changedFiles: ChangedPath[];
  /** Terraform files changed, for the report. */
  terraformFiles: string[];
  roots: RootReplay[];
  combined: AnalysisResult;
  headSource: GitSource;
  baseSource: GitSource;
}

const TF_FILE = /\.(tf|tofu|tfvars|tf\.json|tfvars\.json)$|(^|\/)\.terraform\.lock\.hcl$|(^|\/)terragrunt\.hcl$/;

export async function replayCommit(opts: ReplayOptions): Promise<ReplayResult> {
  const commit = commitInfo(opts.repo, opts.head);
  const baseRev = opts.base ?? commit.parents[0];
  if (!baseRev) throw new Error(`${commit.sha.slice(0, 9)} has no parent; pass --base`);
  const headSource = new GitSource(opts.repo, commit.sha, opts.moduleCache ?? defaultModuleCache());
  const baseSource = new GitSource(opts.repo, baseRev, opts.moduleCache ?? defaultModuleCache());
  const changed = changedPaths(opts.repo, baseSource.sha, headSource.sha);
  const moduleLockChanged = readModuleLock(headSource) !== readModuleLock(baseSource);
  // A changed file is also changed wherever a symbolic link inside the repository makes it appear, and is
  // Terraform when any of those names is.
  const aliases = (p: string) => [...new Set([p, ...headSource.linksTo(p), ...baseSource.linksTo(p)])];
  const tfChanged = changed.filter((c) => [c.path, c.oldPath].filter((p): p is string => Boolean(p)).flatMap(aliases).some((p) => TF_FILE.test(p)));
  const changedDirs = new Set(tfChanged.flatMap((c) => [c.path, c.oldPath].filter((p): p is string => Boolean(p)).flatMap(aliases).map((p) => path.posix.dirname(p))));
  // A changed link to a directory changes everything read through it.
  for (const c of changed) {
    for (const p of [c.path, c.oldPath]) if (p && (headSource.listFiles(p).length || baseSource.listFiles(p).length)) changedDirs.add(p);
  }

  // Policy and exceptions come from the base commit: a change must not be able to accept its own findings.
  const policyFileAtBase = opts.policyFile ? parsePolicyFile(baseSource.readFile(opts.policyFile)) : {};
  const policy = { ...repoPolicy(baseSource), ...policyFileAtBase, ...opts.policy };
  const changedConfig = [CONFIG_FILE, LEGACY_CONFIG_FILE, ...(opts.policyFile ? [opts.policyFile] : [])].filter(
    (f) => baseSource.readFile(f) !== headSource.readFile(f)
  );
  // Files a configuration may read with file() or templatefile(), scripts included
  // (user_data = file("bootstrap.py")). Which roots read them is known only by evaluating.
  const dataChanged = changed
    .flatMap((c) => [c.path, c.oldPath])
    .filter((p): p is string => Boolean(p) && !TF_FILE.test(p!))
    .flatMap(aliases);
  const roots: RootReplay[] = [];
  const rootItems: GateItem[] = [];
  const touchedPaths = new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)).flatMap(aliases));
  if (changedDirs.size || dataChanged.length || moduleLockChanged) {
    const headRoots = discoverRoots(headSource, opts.rootsUnder);
    const baseRoots = discoverRoots(baseSource, opts.rootsUnder);
    const moves = movedRoots(baseSource, headSource, baseRoots, headRoots, changed);
    const movedFrom = new Map([...moves].map(([from, m]) => [m.to, { ...m, from }]));
    const candidates = new Set([...headRoots, ...baseRoots]);
    const allRoots = new Set([...headRoots, ...baseRoots]);
    const renamedTo = new Map(changed.filter((c) => c.status === 'R' && c.oldPath).map((c) => [c.oldPath!, c.path]));
    /**
     * The environments of a root: each var-file at the head paired with its var-file at the base (same
     * path, or renamed by git). Adding the first var-file, or removing the last, pairs it with the root
     * evaluated without one, so what the configuration itself changes is never hidden behind a "new" or
     * "deleted" environment. Without var-files on either side, one evaluation without any.
     */
    const environments = (root: string, baseRoot: string, rootsSet: Set<string>) => {
      const headFiles = varFilesOf(headSource, root, rootsSet);
      const baseFiles = varFilesOf(baseSource, baseRoot, rootsSet);
      const rootAtBase = Boolean(loadModule(baseSource, baseRoot));
      const rootAtHead = Boolean(loadModule(headSource, root));
      type Env = { headFile?: string; baseFile?: string; headMissing?: boolean; baseMissing?: boolean };
      if (!headFiles.length && !baseFiles.length) return [{}] as Env[];
      const out: Env[] = [];
      const paired = new Set<string>();
      for (const h of headFiles) {
        const same = path.posix.join(baseRoot, path.posix.relative(root, h));
        const b = baseFiles.includes(same) ? same : baseFiles.find((x) => renamedTo.get(x) === h);
        if (b) {
          paired.add(b);
          out.push({ headFile: h, baseFile: b });
        } else if (!baseFiles.length && rootAtBase) out.push({ headFile: h });
        else out.push({ headFile: h, baseMissing: true });
      }
      for (const b of baseFiles) {
        if (paired.has(b)) continue;
        if (!headFiles.length && rootAtHead) out.push({ baseFile: b });
        else out.push({ baseFile: b, headMissing: true });
      }
      return out.sort((x, y) => (x.headFile ?? x.baseFile ?? '').localeCompare(y.headFile ?? y.baseFile ?? ''));
    };
    for (const root of [...candidates].sort()) {
      if (moves.has(root)) continue; // replayed under the directory it moved to
      const move = movedFrom.get(root);
      const baseRoot = move?.from ?? root;
      const closure = new Set([...moduleClosure(headSource, root), ...moduleClosure(baseSource, baseRoot)]);
      const touchesConfig = moduleLockChanged || [...changedDirs].some((d) => closure.has(d));
      const rootDeleted = !move && baseRoots.includes(root) && !loadModule(headSource, root);
      let deletedResources = 0;
      for (const env of environments(root, baseRoot, allRoots)) {
        const { headFile, baseFile } = env;
        const touchesEnv = touchesConfig || [headFile, baseFile].some((f) => f !== undefined && touchedPaths.has(f));
        if (!touchesEnv && !(dataChanged.length && readsFiles(closure, headSource, baseSource))) continue;
        // A var-file new at the head with nothing to pair it with is a new environment: nothing of it exists yet.
        const baseEval = env.baseMissing ? undefined : evaluateRoot(baseSource, baseRoot, {}, baseFile ? [baseFile] : []);
        const headEval = env.headMissing ? undefined : evaluateRoot(headSource, root, {}, headFile ? [headFile] : []);
        if (!touchesEnv && !dataChanged.some((p) => headEval?.readFiles.has(p) || baseEval?.readFiles.has(p))) continue;
        // An evaluation with no instances still carries removed, moved and prevent_destroy blocks.
        const changes = compareEvaluations(baseEval, headEval);
        // Terraform refuses a var-file that does not parse; values that fell back to defaults prove nothing.
        const brokenVarFile = [headFile, baseFile].find((f) => f && [...(headEval?.diagnostics ?? []), ...(baseEval?.diagnostics ?? [])].some((d) => d.startsWith(`${f}:`)));
        if (brokenVarFile) {
          for (const c of changes) {
            if (c.action === 'no-op' || c.confidence !== 'proven') continue;
            c.confidence = 'likely';
            c.actionReason = `${brokenVarFile} does not parse, so its values were not read`;
          }
        }
        // A deleted root directory, or a deleted environment's var-file, plans nothing: the state is left
        // behind, and its resources are destroyed only if someone runs destroy against it. Possible
        // deletions, reviewed.
        const envDeleted = Boolean(env.headMissing && baseFile);
        if (rootDeleted || envDeleted) {
          for (const c of changes) {
            if (c.action !== 'delete') continue;
            c.confidence = 'likely';
            c.actionReason = rootDeleted ? DELETED_ROOT_REASON : DELETED_VAR_FILE_REASON;
            if (c.mode === 'managed') deletedResources++;
          }
          if (envDeleted && !rootDeleted) {
            rootItems.push({ kind: 'coverage', level: 'review', text: `Var-file ${baseFile} of root ${root} is deleted. Deleting it destroys nothing by itself: the resources of that environment are destroyed only if someone runs terraform destroy with it, and otherwise stay in AWS without Terraform managing them; confirm which is intended` });
          }
        }
        // Exceptions are judged on the date of the change, so replaying history reproduces its gate.
        const varFile = headFile ?? baseFile;
        roots.push({
          root,
          changes,
          result: analyze(changes, { policy, now: opts.now ?? new Date(commit.date) }),
          diagnostics: [...new Set([...(headEval?.diagnostics ?? []), ...(baseEval && !headEval ? baseEval.diagnostics : [])])],
          ...(move ? { movedFrom: move.from } : {}),
          ...(rootDeleted ? { deleted: true } : {}),
          ...(varFile ? { varFile } : {}),
          ...(env.baseFile && env.baseFile !== varFile ? { baseVarFile: env.baseFile } : {}),
        });
      }
      if (rootDeleted && deletedResources) {
        const n = deletedResources;
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${root} is deleted with ${n} resource${n === 1 ? '' : 's'} in its configuration. Deleting the directory destroys nothing by itself: they are destroyed only if someone runs terraform destroy against its state, and otherwise stay in AWS without Terraform managing them; confirm which is intended` });
      }
      if (move && !move.sameState && roots.some((r) => r.root === root)) {
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${move.from} moved to ${root} (${move.matched} of ${move.total} files kept or renamed). Its state location is not fixed in the configuration, so the existing resources carry over only if its state moves with it; moving the code destroys nothing, but without the state ${root} would create new copies and leave the old resources unmanaged` });
      }
    }
  }

  // Terraform that changed but that no evaluated root covers is reviewed, never silently passed.
  const covered = new Set<string>();
  for (const r of roots) {
    for (const d of moduleClosure(headSource, r.root)) covered.add(d);
    for (const d of moduleClosure(baseSource, r.movedFrom ?? r.root)) covered.add(d);
  }
  const uncovered = tfChanged
    .flatMap((c) => [c.path, c.oldPath])
    .filter((p): p is string => Boolean(p) && /\.(tf|tofu|tf\.json)$/.test(p!))
    .filter((p) => !aliases(p).some((a) => covered.has(path.posix.dirname(a))));
  // Inputs static replay does not evaluate: Terragrunt inputs, and tfvars no root is known to load.
  const evaluatedInputs = new Set<string>();
  for (const r of roots) {
    if (r.varFile) evaluatedInputs.add(r.varFile);
    for (const [src, dir] of [[headSource, r.root], [baseSource, r.movedFrom ?? r.root]] as const) {
      for (const f of src.listFiles(dir)) if (AUTO_LOADED.test(f)) evaluatedInputs.add(path.posix.join(dir, f));
    }
    if (r.varFile && r.movedFrom) evaluatedInputs.add(path.posix.join(r.movedFrom, path.posix.relative(r.root, r.varFile)));
    if (r.baseVarFile) evaluatedInputs.add(r.baseVarFile);
  }
  const inputPaths = [...new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)))];
  const terragrunt = inputPaths.filter((p) => /(^|\/)terragrunt\.hcl$/.test(p));
  const unattributed = inputPaths.filter((p) => /\.tfvars(\.json)?$/.test(p) && !aliases(p).some((a) => evaluatedInputs.has(a)));
  // A var-file evaluated with a root that does not declare a variable it changes: that value goes elsewhere.
  const undeclared: string[] = [];
  for (const r of roots) {
    if (!r.varFile || !touchedPaths.has(r.varFile)) continue;
    const change = varChanges(baseSource, headSource, r.varFile);
    const names = change === 'new' ? [...readVarNames(headSource, r.varFile)] : change;
    if (!Array.isArray(names)) continue;
    const declared = new Set([...(loadModule(headSource, r.root)?.variables.keys() ?? []), ...(loadModule(baseSource, r.movedFrom ?? r.root)?.variables.keys() ?? [])]);
    const missing = names.filter((n) => !declared.has(n));
    if (missing.length) undeclared.push(`${r.varFile} sets ${missing.slice(0, 8).join(', ')}, which ${r.root} does not declare`);
  }
  const combined = combineRoots(roots);
  // An external module Diffseal cannot read offline: a new source or version can replace or delete
  // anything inside it, so the change is reviewed, never passed.
  for (const item of [...rootItems, ...externalModuleItems(roots)]) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, item);
  }
  if (moduleLockChanged && roots.some((root) => root.changes.some((change) => change.type === 'terraform_module_call'))) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: 'Module lock changed while module source remains unavailable offline; review the dependency change' });
  }
  if (unattributed.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    const files = unattributed.slice(0, 5).map((f) => `${f} (${describeVarChanges(baseSource, headSource, f)})`);
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate: ${files.join('; ')}${unattributed.length > 5 ? `; and ${unattributed.length - 5} more` : ''}. No root loads ${unattributed.length === 1 ? 'this file' : 'these files'} automatically or from a directory below it, so the roots that use ${unattributed.length === 1 ? 'it' : 'them'} were not evaluated with ${unattributed.length === 1 ? 'it' : 'them'}; review by hand or with a plan` });
  }
  if (undeclared.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate: ${[...new Set(undeclared)].slice(0, 5).join('; ')}, so the root that uses ${undeclared.length === 1 ? 'that value' : 'those values'} is not known; review by hand or with a plan` });
  }
  if (terragrunt.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate: Terragrunt configuration ${terragrunt.slice(0, 5).join(', ')}${terragrunt.length > 5 ? ` and ${terragrunt.length - 5} more` : ''}. Diffseal does not read Terragrunt, so its inputs were not evaluated; review by hand or with a plan` });
  }
  if (uncovered.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Terraform changed outside every analyzed root (${uncovered.slice(0, 5).join(', ')}${uncovered.length > 5 ? ', ...' : ''}); it was not checked` });
  }
  // Terraform would refuse configuration that does not parse; what the change touches is reviewed.
  const changedSet = new Set(changed.map((c) => c.path));
  const broken = [...new Set(roots.flatMap((r) => r.diagnostics))].filter((d) => changedSet.has(d.slice(0, d.indexOf(':'))));
  if (broken.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Terraform this change edits does not parse, so it was checked only in part (${broken.slice(0, 3).join('; ')}${broken.length > 3 ? '; ...' : ''})` });
  }
  for (const f of changedConfig) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'policy', level: 'review', text: `${f} changed: its policy and exceptions apply from the next change on, after this one is reviewed` });
  }
  return {
    commit,
    base: baseSource.sha,
    head: headSource.sha,
    changedFiles: changed,
    terraformFiles: tfChanged.map((c) => c.path),
    roots,
    combined,
    headSource,
    baseSource,
  };
}

const AUTO_LOADED = /^(terraform\.tfvars|[^/]*\.auto\.tfvars)(\.json)?$/;

/**
 * Var-files of a root: tfvars files in the root directory that Terraform does not load by itself, and
 * tfvars files in directories below it that hold no Terraform configuration and belong to no other root
 * (`envs/prod.tfvars`, `tfvars/dev.tfvars`). Each is one environment, passed with -var-file. Backend
 * settings (a `backend` or `backends` directory, or `backend` in the file name) are not variables.
 * A root with Terragrunt configuration in or below it has none.
 */
export function varFilesOf(source: GitSource, root: string, roots: Set<string>): string[] {
  if (!loadModule(source, root)) return [];
  const prefix = root === '.' ? '' : root + '/';
  const files = source.allFiles();
  // Terragrunt passes var-files its own way, which Diffseal does not read.
  if (files.some((f) => f.startsWith(prefix) && /(^|\/)terragrunt\.hcl$/.test(f))) return [];
  return files.filter((f) => {
    if (!f.startsWith(prefix) || !/\.tfvars(\.json)?$/.test(f)) return false;
    const rel = f.slice(prefix.length);
    const parts = rel.split('/');
    // The repository root only gets its own files: directories below it may serve any root.
    if (root === '.' && parts.length > 1) return false;
    if (parts.length === 1 && AUTO_LOADED.test(rel)) return false;
    if (parts.some((p) => /^backends?$/i.test(p)) || /backend/i.test(parts[parts.length - 1])) return false;
    if (parts.some((p) => p === '.terraform' || p === 'node_modules')) return false;
    // Every directory between the root and the file is configuration-free and not a root.
    for (let i = 1; i < parts.length; i++) {
      const dir = prefix + parts.slice(0, i).join('/');
      if (roots.has(dir) || source.listFiles(dir).some(isConfigFile)) return false;
    }
    return true;
  });
}

/** The variables a tfvars file changes between two commits: `new` or `deleted` for a whole file. */
function varChanges(base: GitSource, head: GitSource, file: string): string[] | 'new' | 'deleted' {
  const read = (src: GitSource) => {
    const text = src.readFile(file);
    if (text === undefined) return undefined;
    if (file.endsWith('.json')) {
      try {
        const v = JSON.parse(text);
        return new Map(Object.entries(v && typeof v === 'object' ? v : {}).map(([k, x]) => [k, JSON.stringify(x)]));
      } catch {
        return new Map<string, string>();
      }
    }
    const { body } = parseHcl(text);
    return new Map(body.attributes.map((a) => [a.name, text.slice(a.expr.range.start.offset, a.expr.range.end.offset).replace(/\s+/g, ' ')]));
  };
  const was = read(base);
  const now = read(head);
  if (!was) return 'new';
  if (!now) return 'deleted';
  return [...new Set([...was.keys(), ...now.keys()])].filter((k) => was.get(k) !== now.get(k)).sort();
}

function readVarNames(src: GitSource, file: string): string[] {
  const text = src.readFile(file);
  if (text === undefined) return [];
  if (file.endsWith('.json')) {
    try {
      const v = JSON.parse(text);
      return v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : [];
    } catch {
      return [];
    }
  }
  return parseHcl(text).body.attributes.map((a) => a.name);
}

function describeVarChanges(base: GitSource, head: GitSource, file: string): string {
  const names = varChanges(base, head, file);
  if (names === 'new') return 'new file';
  if (names === 'deleted') return 'deleted';
  if (!names.length) return 'no variable value changed';
  return `sets ${names.slice(0, 8).join(', ')}${names.length > 8 ? ` and ${names.length - 8} more` : ''}`;
}

const listRoots = (roots: string[]) => (roots.length > 5 ? `${roots.slice(0, 5).join(', ')} and ${roots.length - 5} more` : roots.join(', '));
const quoted = (v: unknown) => (typeof v === 'string' && v !== '' ? v : '(none)');

/**
 * Gate items for external module calls (registry or git sources not in the offline module cache)
 * whose source or version changes, that are removed, or that only one commit can read. One item per
 * module address and change, naming every root that has it.
 */
export function externalModuleItems(roots: RootReplay[]): GateItem[] {
  const groups = new Map<string, { roots: string[]; text: (where: string) => string }>();
  const add = (key: unknown[], root: string, text: (where: string) => string) => {
    const k = JSON.stringify(key);
    const g = groups.get(k) ?? { roots: [], text };
    if (!g.roots.includes(root)) g.roots.push(root);
    groups.set(k, g);
  };
  for (const { root, changes } of roots) {
    for (const c of changes) {
      if (c.type !== 'terraform_module_call' || c.mode !== 'managed') continue;
      const was = { source: c.before?.source, version: c.before?.version };
      const now = { source: c.after?.source, version: c.after?.version };
      if (c.action === 'delete') {
        if (c.actionReason === DELETED_ROOT_REASON || c.actionReason === DELETED_VAR_FILE_REASON) continue; // said once for the whole root or environment
        add(['removed', c.address, was.source, was.version], root, (where) =>
          `External module ${quoted(was.source)}${was.version ? ` (version ${was.version})` : ''} is removed (${c.address} in ${where}): every resource it manages is destroyed, and Diffseal cannot list them offline; review a plan`);
        continue;
      }
      if (c.action !== 'update' && c.action !== 'move') continue;
      if (c.actionReason?.startsWith('Module source is available in only one snapshot')) {
        add(['one-side', c.address, now.source, now.version], root, (where) =>
          `External module ${quoted(now.source)} can be read offline in only one of the two commits (${c.address} in ${where}), so what changes inside it is not known; review a plan`);
        continue;
      }
      const sourceChanged = (was.source ?? null) !== (now.source ?? null);
      const versionChanged = (was.version ?? null) !== (now.version ?? null);
      if (!sourceChanged && !versionChanged) continue;
      const parts = [
        ...(sourceChanged ? [`source from ${quoted(was.source)} to ${quoted(now.source)}`] : []),
        ...(versionChanged ? [`version from ${quoted(was.version)} to ${quoted(now.version)}`] : []),
      ];
      add(['bump', c.address, was.source, was.version, now.source, now.version], root, (where) =>
        `External module ${sourceChanged ? '' : `${quoted(now.source)} `}changes ${parts.join(' and ')} (${c.address} in ${where}). Diffseal cannot read it offline, so what it replaces or deletes is not known; read the module's release notes or a plan, or run diffseal modules fetch to look inside`);
    }
  }
  return [...groups.values()].map((g) => ({ kind: 'coverage', level: 'review', text: g.text(listRoots(g.roots)) }));
}

/**
 * Root directories the change moved: a base root whose directory has no configuration at the head,
 * paired with a new head root that has the same literal state location, or failing that, keeps at
 * least half of its files (identical, or renamed by git) including one that declares resources, data
 * sources or module calls. Files identical in several base roots (shared provider or version files)
 * are not evidence. Pairs are ranked across all roots, best first, and each root is paired at most once.
 */
function movedRoots(base: GitSource, head: GitSource, baseRoots: string[], headRoots: string[], changed: ChangedPath[]) {
  const out = new Map<string, { to: string; sameState: boolean; matched: number; total: number }>();
  const gone = baseRoots.filter((r) => !loadModule(head, r));
  const fresh = headRoots.filter((r) => !loadModule(base, r));
  if (!gone.length || !fresh.length) return out;
  const renamed = new Map(changed.filter((c) => c.status === 'R' && c.oldPath).map((c) => [c.oldPath!, c.path]));
  const blobRoots = new Map<string, Set<string>>();
  for (const r of baseRoots) {
    for (const name of loadModule(base, r)?.files ?? []) {
      const blob = base.blobId(`${r}/${name}`);
      if (blob) blobRoots.set(blob, new Set([...(blobRoots.get(blob) ?? []), r]));
    }
  }
  const pairs: Array<{ from: string; to: string; sameState: boolean; matched: number; total: number; score: number }> = [];
  for (const g of gone) {
    const bm = loadModule(base, g)!;
    const declaring = new Set([...bm.resources.values(), ...bm.data.values(), ...bm.moduleCalls.values()].map((x) => x.file));
    for (const f of fresh) {
      const hm = loadModule(head, f)!;
      const sameState = Boolean(bm.stateLocation) && bm.stateLocation === hm.stateLocation;
      const kept = bm.files.filter((name) => {
        const was = `${g}/${name}`;
        const blob = base.blobId(was);
        if (blob && (blobRoots.get(blob)?.size ?? 0) <= 1 && hm.files.some((n) => head.blobId(`${f}/${n}`) === blob)) return true;
        const to = renamed.get(was);
        return to !== undefined && path.posix.dirname(to) === f;
      });
      const matched = kept.length;
      const total = Math.max(bm.files.length, hm.files.length);
      const score = sameState ? 2 : matched / total;
      if (!sameState && (score < 0.5 || !kept.some((name) => declaring.has(`${g}/${name}`)))) continue;
      pairs.push({ from: g, to: f, sameState, matched, total, score });
    }
  }
  pairs.sort((x, y) => y.score - x.score || x.from.localeCompare(y.from) || x.to.localeCompare(y.to));
  const taken = new Set<string>();
  for (const p of pairs) {
    if (out.has(p.from) || taken.has(p.to)) continue;
    taken.add(p.to);
    out.set(p.from, { to: p.to, sameState: p.sameState, matched: p.matched, total: p.total });
  }
  return out;
}

function parsePolicyFile(text: string | undefined): PolicyConfig {
  if (!text) return {};
  try {
    return JSON.parse(text) as PolicyConfig;
  } catch {
    return {};
  }
}

/** Policy and exceptions from `.diffseal.json` at a commit, so they are versioned with the code. */
function repoPolicy(source: GitSource): PolicyConfig {
  const text = readConfigFile(source);
  if (!text) return {};
  try {
    const cfg = JSON.parse(text) as { policy?: PolicyConfig; exceptions?: PolicyConfig['exceptions'] };
    return { ...cfg.policy, ...(cfg.exceptions ? { exceptions: cfg.exceptions } : {}) };
  } catch {
    return {};
  }
}

const FILE_FUNCTIONS = /\b(file|templatefile|fileexists|filebase64|filebase64sha256|filebase64sha512|filemd5|filesha1|filesha256|filesha512)\s*\(/;

/** True when any module in the closure calls a function that reads files. */
function readsFiles(closure: Set<string>, ...sources: GitSource[]): boolean {
  for (const dir of closure) {
    for (const src of sources) {
      const mod = loadModule(src, dir);
      if (mod && [...mod.sources.values()].some((text) => FILE_FUNCTIONS.test(text))) return true;
    }
  }
  return false;
}

/** Shortest distinguishing label per root: the path segments that are not shared by all roots. */
export function shortRootLabels(roots: string[]): Record<string, string> {
  if (roots.length <= 1) return Object.fromEntries(roots.map((r) => [r, '']));
  const split = roots.map((r) => r.split('/'));
  const len = Math.max(...split.map((s) => s.length));
  const varying = Array.from({ length: len }, (_, i) => new Set(split.map((s) => s[i])).size > 1);
  return Object.fromEntries(roots.map((r, k) => [r, split[k].filter((_, i) => varying[i]).join('/') || r]));
}

/**
 * Merge per-root results for one report. Changes stay per root (each environment really changes),
 * findings and blast rows that are identical across roots collapse into one row naming every root.
 */
export function combineRoots(roots: RootReplay[]): AnalysisResult {
  // A root replayed per environment is labelled by its var-file's name too.
  const name = (r: RootReplay) => (r.varFile ? `${r.root}/${path.posix.relative(r.root, r.varFile)}` : r.root);
  const labels = shortRootLabels(roots.map(name));
  const label = (root: string, r: string) => (labels[root] ? `${labels[root]}: ${r}` : r);
  const gate: Gate = { result: 'pass', reasons: [], items: [] };
  const rank = { pass: 0, review: 1, block: 2 } as const;
  const out: AnalysisResult = {
    changes: [],
    findings: [],
    blast: [],
    cost: { items: [], fixedMonthlyDeltaUsd: 0, basis: roots[0]?.result.cost.basis ?? '' },
    gate,
  };
  const findings = new Map<string, { roots: string[]; f: AnalysisResult['findings'][number] }>();
  const blast = new Map<string, { roots: string[]; b: AnalysisResult['blast'][number] }>();
  const reasons = new Map<string, { roots: string[]; item: GateItem }>();
  for (const replayed of roots) {
    const { result } = replayed;
    const root = name(replayed);
    out.changes.push(...result.changes.map((c) => ({ ...c, address: label(root, c.address) })));
    for (const f of result.findings) {
      const k = JSON.stringify([f.ruleId, f.resource, f.status, f.detail, f.preExisting]);
      const e = findings.get(k);
      if (e) e.roots.push(root);
      else findings.set(k, { roots: [root], f });
    }
    for (const b of result.blast) {
      const k = JSON.stringify([b.resource, b.severity, b.action, b.reason, b.confidence]);
      const e = blast.get(k);
      if (e) e.roots.push(root);
      else blast.set(k, { roots: [root], b });
    }
    out.cost.items.push(...result.cost.items.map((i) => ({ ...i, resource: label(root, i.resource) })));
    out.cost.fixedMonthlyDeltaUsd = Math.round((out.cost.fixedMonthlyDeltaUsd + result.cost.fixedMonthlyDeltaUsd) * 100) / 100;
    if (rank[result.gate.result] > rank[gate.result]) gate.result = result.gate.result;
    for (const item of result.gate.items) {
      const previous = reasons.get(item.text);
      reasons.set(item.text, { roots: [...(previous?.roots ?? []), root], item });
    }
  }
  const multi = (rs: string[], r: string) => (labels[rs[0]] ? `${rs.map((x) => labels[x]).join(', ')}: ${r}` : r);
  out.findings = [...findings.values()].map(({ roots: rs, f }) => ({ ...f, resource: multi(rs, f.resource) }));
  out.blast = [...blast.values()].map(({ roots: rs, b }) => ({ ...b, resource: multi(rs, b.resource) }));
  gate.items = [...reasons.values()].map(({ roots: rs, item }) => ({ ...item, text: multi(rs, item.text) }));
  gate.reasons = gate.items.map((item) => item.text);
  const sev = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;
  out.blast.sort((a, b) => sev[a.severity] - sev[b.severity]);
  return out;
}
