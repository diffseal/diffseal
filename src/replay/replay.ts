import { defaultModuleCache, readModuleLock } from '../terraform/moduleCache.js';
import * as path from 'node:path';
import { analyze } from '../analysis/analyze.js';
import { addGateItem, isUnknown, type GateItem, type AnalysisResult, type Gate, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots, isConfigFile, loadModule, moduleClosure } from '../terraform/config.js';
import { parseHcl } from '../hcl/parser.js';
import { stableKey } from '../hcl/eval.js';
import { evaluateRoot, readVarFile } from '../terraform/expand.js';
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
  /** The directory this root is a directory link to. */
  aliasOf?: string;
}

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
  // A changed path that is a directory at either commit (a directory link, retargeted or not) changes
  // every directory and file read through it.
  const dirSets = [headSource, baseSource].map((src) => new Set(src.allFiles().flatMap((f) => {
    const parts = f.split('/');
    return parts.slice(1).map((_, i) => parts.slice(0, i + 1).join('/'));
  })));
  const linkedDirs = changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p) && dirSets.some((d) => d.has(p!)));
  for (const p of linkedDirs) {
    for (const src of [headSource, baseSource]) for (const f of src.allFiles()) if (f.startsWith(p + '/')) changedDirs.add(path.posix.dirname(f));
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
  // Files read through a changed directory link changed too.
  for (const p of linkedDirs) {
    for (const src of [headSource, baseSource]) dataChanged.push(...src.allFiles().filter((f) => f.startsWith(p + '/') && !TF_FILE.test(f)));
  }
  const roots: RootReplay[] = [];
  const rootItems: GateItem[] = [];
  /** Configuration files read at the base that a root cannot read at the head (reported per root). */
  const unreadableConfig = new Set<string>();
  const touchedPaths = new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)).flatMap(aliases));
  if (changedDirs.size || dataChanged.length || moduleLockChanged) {
    const headRoots = discoverRoots(headSource, opts.rootsUnder);
    const baseRoots = discoverRoots(baseSource, opts.rootsUnder);
    const moves = movedRoots(baseSource, headSource, baseRoots, headRoots, changed);
    const movedFrom = new Map([...moves].map(([from, m]) => [m.to, { ...m, from }]));
    const candidates = new Set([...headRoots, ...baseRoots]);
    const allRoots = new Set([...headRoots, ...baseRoots]);
    // A directory link to a root, unless it points at different roots at the two commits.
    const aliasTarget = (root: string) => {
      const h = headSource.linkedDir(root);
      const b = baseSource.linkedDir(root);
      if (h !== undefined) return b === undefined || b === h ? h : undefined;
      // A link deleted with nothing left in its place; a real directory there now is a root of its own.
      return b !== undefined && !loadModule(headSource, root) ? b : undefined;
    };
    const renamedTo = new Map(changed.filter((c) => c.status === 'R' && c.oldPath).map((c) => [c.oldPath!, c.path]));
    /**
     * The evaluations of a root: always one without a var-file, as before var-files were read, so nothing
     * the configuration itself changes can hide behind them; and one per var-file that exists at both
     * commits (same path, or renamed by git). A var-file added or deleted is a changed input, reviewed.
     */
    const environments = (root: string, baseRoot: string, rootsSet: Set<string>) => {
      type Env = { headFile?: string; baseFile?: string };
      const out: Env[] = [{}];
      if (!loadModule(headSource, root) || !loadModule(baseSource, baseRoot)) return out;
      const baseFiles = varFilesOf(baseSource, baseRoot, rootsSet);
      for (const h of varFilesOf(headSource, root, rootsSet)) {
        const same = path.posix.join(baseRoot, path.posix.relative(root, h));
        const b = baseFiles.includes(same) ? same : baseFiles.find((x) => renamedTo.get(x) === h);
        if (b) out.push({ headFile: h, baseFile: b });
      }
      return out;
    };
    for (const root of [...candidates].sort()) {
      if (moves.has(root)) continue; // replayed under the directory it moved to
      const move = movedFrom.get(root);
      const baseRoot = move?.from ?? root;
      const closure = new Set([...moduleClosure(headSource, root), ...moduleClosure(baseSource, baseRoot)]);
      const touchesConfig = moduleLockChanged || [...changedDirs].some((d) => closure.has(d));
      // A root whose state location another root at the head now uses is not just deleted code: applying
      // that root plans against this state.
      // Only a root that takes the state over in this change counts: one that already used it keeps planning
      // it as before (a deleted link to that root destroys nothing). Matched by the arguments naming the
      // state, or by the full location (an S3 workspace prefix too).
      const gone = loadModule(baseSource, baseRoot);
      const takesOver = (h: string, field: 'stateKey' | 'stateLocation') => {
        const want = gone?.[field];
        return want !== undefined && loadModule(headSource, h)?.[field] === want && loadModule(baseSource, h)?.[field] !== want;
      };
      const adopted = headRoots.some((h) => h !== root && (takesOver(h, 'stateKey') || takesOver(h, 'stateLocation')));
      const rootDeleted = !move && !adopted && baseRoots.includes(root) && !loadModule(headSource, root);
      const was = loadModule(baseSource, baseRoot)?.stateKey;
      const now = loadModule(headSource, root)?.stateKey;
      if (!move && was !== undefined && now !== undefined && was !== now && touchesConfig) {
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${root} changes its state location. Terraform then plans against the other state, which this replay does not compare; confirm the state was moved, or what the other state holds` });
      }
      let deletedResources = 0;
      // A configuration file Terraform cannot read stops its plan with "Failed to read file": a .tf link
      // whose target is deleted, missing or outside the repository. Read at the base, it is not deleted
      // code: the root is not evaluable at the head, and nothing in that file is a deletion.
      // Its path at the base: a root moved in this change had its files under its old directory.
      const atBase = (f: string) => (f === root || f.startsWith(root + '/') ? path.posix.join(baseRoot, path.posix.relative(root, f)) : f);
      const unreadable = [...moduleClosure(headSource, root)]
        // Only the files Terraform reads: OpenTofu's x.tofu shadows x.tf.
        .flatMap((d) => (loadModule(headSource, d)?.files ?? []).filter((f, _, all) => !(f.endsWith('.tf') && all.includes(f.slice(0, -3) + '.tofu'))).map((f) => path.posix.join(d, f)))
        .filter((f) => headSource.linkProblem(f) !== undefined && baseSource.blobId(atBase(f)) !== undefined)
        .sort();
      // What the base read from those files: resources declared in them, and everything in the modules
      // they call (`module.m.` and below, as configuration addresses).
      const lost = new Set(unreadable.map(atBase));
      const lostModules: string[] = [];
      if (lost.size) {
        const walk = (dir: string, prefix: string, depth: number) => {
          if (depth > 16) return;
          for (const call of loadModule(baseSource, dir)?.moduleCalls.values() ?? []) {
            const at = `${prefix}module.${call.name}`;
            if (lost.has(call.file)) lostModules.push(at + '.');
            else if (call.localDir) walk(call.localDir, at + '.', depth + 1);
          }
        };
        walk(baseRoot, '', 0);
      }
      const configAddress = (a: string) => a.replace(/\[("([^"\\]|\\.)*"|[^\]]*)\]/g, '');
      if (unreadable.length) {
        for (const f of unreadable) unreadableConfig.add(f);
        const named = unreadable.slice(0, 3).map((f) => `${f} (${headSource.linkProblem(f)})`).join('; ');
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${root} cannot be planned at this commit: ${named}${unreadable.length > 3 ? '; ...' : ''}. Terraform stops with "Failed to read file" when a configuration file cannot be read, so what this root plans was not checked; what ${unreadable.length === 1 ? 'that file declares or calls is' : 'those files declare or call is'} not shown as deleted` });
      }
      for (const env of environments(root, baseRoot, allRoots)) {
        const { headFile, baseFile } = env;
        const touchesEnv = touchesConfig || [headFile, baseFile].some((f) => f !== undefined && touchedPaths.has(f));
        if (!touchesEnv && !(dataChanged.length && readsFiles(closure, headSource, baseSource))) continue;
        // A var-file new at the head with nothing to pair it with is a new environment: nothing of it exists yet.
        const baseEval = evaluateRoot(baseSource, baseRoot, {}, baseFile ? [baseFile] : []);
        const headEval = evaluateRoot(headSource, root, {}, headFile ? [headFile] : []);
        if (!touchesEnv && !dataChanged.some((p) => headEval.readFiles.has(p) || baseEval.readFiles.has(p))) continue;
        // An evaluation with no instances still carries removed, moved and prevent_destroy blocks.
        let changes = compareEvaluations(baseEval, headEval);
        if (unreadable.length) {
          changes = changes.filter((c) => !(c.action === 'delete' && ((c.source && lost.has(c.source.file)) || lostModules.some((m) => configAddress(c.address).startsWith(m)))));
          for (const c of changes) {
            if (c.action === 'no-op' || c.confidence !== 'proven') continue;
            c.confidence = 'likely';
            c.actionReason = `${unreadable[0]} cannot be read, so Terraform does not plan this root`;
          }
        }
        // Terraform refuses a var-file that does not parse; values that fell back to defaults prove nothing.
        // Only a tfvars file read at one commit and not the other: then defaults stand in for its values on
        // one side only. Unreadable at both (an encrypted file), both sides lack the same values.
        // Compared by path inside the root, so a root that moves with its encrypted file is not a change.
        const brokenAt = (e: { diagnostics: string[] }, dir: string) => new Set(e.diagnostics.map((d) => d.slice(0, d.indexOf(':'))).filter((f) => /\.tfvars(\.json)?$/.test(f)).map((f) => path.posix.relative(dir, f)));
        const brokenHead = brokenAt(headEval, root);
        const brokenBase = brokenAt(baseEval, baseRoot);
        // Broken at both but edited: what was recovered from each says nothing certain either.
        // Only for the var-file this evaluation was made with: an edited auto-loaded file is reviewed by name.
        const envFile = headFile ? path.posix.relative(root, headFile) : undefined;
        const editedBroken = envFile !== undefined && brokenHead.has(envFile) && brokenBase.has(envFile) && headSource.blobId(headFile!) !== baseSource.blobId(baseFile ?? headFile!) ? envFile : undefined;
        // Readable at one commit and not the other: the file must exist at both (an encrypted file added,
        // deleted or renamed is unreadable wherever it is, and reviewed by name).
        const atBase = (f: string) => baseSource.blobId(path.posix.join(baseRoot, f)) !== undefined;
        const atHead = (f: string) => headSource.blobId(path.posix.join(root, f)) !== undefined;
        const brokenVarFile = [...brokenHead].find((f) => !brokenBase.has(f) && atBase(f)) ?? [...brokenBase].find((f) => !brokenHead.has(f) && atHead(f)) ?? editedBroken;
        if (brokenVarFile) {
          for (const c of changes) {
            if (c.action === 'no-op' || c.confidence !== 'proven') continue;
            c.confidence = 'likely';
            c.actionReason = `${brokenVarFile} does not parse, so its values were not read`;
          }
        }
        // A deleted root directory plans nothing: the state is left behind, and its resources are destroyed
        // only if someone runs destroy against it. Possible deletions, reviewed.
        if (rootDeleted) {
          for (const c of changes) {
            if (c.action !== 'delete') continue;
            c.confidence = 'likely';
            c.actionReason = DELETED_ROOT_REASON;
            if (c.mode === 'managed') deletedResources++;
          }
        }
        // Exceptions are judged on the date of the change, so replaying history reproduces its gate.
        roots.push({
          root,
          changes,
          result: analyze(changes, { policy, now: opts.now ?? new Date(commit.date) }),
          diagnostics: headEval.diagnostics,
          ...(move ? { movedFrom: move.from } : {}),
          ...(rootDeleted ? { deleted: true } : {}),
          ...(headFile ? { varFile: headFile } : {}),
          ...(baseFile && baseFile !== headFile ? { baseVarFile: baseFile } : {}),
          // A link pointing at the same root at both commits; a retargeted link is a deployment of its own.
          ...(aliasTarget(root) !== undefined ? { aliasOf: aliasTarget(root) } : {}),
        });
      }
      if (rootDeleted && deletedResources) {
        const n = deletedResources;
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${root} is deleted with ${n} resource${n === 1 ? '' : 's'} in its configuration. Deleting the directory destroys nothing by itself: they are destroyed only if someone runs terraform destroy against its state, and otherwise stay in AWS without Terraform managing them; confirm which is intended` });
      }
      if (move && !move.sameState && roots.some((r) => r.root === root)) {
        rootItems.push({ kind: 'coverage', level: 'review', text: `Root ${move.from} moved to ${root} (${move.matched} of ${move.total} files kept or renamed). The configuration does not show that both use the same state, so the existing resources carry over only if its state moves with it; moving the code destroys nothing, but without the state ${root} would create new copies and leave the old resources unmanaged` });
      }
    }
  }

  // Terraform that changed but that no evaluated root covers is reviewed, never silently passed.
  const covered = new Set<string>();
  for (const r of roots) {
    for (const d of moduleClosure(headSource, r.root)) covered.add(d);
    for (const d of moduleClosure(baseSource, r.movedFrom ?? r.root)) covered.add(d);
  }
  // A file is configuration under every name Terraform reads it by: a `.tf` link to a target without a
  // `.tf` name (`r/table.tf -> ../shared/config`) is Terraform, named by the link.
  const uncovered = [...new Set(tfChanged.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)))]
    .map((p) => ({ p, names: aliases(p).filter((a) => isConfigFile(path.posix.basename(a))) }))
    .filter(({ names }) => names.length && !names.some((a) => covered.has(path.posix.dirname(a))))
    .map(({ p, names }) => (isConfigFile(path.posix.basename(p)) ? p : `${names.slice(0, 3).join(', ')} (link to ${p})`));
  // A changed directory link that holds Terraform no replayed root reads is not checked.
  for (const p of linkedDirs) {
    const inside = [headSource, baseSource].flatMap((src) => src.allFiles().filter((f) => f.startsWith(p + '/') && isConfigFile(path.posix.basename(f))));
    const unread = [...new Set(inside.map((f) => path.posix.dirname(f)))].filter((d) => !covered.has(d));
    if (unread.length) {
      rootItems.push({ kind: 'coverage', level: 'review', text: `Directory link ${p} changed and holds Terraform (${unread.slice(0, 3).join(', ')}${unread.length > 3 ? ', ...' : ''}) that no replayed root reads; what it plans now was not checked` });
    }
  }
  // Inputs static replay does not evaluate: Terragrunt inputs, and tfvars no root is known to load.
  const evaluatedInputs = new Set<string>();
  for (const r of roots) {
    if (r.varFile) evaluatedInputs.add(r.varFile);
    for (const [src, dir] of [[headSource, r.root], [baseSource, r.movedFrom ?? r.root]] as const) {
      // A linked tfvars file may be shared with other roots, so only a plain one counts as evaluated.
      for (const f of src.listFiles(dir)) if (AUTO_LOADED.test(f) && !src.linkTarget(path.posix.join(dir, f))) evaluatedInputs.add(path.posix.join(dir, f));
    }
    if (r.varFile && r.movedFrom) evaluatedInputs.add(path.posix.join(r.movedFrom, path.posix.relative(r.root, r.varFile)));
    if (r.baseVarFile) evaluatedInputs.add(r.baseVarFile);
  }
  // A tfvars file that cannot be read (an encrypted one) at either commit was not evaluated.
  for (const f of [...evaluatedInputs]) {
    for (const src of [headSource, baseSource]) {
      if (src.blobId(f) === undefined && !src.linkProblem(f)) continue;
      const problems: string[] = [];
      readVarFile(src, f, false, problems);
      if (problems.length) evaluatedInputs.delete(f);
    }
  }
  // Every name a changed file has, so a terragrunt.hcl or tfvars link to a changed target counts.
  const inputPaths = [...new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)).flatMap(aliases))];
  const terragrunt = inputPaths.filter((p) => /(^|\/)terragrunt\.hcl$/.test(p));
  const unattributed = inputPaths.filter((p) => /\.tfvars(\.json)?$/.test(p) && !aliases(p).some((a) => evaluatedInputs.has(a)));
  // A changed var-file found below a root is evaluated with that root, on its own. Which roots load it,
  // and with which other var-files, is set outside the configuration, so the change stays reviewed.
  const partly = [...new Set(roots.filter((r) => r.varFile && [r.varFile, r.baseVarFile].some((f) => f && touchedPaths.has(f))).map((r) => `${r.varFile} (${describeVarChanges(baseSource, headSource, r.varFile!, r.baseVarFile)}) with ${r.root}`))];
  // A var-file evaluated with a root that does not declare a variable it changes: that value goes elsewhere.
  const undeclared: string[] = [];
  for (const r of roots) {
    if (!r.varFile || !touchedPaths.has(r.varFile)) continue;
    const change = varChanges(baseSource, headSource, r.varFile, r.baseVarFile);
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
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate: ${files.join('; ')}${unattributed.length > 5 ? `; and ${unattributed.length - 5} more` : ''}. No root was evaluated with ${unattributed.length === 1 ? 'this file' : 'these files'}: a var-file is evaluated only when it sits in or below its root and exists at both commits; review by hand or with a plan` });
  }
  if (partly.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that were evaluated only in part: ${partly.slice(0, 5).join('; ')}${partly.length > 5 ? `; and ${partly.length - 5} more` : ''}. Each var-file was evaluated on its own with the root it sits in; a root that loads it from elsewhere, or together with other var-files, was not evaluated; review by hand or with a plan` });
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
  const changedSet = new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)).flatMap(aliases));
  // A configuration link that cannot be read at the head is reviewed above, with its root.
  const broken = [...new Set(roots.flatMap((r) => r.diagnostics))].filter((d) => changedSet.has(d.slice(0, d.indexOf(':'))) && !unreadableConfig.has(d.slice(0, d.indexOf(':'))));
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

/** How each replayed root is named in reports and change records: its var-file and a move show. */
export function rootNames(roots: RootReplay[]): string[] {
  return roots.map((r) => `${r.root}${r.varFile ? ` [${path.posix.relative(r.root, r.varFile)}]` : ''}${r.movedFrom ? ` (moved from ${r.movedFrom})` : ''}${r.deleted ? ' (deleted)' : ''}`);
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
function varChanges(base: GitSource, head: GitSource, file: string, baseFile = file): string[] | 'new' | 'deleted' {
  const read = (src: GitSource) => {
    const text = src.readFile(src === base ? baseFile : file);
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

function describeVarChanges(base: GitSource, head: GitSource, file: string, baseFile = file): string {
  const names = varChanges(base, head, file, baseFile);
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
      // No instances at either commit (count = 0, for_each = {} or []): nothing of it exists or will.
      const empty = (a: typeof c.before) => a?.count === 0 || (a?.for_each !== undefined && a.for_each !== null && typeof a.for_each === 'object' && !isUnknown(a.for_each) && Object.keys(a.for_each).length === 0);
      if (empty(c.before) && empty(c.after)) continue;
      // A local module path that cannot be read (a missing directory, a refused link) hides its resources.
      const local = [c.before?.source, c.after?.source].find((x) => typeof x === 'string' && (x.startsWith('./') || x.startsWith('../')));
      if (local !== undefined && c.action !== 'no-op') {
        add(['local', c.address, local], root, (where) => `Local module ${local} cannot be read (${c.address} in ${where}), so what it changes is not known; review a plan`);
        continue;
      }
      const was = { source: c.before?.source, version: c.before?.version };
      const now = { source: c.after?.source, version: c.after?.version };
      if (c.action === 'delete') {
        if (c.actionReason === DELETED_ROOT_REASON) continue; // said once for the whole root
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
      if (['count', 'for_each'].some((k) => stableKey(c.before?.[k] ?? null) !== stableKey(c.after?.[k] ?? null))) {
        add(['instances', c.address], root, (where) =>
          `count or for_each of external module ${quoted(now.source)} changes (${c.address} in ${where}): instances of it may be added or destroyed, and Diffseal cannot list their resources offline; review a plan`);
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
      const blob = base.blobId(path.posix.join(r, name));
      if (blob) blobRoots.set(blob, new Set([...(blobRoots.get(blob) ?? []), r]));
    }
  }
  const pairs: Array<{ from: string; to: string; sameState: boolean; matched: number; total: number; score: number }> = [];
  const sharingCount = new Map<string, number>();
  for (const f of fresh) {
    const loc = loadModule(head, f)?.stateLocation;
    if (loc !== undefined) sharingCount.set(loc, (sharingCount.get(loc) ?? 0) + 1);
  }
  for (const g of gone) {
    const bm = loadModule(base, g)!;
    const declaring = new Set([...bm.resources.values(), ...bm.data.values(), ...bm.moduleCalls.values()].map((x) => x.file));
    for (const f of fresh) {
      const hm = loadModule(head, f)!;
      // Two new roots with the old root's state location cannot both be it: then neither is known to be.
      const sharing = bm.stateLocation === undefined ? 0 : (sharingCount.get(bm.stateLocation) ?? 0);
      const sameState = Boolean(bm.stateLocation) && bm.stateLocation === hm.stateLocation && sharing === 1;
      const kept = bm.files.filter((name) => {
        const was = path.posix.join(g, name);
        const blob = base.blobId(was);
        if (blob && (blobRoots.get(blob)?.size ?? 0) <= 1 && hm.files.some((n) => head.blobId(path.posix.join(f, n)) === blob)) return true;
        const to = renamed.get(was);
        return to !== undefined && path.posix.dirname(to) === f;
      });
      const matched = kept.length;
      const total = Math.max(bm.files.length, hm.files.length);
      const score = sameState ? 2 : matched / total;
      if (!sameState && (score < 0.5 || !kept.some((name) => declaring.has(path.posix.join(g, name))))) continue;
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
  const withEnvs = new Set(roots.filter((r) => r.varFile).map((r) => r.root));
  const name = (r: RootReplay) => (r.varFile ? `${r.root}/${path.posix.relative(r.root, r.varFile)}` : withEnvs.has(r.root) ? `${r.root}/(no var-file)` : r.root);
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
    // A root with var-files is deployed with them: its evaluation without one is a check, not a deployment.
    // A directory link to a root replayed too is the same deployment, counted once.
    const alias = replayed.aliasOf !== undefined && roots.some((r) => r.root === replayed.aliasOf);
    if (!(withEnvs.has(replayed.root) && !replayed.varFile) && !alias) {
      out.cost.items.push(...result.cost.items.map((i) => ({ ...i, resource: label(root, i.resource) })));
      out.cost.fixedMonthlyDeltaUsd = Math.round((out.cost.fixedMonthlyDeltaUsd + result.cost.fixedMonthlyDeltaUsd) * 100) / 100;
    }
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
