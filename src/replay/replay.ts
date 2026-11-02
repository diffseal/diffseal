import { defaultModuleCache, readModuleLock } from '../terraform/moduleCache.js';
import * as path from 'node:path';
import { analyze } from '../analysis/analyze.js';
import { addGateItem, isUnknown, type GateItem, type AnalysisResult, type Gate, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots, isConfigFile, loadModule, moduleClosure } from '../terraform/config.js';
import { parseHcl } from '../hcl/parser.js';
import { stableKey } from '../hcl/eval.js';
import { evaluateRoot, readVarFile, type RootEvaluation } from '../terraform/expand.js';
import { MAX_WORKSPACES, readsWorkspace, surveyWorkspaces } from '../terraform/workspaces.js';
import { inputValues, terragruntDeployments, terragruntFiles, unevaluatedChanges, type TerragruntDeployment } from '../terraform/terragrunt.js';
import { MAX_MAPPED_ENVIRONMENTS, insideRepository, mappedEnvironments, readRootMappings } from './rootInputs.js';
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
  /** The var-files this replay of the root was evaluated with, in order, as repeated `-var-file`. */
  varFiles?: string[];
  /** The base's var-files for this environment, when they differ (git renamed one, or the root moved). */
  baseVarFiles?: string[];
  /** The Terraform workspace this replay selected, when it is not `default`. */
  workspace?: string;
  /** True when the var-files and workspace come from the `roots` mapping in `.diffseal.json`. */
  mapped?: boolean;
  /** The Terragrunt configuration this replay ran the root for, with its inputs. */
  terragrunt?: string;
  /** The module directory that Terragrunt configuration ran at the base, when it was another one. */
  terragruntBaseRoot?: string;
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
  /** Facts about what was evaluated that do not change the gate: workspaces not found or capped, mapping problems. */
  notes: string[];
  headSource: GitSource;
  baseSource: GitSource;
}

/** One evaluation of a root: var-files at each commit, workspace, Terragrunt configuration. */
interface Variant {
  headFiles: string[];
  baseFiles: string[];
  workspace?: string;
  mapped?: boolean;
  tg?: { file: string; head: TerragruntDeployment; base?: TerragruntDeployment; baseRoot: string };
}

/** The evaluation of a root that does not exist yet. */
function emptyEvaluation(root: string): RootEvaluation {
  return { root, instances: [], moved: [], removed: [], imports: [], diagnostics: [], accounts: [], readFiles: new Set(), preventDestroy: new Set() };
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
  const notes: string[] = [];
  /** Notes about one root, kept only when that root is replayed. */
  const rootNotes = new Map<string, string[]>();
  const noteFor = (root: string, text: string) => rootNotes.set(root, [...(rootNotes.get(root) ?? []), text]);
  /** Coverage reviews about one root, raised only when that root is replayed. */
  const rootReviews = new Map<string, string[]>();
  const reviewFor = (root: string, text: string) => rootReviews.set(root, [...(rootReviews.get(root) ?? []), text]);
  // Which inputs each root is deployed with, from the base: a change must not choose how it is reviewed.
  const mappings = readRootMappings(baseSource);
  for (const p of mappings.problems) notes.push(`.diffseal.json ${p}; that part of the roots mapping is ignored`);
  const headDeployments = terragruntDeployments(headSource);
  const baseDeployments = terragruntDeployments(baseSource);
  const under = opts.rootsUnder && path.posix.normalize(opts.rootsUnder) !== '.' ? path.posix.normalize(opts.rootsUnder).replace(/\/$/, '') + '/' : undefined;
  const inScope = (d: TerragruntDeployment) => !under || (d.dir + '/').startsWith(under) || (d.moduleDir !== undefined && (d.moduleDir + '/').startsWith(under));
  /** Configuration files read at the base that a root cannot read at the head (reported per root). */
  const unreadableConfig = new Set<string>();
  const touchedPaths = new Set(changed.flatMap((c) => [c.path, c.oldPath]).filter((p): p is string => Boolean(p)).flatMap(aliases));
  if (changedDirs.size || dataChanged.length || moduleLockChanged) {
    const headRoots = discoverRoots(headSource, opts.rootsUnder);
    const baseRoots = discoverRoots(baseSource, opts.rootsUnder);
    const moves = movedRoots(baseSource, headSource, baseRoots, headRoots, changed);
    const movedFrom = new Map([...moves].map(([from, m]) => [m.to, { ...m, from }]));
    // The module a Terragrunt configuration runs is replayed as a root, even where another root calls it.
    const tgRoots = [...headDeployments.values()].filter((d) => d.moduleDir !== undefined && inScope(d)).map((d) => d.moduleDir!);
    const candidates = new Set([...headRoots, ...baseRoots, ...tgRoots]);
    const allRoots = new Set([...headRoots, ...baseRoots]);
    // Var-files the mapping assigns: they belong to the roots it names, not to whichever root they sit under.
    const mappedFiles = new Set<string>();
    for (const r of candidates) for (const e of mappedEnvironments(mappings, r) ?? []) for (const f of e.varFiles) mappedFiles.add(f);
    // A directory link to a root, unless it points at different roots at the two commits.
    const aliasTarget = (root: string) => {
      const h = headSource.linkedDir(root);
      const b = baseSource.linkedDir(root);
      if (h !== undefined) return b === undefined || b === h ? h : undefined;
      // A link deleted with nothing left in its place; a real directory there now is a root of its own.
      return b !== undefined && !loadModule(headSource, root) ? b : undefined;
    };
    const renamedTo = new Map(changed.filter((c) => c.status === 'R' && c.oldPath).map((c) => [c.oldPath!, c.path]));
    /** Values tfvars files give a root variable: terraform.tfvars, *.auto.tfvars and the root's var-files. */
    const rootVarValues = (src: GitSource, root: string, files: string[]) => {
      const all = [...src.listFiles(root).filter((f) => AUTO_LOADED.test(f)).map((f) => path.posix.join(root, f)), ...files];
      const values = all.map((f) => readVarFile(src, f));
      return (name: string) => values.filter((v) => name in v).map((v) => v[name]);
    };
    /**
     * The evaluations of a root. With a `roots` mapping in `.diffseal.json`, exactly the environments it
     * lists, each with its var-files layered in order and its workspace. Without one: always one without
     * a var-file in workspace `default`, as before inputs were read, so nothing the configuration itself
     * changes can hide behind them; one per var-file that exists at both commits (same path, or renamed
     * by git), in the workspace of the same name when the configuration tells that workspace apart; and
     * one per other workspace name the configuration tells apart. A var-file added or deleted is a changed
     * input, reviewed. A Terragrunt configuration that runs the root adds one evaluation with its inputs.
     */
    const environments = (root: string, baseRoot: string, rootsSet: Set<string>, configTouched: boolean) => {
      const out: Variant[] = [];
      // A root new in this change is evaluated in its environments too, against nothing; a deleted one in the
      // environments it had, against nothing at the head.
      const atHead = Boolean(loadModule(headSource, root));
      const atBase = Boolean(loadModule(baseSource, baseRoot));
      const both = atHead && atBase;
      // A root moved in this change keeps the mapping of its old directory.
      const fromBase = baseRoot !== root ? mappedEnvironments(mappings, baseRoot) : undefined;
      const mapped = !atHead && !atBase
        ? undefined
        : (mappedEnvironments(mappings, root) ??
          fromBase?.map((e) => ({ ...e, varFiles: e.varFiles.map((f) => (f === baseRoot || f.startsWith(baseRoot + '/') ? path.posix.join(root, path.posix.relative(baseRoot, f)) : f)) })));
      if (mapped) {
        if (mapped.length > MAX_MAPPED_ENVIRONMENTS) noteFor(root, `Root ${root} maps ${mapped.length} environments in .diffseal.json; the first ${MAX_MAPPED_ENVIRONMENTS} were evaluated`);
        const skipped: string[] = [];
        for (const env of mapped.slice(0, MAX_MAPPED_ENVIRONMENTS)) {
          const headFiles = env.varFiles;
          const baseFiles = env.varFiles.map((f) => (f === root || f.startsWith(root + '/') ? path.posix.join(baseRoot, path.posix.relative(root, f)) : f));
          const outside = headFiles.filter((f) => !insideRepository(f));
          if (outside.length) {
            noteFor(root, `.diffseal.json maps ${outside.join(', ')} for ${root}, which is outside the repository; that environment is not evaluated`);
            skipped.push(`${outside.join(', ')} is outside the repository`);
            continue;
          }
          const missing = headFiles.filter((f, i) => headSource.blobId(f) === undefined && baseSource.blobId(baseFiles[i]) === undefined && !headSource.linkProblem(f));
          if (missing.length) noteFor(root, `.diffseal.json maps ${missing.join(', ')} for ${root}, which exists at neither commit`);
          // A var-file added or deleted is a new or removed environment: reviewed by name, not compared.
          // A new root has no base to compare with, and a deleted one no head: those sides are not required.
          const gone = headFiles.filter((f, i) => (atHead && headSource.blobId(f) === undefined && !headSource.linkProblem(f)) || (atBase && baseSource.blobId(baseFiles[i]) === undefined && !baseSource.linkProblem(baseFiles[i])));
          if (gone.length) {
            skipped.push(missing.length ? `${missing.join(', ')} ${missing.length === 1 ? 'exists' : 'exist'} at neither commit` : `${gone.join(', ')} is added or deleted by this change`);
            continue;
          }
          out.push({ headFiles, baseFiles, ...(env.workspace ? { workspace: env.workspace } : {}), mapped: true });
        }
        // Nothing mapped can be evaluated: the root is still checked, without inputs, and reviewed.
        if (!out.length) {
          out.push({ headFiles: [], baseFiles: [] });
          reviewFor(root, `Root ${root} maps environments in .diffseal.json, but none could be evaluated (${[...new Set(skipped)].join('; ')}), so it was evaluated without inputs; fix the mapping or review by hand`);
        }
      } else {
        out.push({ headFiles: [], baseFiles: [] });
        if (atHead || atBase) {
          // Workspaces the configuration tells apart, read from both commits. Only needed when an evaluation
          // in a workspace can be compared: the configuration or one of the root's var-files changed.
          // Var-files pair only across both commits; a new root's var-files are new inputs, reviewed.
          const headFilesAll = both ? varFilesOf(headSource, root, rootsSet).filter((f) => !mappedFiles.has(f)) : [];
          const baseFilesAll = both ? varFilesOf(baseSource, baseRoot, rootsSet).filter((f) => !mappedFiles.has(f)) : [];
          const needed = configTouched || [...headFilesAll, ...baseFilesAll].some((f) => touchedPaths.has(f));
          const reads = needed && ((atHead && readsWorkspace(headSource, root)) || (atBase && readsWorkspace(baseSource, baseRoot)));
          let names: string[] = [];
          if (reads) {
            // Names the base tells apart come first, so a change cannot push them past the cap.
            const baseSurvey = atBase ? surveyWorkspaces(baseSource, baseRoot, rootVarValues(baseSource, baseRoot, baseFilesAll)) : undefined;
            const headSurvey = atHead ? surveyWorkspaces(headSource, root, rootVarValues(headSource, root, headFilesAll)) : undefined;
            const baseNames = baseSurvey?.names ?? [];
            const headNames = (headSurvey?.names ?? []).filter((n) => !baseNames.includes(n));
            names = [...baseNames, ...headNames];
            // A name derived from the workspace by removing a part (`trimprefix(terraform.workspace, "app-")`)
            // is an environment, not a workspace: never evaluated bare. When no full name can be built, the
            // environments are not evaluated, and a count or for_each that depends on them is reviewed.
            const surveys = [baseSurvey, headSurvey].filter((x) => x !== undefined);
            const noneBuilt = surveys.some((x) => x.transforms.length) && !surveys.some((x) => x.built);
            const unbuilt = [...new Set(surveys.flatMap((x) => (noneBuilt ? [...x.transforms, ...x.unbuilt] : x.unbuilt)))].sort();
            if (unbuilt.length) {
              const how = unbuilt.slice(0, 3).join(', ') + (unbuilt.length > 3 ? ` and ${unbuilt.length - 3} more` : '');
              const what = noneBuilt
                ? `Root ${root} derives its environment from terraform.workspace (${how}), but no full workspace name could be built from its configuration, so those environments were not evaluated${names.length ? '' : ' and it was evaluated as workspace default only'}`
                : `Root ${root} derives its environment from terraform.workspace (${how}), and some environments it tells apart could not be turned into full workspace names, so they were not evaluated`;
              noteFor(root, `${what}; list its workspaces under roots in .diffseal.json`);
              if (noneBuilt && surveys.some((x) => x.gated)) {
                reviewFor(root, `Root ${root} creates resources depending on terraform.workspace, which it transforms (${how}), and no full workspace name could be built, so what this change does in its environments is not known; list its workspaces under roots in .diffseal.json, or review a plan`);
              }
            } else if (!names.length) noteFor(root, `Root ${root} reads terraform.workspace, but no workspace names could be found in its configuration, so it was evaluated as workspace default only; list its workspaces under roots in .diffseal.json`);
            if (names.length > MAX_WORKSPACES) {
              noteFor(root, `Root ${root} tells ${names.length} workspaces apart; ${MAX_WORKSPACES} were evaluated besides default (${names.slice(0, MAX_WORKSPACES).join(', ')}), not ${names.slice(MAX_WORKSPACES).join(', ')}`);
              names = names.slice(0, MAX_WORKSPACES);
            }
          }
          const paired = new Set<string>();
          for (const h of headFilesAll) {
            const same = path.posix.join(baseRoot, path.posix.relative(root, h));
            const b = baseFilesAll.includes(same) ? same : baseFilesAll.find((x) => renamedTo.get(x) === h);
            if (!b) continue;
            // prod.tfvars is most likely planned in workspace prod, when the configuration has one.
            const stem = path.posix.basename(h).replace(/\.tfvars(\.json)?$/, '');
            const ws = names.includes(stem) ? stem : undefined;
            if (ws) paired.add(ws);
            out.push({ headFiles: [h], baseFiles: [b], ...(ws ? { workspace: ws } : {}) });
          }
          for (const n of names) if (!paired.has(n)) out.push({ headFiles: [], baseFiles: [], workspace: n });
        }
      }
      // Terragrunt configurations that run this root at the head, paired with the same file at the base.
      for (const [file, head] of headDeployments) {
        if (head.moduleDir !== root || !inScope(head)) continue;
        const base = baseDeployments.get(file);
        out.push({ headFiles: [], baseFiles: [], tg: { file, head, base, baseRoot: base?.moduleDir ?? baseRoot } });
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
      const readsData = dataChanged.length > 0 && readsFiles(closure, headSource, baseSource);
      for (const env of environments(root, baseRoot, allRoots, touchesConfig || readsData)) {
        const { headFiles, baseFiles, workspace, tg } = env;
        // A Terragrunt configuration may run another module at the base.
        const envBaseRoot = tg ? tg.baseRoot : baseRoot;
        const envClosure = tg && envBaseRoot !== baseRoot ? new Set([...closure, ...moduleClosure(baseSource, envBaseRoot)]) : closure;
        const tgFiles = tg ? [tg.file, ...tg.head.includes, ...tg.head.reads, ...(tg.base?.includes ?? []), ...(tg.base?.reads ?? [])] : [];
        const touchesEnv =
          (tg && envBaseRoot !== baseRoot ? [...changedDirs].some((d) => envClosure.has(d)) || moduleLockChanged : touchesConfig) ||
          [...headFiles, ...baseFiles, ...tgFiles].some((f) => touchedPaths.has(f));
        if (!touchesEnv && !(dataChanged.length && readsFiles(envClosure, headSource, baseSource))) continue;
        const inputs = (side: 'head' | 'base') => ({ ...(workspace ? { workspace } : {}), ...(tg ? { envVars: inputValues(side === 'head' ? tg.head : tg.base) } : {}) });
        // A Terragrunt configuration new at the head is a new deployment: nothing of it exists yet. Unless it
        // wraps Terraform that was a root already: then it most likely plans against that root's state, so it
        // is compared with the root as it was, and reviewed.
        const wrapsRoot = Boolean(tg && !tg.base && baseRoots.includes(envBaseRoot));
        if (tg && wrapsRoot) reviewFor(root, `${tg.file} is new for ${root}, which existed before as a root: it is compared with ${root} as it was, without Terragrunt inputs; confirm that it keeps that state`);
        const baseEval = tg && !tg.base && !wrapsRoot ? emptyEvaluation(envBaseRoot) : evaluateRoot(baseSource, envBaseRoot, {}, baseFiles, inputs('base'));
        const headEval = evaluateRoot(headSource, root, {}, headFiles, inputs('head'));
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
        const brokenBase = brokenAt(baseEval, envBaseRoot);
        // Broken at both but edited: what was recovered from each says nothing certain either.
        // Only for the var-files this evaluation was made with: an edited auto-loaded file is reviewed by name.
        const editedBroken = headFiles
          .map((h, i) => ({ rel: path.posix.relative(root, h), h, b: baseFiles[i] ?? h }))
          .find(({ rel, h, b }) => brokenHead.has(rel) && brokenBase.has(rel) && headSource.blobId(h) !== baseSource.blobId(b))?.rel;
        // Readable at one commit and not the other: the file must exist at both (an encrypted file added,
        // deleted or renamed is unreadable wherever it is, and reviewed by name).
        const atBase = (f: string) => baseSource.blobId(path.posix.join(envBaseRoot, f)) !== undefined;
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
            // A resource with skip_destroy is reported as removed from state; with its root deleted even that
            // does not happen, and the deleted root is still reviewed.
            if (c.action !== 'delete' && !(c.action === 'forget' && c.actionReason?.startsWith('skip_destroy'))) continue;
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
          ...(headFiles.length ? { varFiles: headFiles } : {}),
          ...(baseFiles.length && baseFiles.some((f, i) => f !== headFiles[i]) ? { baseVarFiles: baseFiles } : {}),
          ...(workspace ? { workspace } : {}),
          ...(env.mapped ? { mapped: true } : {}),
          ...(tg ? { terragrunt: tg.file, ...(tg.baseRoot !== root ? { terragruntBaseRoot: tg.baseRoot } : {}) } : {}),
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

  for (const r of new Set(roots.map((x) => x.root))) {
    notes.push(...(rootNotes.get(r) ?? []));
    for (const text of rootReviews.get(r) ?? []) rootItems.push({ kind: 'coverage', level: 'review', text });
  }
  // Terraform that changed but that no evaluated root covers is reviewed, never silently passed.
  const covered = new Set<string>();
  for (const r of roots) {
    for (const d of moduleClosure(headSource, r.root)) covered.add(d);
    for (const d of moduleClosure(baseSource, r.terragruntBaseRoot ?? r.movedFrom ?? r.root)) covered.add(d);
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
    for (const f of [...(r.varFiles ?? []), ...(r.baseVarFiles ?? [])]) evaluatedInputs.add(f);
    for (const [src, dir] of [[headSource, r.root], [baseSource, r.movedFrom ?? r.root]] as const) {
      // A linked tfvars file may be shared with other roots, so only a plain one counts as evaluated.
      for (const f of src.listFiles(dir)) if (AUTO_LOADED.test(f) && !src.linkTarget(path.posix.join(dir, f))) evaluatedInputs.add(path.posix.join(dir, f));
    }
    if (r.movedFrom) for (const f of r.varFiles ?? []) evaluatedInputs.add(path.posix.join(r.movedFrom, path.posix.relative(r.root, f)));
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
  const unattributed = inputPaths.filter((p) => /\.tfvars(\.json)?$/.test(p) && !aliases(p).some((a) => evaluatedInputs.has(a)));
  const touchedFiles = (r: RootReplay) => [...(r.varFiles ?? []), ...(r.baseVarFiles ?? [])].filter((f) => touchedPaths.has(f));
  // A changed var-file found below a root is evaluated with that root, on its own. Which roots load it,
  // and with which other var-files, is set outside the configuration, so the change stays reviewed.
  // A var-file the roots mapping assigns is evaluated as the team deploys it, and needs no such review.
  const partly = [...new Set(roots.filter((r) => !r.mapped && touchedFiles(r).length).map((r) => `${r.varFiles![0]} (${describeVarChanges(baseSource, headSource, r.varFiles![0], r.baseVarFiles?.[0])}) with ${r.root}`))];
  // A var-file evaluated with a root that does not declare a variable it changes: that value goes elsewhere.
  // For a mapped var-file, only a value no root it is mapped to declares.
  const undeclared: string[] = [];
  const declaredBy = (r: RootReplay) => new Set([...(loadModule(headSource, r.root)?.variables.keys() ?? []), ...(loadModule(baseSource, r.movedFrom ?? r.root)?.variables.keys() ?? [])]);
  const mappedDeclared = new Map<string, { roots: Set<string>; names: Set<string> }>();
  for (const r of roots) {
    if (!r.mapped) continue;
    for (const f of r.varFiles ?? []) {
      const e = mappedDeclared.get(f) ?? { roots: new Set(), names: new Set() };
      e.roots.add(r.root);
      for (const n of declaredBy(r)) e.names.add(n);
      mappedDeclared.set(f, e);
    }
  }
  for (const r of roots) {
    r.varFiles?.forEach((file, i) => {
      if (!touchedPaths.has(file) && !(r.baseVarFiles?.[i] && touchedPaths.has(r.baseVarFiles[i]))) return;
      const change = varChanges(baseSource, headSource, file, r.baseVarFiles?.[i]);
      const names = change === 'new' ? [...readVarNames(headSource, file)] : change;
      if (!Array.isArray(names)) return;
      const declared = r.mapped ? mappedDeclared.get(file)!.names : declaredBy(r);
      const missing = names.filter((n) => !declared.has(n));
      const who = r.mapped ? [...mappedDeclared.get(file)!.roots].sort().join(', ') : r.root;
      if (missing.length) undeclared.push(`${file} sets ${missing.slice(0, 8).join(', ')}, which ${who} ${r.mapped && mappedDeclared.get(file)!.roots.size > 1 ? 'do' : 'does'} not declare`);
    });
  }
  // Terragrunt: a changed configuration is reviewed for what static replay does not evaluate in it.
  const headTg = terragruntFiles(headSource);
  const baseTg = terragruntFiles(baseSource);
  const tgChanged = inputPaths.filter((p) => headTg.has(p) || baseTg.has(p) || /(^|\/)terragrunt\.hcl$/.test(p));
  const tgLines: string[] = [];
  // A configuration's lines are given once, under its own file when that changed too.
  const said = new Set<string>();
  for (const f of [...tgChanged].sort((a, b) => Number(/(^|\/)terragrunt\.hcl$/.test(b)) - Number(/(^|\/)terragrunt\.hcl$/.test(a)))) {
    const reading = (m: Map<string, TerragruntDeployment>) => [...m.values()].filter((d) => d.file === f || d.includes.includes(f) || d.reads.has(f));
    const keys = [...new Set([...reading(headDeployments), ...reading(baseDeployments)].map((d) => d.file))].sort();
    const why: string[] = [];
    if (!keys.length) why.push('no Terragrunt configuration that runs a local Terraform module reads it');
    for (const k of keys) {
      const head = headDeployments.get(k);
      const base = baseDeployments.get(k);
      const where = k === f ? '' : `${k}: `;
      if (!head) {
        why.push(`${where}${k} no longer runs a module here; what it deployed is destroyed only if someone runs terragrunt destroy against its state`);
        continue;
      }
      // Outside --roots-under: not replayed, and so not checked.
      if (!inScope(head) && (!base || !inScope(base))) {
        why.push(`${where}it runs outside --roots-under ${opts.rootsUnder}, so it was not checked`);
        continue;
      }
      const declared = (src: GitSource, d?: TerragruntDeployment) => new Set(d?.moduleDir ? loadModule(src, d.moduleDir)?.variables.keys() ?? [] : []);
      const lines = unevaluatedChanges(base, head, { head: declared(headSource, head), base: declared(baseSource, base) }).filter((l) => !said.has(`${k}\0${l}`));
      for (const l of lines) said.add(`${k}\0${l}`);
      why.push(...lines.map((l) => where + l));
      if (!lines.length && !roots.some((r) => r.terragrunt === k)) why.push(`${where}${head.moduleDir ?? k} was not replayed with its inputs`);
    }
    if (why.length) tgLines.push(`${f} (${[...new Set(why)].slice(0, 4).join('; ')}${why.length > 4 ? '; ...' : ''})`);
  }
  const combined = combineRoots(roots);
  // An external module Diffseal cannot read offline: a new source or version can replace or delete
  // anything inside it, so the change is reviewed, never passed.
  // A submodule bump changes the modules read from it, whether or not a .tf file changed with it.
  const submodules = submoduleItems(baseSource, headSource, opts.rootsUnder);
  for (const item of [...rootItems, ...externalModuleItems(roots), ...submodules]) {
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
  if (tgLines.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate: Terragrunt configuration ${tgLines.slice(0, 5).join('; ')}${tgLines.length > 5 ? `; and ${tgLines.length - 5} more` : ''}. Diffseal reads Terragrunt inputs with literal values and locals, a local terraform source and an included parent, and runs nothing; review the rest by hand or with a plan` });
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
    notes: [...new Set(notes)],
    headSource,
    baseSource,
  };
}

/** The var-files of a replay, relative to its root, in order. */
const varFileNames = (r: RootReplay) => (r.varFiles ?? []).map((f) => path.posix.relative(r.root, f));

/**
 * How each replayed root is named in reports and change records: its var-files, workspace, Terragrunt
 * configuration and a move show.
 */
export function rootNames(roots: RootReplay[]): string[] {
  return roots.map((r) =>
    `${r.root}${r.varFiles?.length ? ` [${varFileNames(r).join(', ')}]` : ''}${r.workspace ? ` (workspace ${r.workspace})` : ''}${r.terragrunt ? ` (terragrunt ${r.terragrunt})` : ''}${r.movedFrom ? ` (moved from ${r.movedFrom})` : ''}${r.deleted ? ' (deleted)' : ''}`
  );
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

const short = (sha: string | undefined) => (sha ? sha.slice(0, 9) : '(none)');

/**
 * Gate items for git submodules whose recorded commit changes (or that are added or removed) and that a
 * root calls modules from, directly or through local modules. Diffseal does not read a submodule's
 * content, so, like an external module version change, a bump is reviewed: one item per submodule,
 * naming both commits, the module calls that read it and the roots that make them.
 */
export function submoduleItems(base: GitSource, head: GitSource, rootsUnder?: string): GateItem[] {
  const was = base.submodules();
  const now = head.submodules();
  const bumped = [...new Set([...was.keys(), ...now.keys()])].filter((p) => was.get(p) !== now.get(p)).sort();
  if (!bumped.length) return [];
  const roots = [...new Set([...discoverRoots(head, rootsUnder), ...discoverRoots(base, rootsUnder)])].sort();
  const items: GateItem[] = [];
  for (const sub of bumped) {
    const inside = (dir: string) => dir === sub || dir.startsWith(sub + '/');
    const users: string[] = [];
    const calls = new Set<string>();
    for (const root of roots) {
      let uses = false;
      for (const src of [head, base]) {
        const walk = (dir: string, prefix: string, depth: number) => {
          if (depth > 16) return;
          for (const call of loadModule(src, dir)?.moduleCalls.values() ?? []) {
            if (!call.localDir) continue;
            const at = `${prefix}module.${call.name}`;
            if (inside(call.localDir)) {
              uses = true;
              calls.add(at);
            } else walk(call.localDir, at + '.', depth + 1);
          }
        };
        walk(root, '', 0);
      }
      if (uses) users.push(root);
    }
    if (!users.length) continue;
    const from = was.get(sub);
    const to = now.get(sub);
    const what = !from ? `is added at ${short(to)}` : !to ? `is removed (it was at ${short(from)})` : `changes from ${short(from)} to ${short(to)}`;
    const list = [...calls].sort();
    const named = `${list.slice(0, 5).join(', ')}${list.length > 5 ? ` and ${list.length - 5} more` : ''}`;
    items.push({
      kind: 'coverage',
      level: 'review',
      text: `Git submodule ${sub} ${what}, and ${named} in ${listRoots(users)} ${list.length === 1 ? 'calls a module' : 'call modules'} from it. Diffseal does not read a submodule's content, so what the new commit replaces or deletes is not known; review the submodule's changes between the two commits, or a plan`,
    });
  }
  return items;
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
  // A root replayed per environment is labelled by its var-files and workspace too; a Terragrunt
  // configuration by its directory.
  const variant = (r: RootReplay) => Boolean(r.varFiles?.length || r.workspace || r.terragrunt || r.mapped);
  const withEnvs = new Set(roots.filter(variant).map((r) => r.root));
  const withVarFiles = new Set(roots.filter((r) => r.varFiles?.length).map((r) => r.root));
  const withWorkspaces = new Set(roots.filter((r) => r.workspace || r.mapped).map((r) => r.root));
  const bare = (root: string) => (withVarFiles.has(root) ? '(no var-file)' : withWorkspaces.has(root) ? '(workspace default)' : '(no inputs)');
  const name = (r: RootReplay) => {
    if (r.terragrunt) return path.posix.dirname(r.terragrunt);
    if (!variant(r)) return withEnvs.has(r.root) ? `${r.root}/${bare(r.root)}` : r.root;
    const parts = [...(r.varFiles?.length ? [varFileNames(r).join(' + ')] : []), ...(r.workspace ? [`workspace ${r.workspace}`] : [])];
    return `${r.root}/${parts.length ? parts.join(', ') : '(workspace default)'}`;
  };
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
    // Workspace default is a deployment of its own; the evaluation without a var-file or Terragrunt inputs is not.
    const check = !variant(replayed) && roots.some((r) => r.root === replayed.root && (r.varFiles?.length || r.terragrunt));
    if (!check && !alias) {
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
