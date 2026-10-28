import { defaultModuleCache, MODULE_LOCK } from '../terraform/moduleCache.js';
import { deploymentIndex } from '../app/deployments.js';
import * as path from 'node:path';
import { analyze } from '../analysis/analyze.js';
import { addGateItem, type GateItem, type AnalysisResult, type Gate, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots, loadModule, moduleClosure } from '../terraform/config.js';
import { evaluateRoot } from '../terraform/expand.js';
import { GitSource, changedPaths, commitInfo, unifiedDiff, type ChangedPath, type CommitInfo } from '../terraform/source.js';
import { parseAddedLines } from '../app/diff.js';
import { isAppFile, scanApp } from '../app/scan.js';
import { InfraIndex } from '../reconcile/infraIndex.js';
import { reconcile, type AppLink } from '../reconcile/reconcile.js';
import type { RootEvaluation } from '../terraform/expand.js';

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
}

export interface ReplayResult {
  commit: CommitInfo;
  base: string;
  head: string;
  changedFiles: ChangedPath[];
  /** Terraform files changed, for the report. */
  terraformFiles: string[];
  roots: RootReplay[];
  combined: AnalysisResult;
  /** What changed application code needs from AWS, checked against the infrastructure at head. */
  appLinks: AppLink[];
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
  const moduleLockChanged = headSource.readFile(MODULE_LOCK) !== baseSource.readFile(MODULE_LOCK);
  const tfChanged = changed.filter((c) => TF_FILE.test(c.path) || (c.oldPath && TF_FILE.test(c.oldPath)));
  const changedDirs = new Set(tfChanged.flatMap((c) => [c.path, c.oldPath].filter((p): p is string => Boolean(p)).map((p) => path.posix.dirname(p))));

  // Policy and exceptions come from the base commit: a change must not be able to accept its own findings.
  const policyFileAtBase = opts.policyFile ? parsePolicyFile(baseSource.readFile(opts.policyFile)) : {};
  const policy = { ...repoPolicy(baseSource), ...policyFileAtBase, ...opts.policy };
  const changedConfig = ['.diffseal.json', ...(opts.policyFile ? [opts.policyFile] : [])].filter(
    (f) => baseSource.readFile(f) !== headSource.readFile(f)
  );
  // Files a configuration may read with file() or templatefile(), application code included
  // (user_data = file("bootstrap.py")). Which roots read them is known only by evaluating.
  const dataChanged = changed
    .flatMap((c) => [c.path, c.oldPath])
    .filter((p): p is string => Boolean(p) && !TF_FILE.test(p!));
  const roots: RootReplay[] = [];
  const headEvals = new Map<string, RootEvaluation>();
  if (changedDirs.size || dataChanged.length || moduleLockChanged) {
    const candidates = new Set([...discoverRoots(headSource, opts.rootsUnder), ...discoverRoots(baseSource, opts.rootsUnder)]);
    for (const root of [...candidates].sort()) {
      const closure = new Set([...moduleClosure(headSource, root), ...moduleClosure(baseSource, root)]);
      const touchesConfig = moduleLockChanged || [...changedDirs].some((d) => closure.has(d));
      if (!touchesConfig && !(dataChanged.length && readsFiles(closure, headSource, baseSource))) continue;
      const baseEval = evaluateRoot(baseSource, root);
      const headEval = evaluateRoot(headSource, root);
      if (!touchesConfig && !dataChanged.some((p) => headEval.readFiles.has(p) || baseEval.readFiles.has(p))) continue;
      headEvals.set(root, headEval);
      // An evaluation with no instances still carries removed, moved and prevent_destroy blocks.
      const changes = compareEvaluations(baseEval, headEval);
      // Exceptions are judged on the date of the change, so replaying history reproduces its gate.
      roots.push({ root, changes, result: analyze(changes, { policy, now: opts.now ?? new Date(commit.date) }), diagnostics: headEval.diagnostics });
    }
  }

  // Terraform that changed but that no evaluated root covers is reviewed, never silently passed.
  const covered = new Set<string>();
  for (const r of roots) for (const src of [headSource, baseSource]) for (const d of moduleClosure(src, r.root)) covered.add(d);
  const uncovered = tfChanged
    .flatMap((c) => [c.path, c.oldPath])
    .filter((p): p is string => Boolean(p) && /\.(tf|tofu|tf\.json)$/.test(p!))
    .filter((p) => !covered.has(path.posix.dirname(p)));
  // Inputs static replay does not evaluate: Terragrunt inputs, and tfvars passed with -var-file.
  const evaluatedRoots = new Set(roots.map((r) => r.root));
  const autoLoaded = /(^|\/)(terraform\.tfvars|[^/]*\.auto\.tfvars)(\.json)?$/;
  const unevaluated = changed
    .flatMap((c) => [c.path, c.oldPath])
    .filter((p): p is string => Boolean(p))
    .filter((p) => /(^|\/)terragrunt\.hcl$/.test(p) || (/\.tfvars(\.json)?$/.test(p) && !(autoLoaded.test(p) && evaluatedRoots.has(path.posix.dirname(p)))));
  const appLinks = await checkAppChanges(opts, headSource, baseSource, changed, headEvals);
  const combined = combineRoots(roots);
  if (moduleLockChanged && roots.some((root) => root.changes.some((change) => change.type === 'terraform_module_call'))) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: 'Module lock changed while module source remains unavailable offline; review the dependency change' });
  }
  if (unevaluated.length) {
    if (combined.gate.result === 'pass') combined.gate.result = 'review';
    addGateItem(combined.gate, { kind: 'coverage', level: 'review', text: `Inputs changed that static replay does not evaluate (${[...new Set(unevaluated)].slice(0, 5).join(', ')}); review them by hand or with a plan` });
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
  const attention = appLinks.filter((l) => l.status === 'NOT_GRANTED' || l.status === 'MISSING');
  if (attention.length && combined.gate.result === 'pass') combined.gate.result = 'review';
  for (const l of attention) addGateItem(combined.gate, { kind: 'access', level: 'review', rule: l.status, resource: l.callsite, text: `${l.status}: ${l.callsite}: ${l.access}` });

  return {
    commit,
    base: baseSource.sha,
    head: headSource.sha,
    changedFiles: changed,
    terraformFiles: tfChanged.map((c) => c.path),
    roots,
    combined,
    appLinks,
    headSource,
    baseSource,
  };
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
  const text = source.readFile('.diffseal.json');
  if (!text) return {};
  try {
    const cfg = JSON.parse(text) as { policy?: PolicyConfig; exceptions?: PolicyConfig['exceptions'] };
    return { ...cfg.policy, ...(cfg.exceptions ? { exceptions: cfg.exceptions } : {}) };
  } catch {
    return {};
  }
}

/** Reconcile the app code a commit adds against every root's infrastructure at head. */
async function checkAppChanges(
  opts: ReplayOptions,
  head: GitSource,
  base: GitSource,
  changed: ChangedPath[],
  evaluated: Map<string, RootEvaluation>
): Promise<AppLink[]> {
  const appFiles = changed.filter((c) => c.status !== 'D' && isAppFile(c.path)).map((c) => c.path);
  if (!appFiles.length) return [];
  const addedLines = parseAddedLines(unifiedDiff(opts.repo, base.sha, head.sha, appFiles));
  const scan = await scanApp(head, { addedLines });
  if (!scan.facts.length && !scan.envReads.length) return [];
  const evals = discoverRoots(head, opts.rootsUnder).map((r) => evaluated.get(r) ?? evaluateRoot(head, r));
  const index = new InfraIndex(evals);
  const deployments = deploymentIndex(head, index);
  index.computes.push(...deployments.computes);
  return reconcile(scan.facts, scan.envReads, index, { fileEnv: scan.fileEnv, fileComputes: deployments.files, pairWithChangedEnv: true });
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
  const labels = shortRootLabels(roots.map((r) => r.root));
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
  for (const { root, result } of roots) {
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
