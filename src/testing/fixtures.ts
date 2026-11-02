import { expect } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { reveal, type AnalysisResult, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots } from '../terraform/config.js';
import { evaluateRoot } from '../terraform/expand.js';
import { MemorySource } from '../terraform/source.js';
import { replayCommit } from '../replay/replay.js';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface ChangeExpectation {
  address: string;
  action?: string;
  actionNot?: string;
  confidence?: string;
  confidenceNot?: string;
  previousAddress?: string;
  preventDestroy?: boolean;
  actionReasonContains?: string;
  after?: Record<string, unknown>;
  references?: Record<string, string[]>;
  mode?: 'managed' | 'data';
}

export interface FindingExpectation {
  ruleId: string;
  resource?: string;
  status?: string;
  statusIn?: string[];
  statusNot?: string;
  preExisting?: boolean | null;
  detailContains?: string;
  detailNotContains?: string;
  acceptedReasonContains?: string;
}

export interface BlastExpectation {
  resource?: string;
  action?: string;
  severity?: string;
  dataLoss?: boolean;
  downtimeNot?: string;
  reasonContains?: string;
}

export interface AnalysisExpectation {
  roots?: string[];
  diagnostics?: string[];
  instanceCount?: number;
  instances?: Array<{
    address: string;
    attrs?: Record<string, unknown>;
    revealedAttrs?: Record<string, unknown>;
    references?: Record<string, string[]>;
  }>;
  changedAddresses?: string[];
  changes?: ChangeExpectation[];
  noProvenDelete?: boolean;
  findings?: FindingExpectation[];
  noFindingFor?: Array<{ ruleId?: string; resource?: string; resourceContains?: string }>;
  blast?: BlastExpectation[];
  cost?: {
    fixedMonthlyDeltaUsd?: number;
    fixedMonthlyDeltaUsdGt?: number;
    items?: Array<{ resource: string; kind?: string; monthlyDeltaUsdGt?: number; noteContains?: string }>;
  };
  gate?: {
    result?: 'pass' | 'review' | 'block';
    resultNot?: 'pass' | 'review' | 'block';
    reasonsContain?: string[];
  };
  forbiddenSubstrings?: string[];
}

export interface TerraformFixtureCase {
  kind: 'terraform';
  name: string;
  root?: string;
  base?: Record<string, string>;
  head: Record<string, string>;
  policy?: PolicyConfig;
  now?: string;
  expect: AnalysisExpectation;
}

export interface PlanFixtureCase {
  kind: 'plan';
  name: string;
  plan: Record<string, unknown>;
  policy?: PolicyConfig;
  now?: string;
  expect: AnalysisExpectation;
}

/**
 * A commit replayed from a git repository: `base` and `head` are whole snapshots of the repository
 * (path -> contents), `baseLinks` and `headLinks` symbolic links (path -> link text). The base is
 * committed first, then the tree is replaced by the head and committed, and the head is replayed.
 */
export interface ReplayFixtureCase {
  kind: 'replay';
  name: string;
  base: Record<string, string>;
  head: Record<string, string>;
  baseLinks?: Record<string, string>;
  headLinks?: Record<string, string>;
  /** Git submodules in each snapshot (path -> commit id); their content is never in the repository. */
  baseSubmodules?: Record<string, string>;
  headSubmodules?: Record<string, string>;
  /** Replay only the roots under this path, as `diffseal replay --roots-under` does. */
  rootsUnder?: string;
  expect: AnalysisExpectation & {
    /** Roots replayed, in order. */
    replayedRoots?: string[];
    /** Every diagnostic of every replayed root. */
    rootDiagnostics?: string[];
    /** Substrings no gate reason may contain. */
    reasonsNotContain?: string[];
  };
}

export type FixtureCase = TerraformFixtureCase | PlanFixtureCase | ReplayFixtureCase;

export interface FixtureSuite {
  suite: string;
  description?: string;
  cases: FixtureCase[];
}

function checkAnalysisExpectations(
  changes: ResourceChange[],
  result: AnalysisResult,
  exp: AnalysisExpectation,
  extraPrinted: string[] = []
) {
  if (exp.changedAddresses !== undefined) {
    const actual = changes
      .filter((c) => c.mode === 'managed' && c.action !== 'no-op')
      .map((c) => `${c.action} ${c.address}`)
      .sort();
    expect(actual).toEqual([...exp.changedAddresses].sort());
  }
  if (exp.noProvenDelete) {
    expect(changes.some((c) => c.action === 'delete' && c.confidence === 'proven')).toBe(false);
  }
  if (exp.changes) {
    for (const ce of exp.changes) {
      const c = changes.find((x) => x.address === ce.address || (ce.address.endsWith('*') && x.address.startsWith(ce.address.slice(0, -1))));
      if (ce.action === 'no-op' && !c) continue;
      expect(c).toBeDefined();
      if (!c) continue;
      if (ce.action !== undefined) expect(c.action).toBe(ce.action as ResourceChange['action']);
      if (ce.actionNot !== undefined) expect(c.action).not.toBe(ce.actionNot as ResourceChange['action']);
      if (ce.confidence !== undefined) expect(c.confidence).toBe(ce.confidence as NonNullable<ResourceChange['confidence']>);
      if (ce.confidenceNot !== undefined) expect(c.confidence).not.toBe(ce.confidenceNot as NonNullable<ResourceChange['confidence']>);
      if (ce.previousAddress !== undefined) expect(c.previousAddress).toBe(ce.previousAddress);
      if (ce.preventDestroy !== undefined) expect(c.preventDestroy).toBe(ce.preventDestroy);
      if (ce.actionReasonContains !== undefined) expect(c.actionReason ?? '').toContain(ce.actionReasonContains);
      if (ce.mode !== undefined) expect(c.mode).toBe(ce.mode);
      if (ce.after !== undefined) {
        for (const [k, v] of Object.entries(ce.after)) expect(c.after?.[k]).toEqual(v);
      }
      if (ce.references !== undefined) {
        for (const [k, v] of Object.entries(ce.references)) expect(c.references[k]).toEqual(v);
      }
    }
  }
  if (exp.findings) {
    for (const fe of exp.findings) {
      const matches = result.findings.filter(
        (f) => f.ruleId === fe.ruleId && (fe.resource === undefined || f.resource === fe.resource)
      );
      expect(matches.length).toBeGreaterThan(0);
      const f = matches.find((m) => (fe.preExisting === undefined ? true : fe.preExisting === null ? !m.preExisting : m.preExisting === fe.preExisting)) ?? matches[0];
      if (fe.status !== undefined) expect(f.status).toBe(fe.status as typeof f.status);
      if (fe.statusIn !== undefined) expect(fe.statusIn).toContain(f.status);
      if (fe.statusNot !== undefined) expect(f.status).not.toBe(fe.statusNot as typeof f.status);
      if (fe.preExisting === null) expect(f.preExisting).toBeUndefined();
      else if (fe.preExisting !== undefined) expect(f.preExisting).toBe(fe.preExisting);
      if (fe.detailContains !== undefined) expect(f.detail).toContain(fe.detailContains);
      if (fe.detailNotContains !== undefined) expect(f.detail).not.toContain(fe.detailNotContains);
      if (fe.acceptedReasonContains !== undefined) expect(f.accepted?.reason ?? '').toContain(fe.acceptedReasonContains);
    }
  }
  if (exp.noFindingFor) {
    for (const nf of exp.noFindingFor) {
      const hit = result.findings.some(
        (f) =>
          (nf.ruleId === undefined || f.ruleId === nf.ruleId) &&
          (nf.resource === undefined || f.resource === nf.resource) &&
          (nf.resourceContains === undefined || f.resource.includes(nf.resourceContains))
      );
      expect(hit).toBe(false);
    }
  }
  if (exp.blast) {
    for (const be of exp.blast) {
      const b = result.blast.find(
        (x) =>
          (be.resource === undefined || x.resource === be.resource) &&
          (be.action === undefined || x.action === be.action)
      );
      expect(b).toBeDefined();
      if (!b) continue;
      if (be.severity !== undefined) expect(b.severity).toBe(be.severity as typeof b.severity);
      if (be.dataLoss !== undefined) expect(b.dataLoss).toBe(be.dataLoss);
      if (be.downtimeNot !== undefined) expect(b.downtime).not.toBe(be.downtimeNot as typeof b.downtime);
      if (be.reasonContains !== undefined) expect(b.reason).toContain(be.reasonContains);
    }
  }
  if (exp.cost) {
    if (exp.cost.fixedMonthlyDeltaUsd !== undefined) expect(result.cost.fixedMonthlyDeltaUsd).toBe(exp.cost.fixedMonthlyDeltaUsd);
    if (exp.cost.fixedMonthlyDeltaUsdGt !== undefined) expect(result.cost.fixedMonthlyDeltaUsd).toBeGreaterThan(exp.cost.fixedMonthlyDeltaUsdGt);
    if (exp.cost.items) {
      for (const ie of exp.cost.items) {
        const item = result.cost.items.find((x) => x.resource === ie.resource);
        expect(item).toBeDefined();
        if (!item) continue;
        if (ie.kind !== undefined) expect(item.kind).toBe(ie.kind as typeof item.kind);
        if (ie.monthlyDeltaUsdGt !== undefined) expect(item.monthlyDeltaUsd ?? 0).toBeGreaterThan(ie.monthlyDeltaUsdGt);
        if (ie.noteContains !== undefined) expect(item.note).toContain(ie.noteContains);
      }
    }
  }
  if (exp.gate) {
    if (exp.gate.result !== undefined) expect(result.gate.result).toBe(exp.gate.result);
    if (exp.gate.resultNot !== undefined) expect(result.gate.result).not.toBe(exp.gate.resultNot);
    if (exp.gate.reasonsContain) {
      const joined = result.gate.reasons.join(' ');
      for (const r of exp.gate.reasonsContain) expect(joined).toContain(r);
    }
  }
  if (exp.forbiddenSubstrings) {
    const serialized = JSON.stringify({ changes, result }) + extraPrinted.join('\n');
    for (const sub of exp.forbiddenSubstrings) {
      expect(serialized).not.toContain(sub);
    }
  }
}

export async function runFixtureCase(tc: FixtureCase): Promise<void> {
  if (tc.kind === 'terraform') {
    const headSource = new MemorySource(tc.head);
    if (tc.expect.roots !== undefined) {
      expect(discoverRoots(headSource)).toEqual(tc.expect.roots);
    }
    const root = tc.root ?? discoverRoots(headSource)[0] ?? 'r';
    const headEval = evaluateRoot(headSource, root);
    const baseEval = tc.base ? evaluateRoot(new MemorySource(tc.base), root) : undefined;
    if (tc.expect.diagnostics !== undefined) {
      expect(headEval.diagnostics).toEqual(tc.expect.diagnostics);
    }
    if (tc.expect.instanceCount !== undefined) {
      expect(headEval.instances.length).toBe(tc.expect.instanceCount);
    }
    if (tc.expect.instances) {
      for (const ie of tc.expect.instances) {
        const inst = headEval.instances.find((i) => i.address === ie.address);
        expect(inst).toBeDefined();
        if (!inst) continue;
        if (ie.attrs) {
          for (const [k, v] of Object.entries(ie.attrs)) expect(inst.attrs[k]).toEqual(v);
        }
        if (ie.revealedAttrs) {
          for (const [k, v] of Object.entries(ie.revealedAttrs)) expect(reveal(inst.attrs[k])).toEqual(v);
        }
        if (ie.references) {
          for (const [k, v] of Object.entries(ie.references)) {
            for (const target of v) expect(inst.references[k]).toContain(target);
          }
        }
      }
    }
    const changes = compareEvaluations(baseEval, headEval);
    const result = analyze(changes, {
      policy: tc.policy,
      ...(tc.now ? { now: new Date(tc.now) } : {}),
    });
    const extraPrinted = [
      JSON.stringify(headEval.instances.map((i) => i.attrs)),
      ...(baseEval ? [JSON.stringify(baseEval.instances.map((i) => i.attrs))] : []),
    ];
    checkAnalysisExpectations(changes, result, tc.expect, extraPrinted);
    return;
  }

  if (tc.kind === 'replay') {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'diffseal-fixture-'));
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', '-c', 'core.symlinks=true', ...args], { encoding: 'utf8' });
      if (r.status !== 0) throw new Error(`git ${args[0]}: ${r.stderr}`);
    };
    const snapshot = (files: Record<string, string>, links: Record<string, string> = {}, msg: string, submodules: Record<string, string> = {}) => {
      for (const entry of fs.readdirSync(dir)) if (entry !== '.git') fs.rmSync(path.join(dir, entry), { recursive: true, force: true });
      for (const [f, c] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.writeFileSync(path.join(dir, f), c);
      }
      for (const [f, target] of Object.entries(links)) {
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.symlinkSync(target, path.join(dir, f));
      }
      git('add', '-A');
      for (const [p, sha] of Object.entries(submodules)) git('update-index', '--add', '--cacheinfo', `160000,${sha},${p}`);
      git('commit', '-q', '--allow-empty', '-m', msg);
    };
    try {
      git('init', '-q');
      snapshot(tc.base, tc.baseLinks, 'base', tc.baseSubmodules);
      snapshot(tc.head, tc.headLinks, 'head', tc.headSubmodules);
      const r = await replayCommit({ repo: dir, head: 'HEAD', moduleCache: path.join(dir, '.no-module-cache'), ...(tc.rootsUnder ? { rootsUnder: tc.rootsUnder } : {}) });
      if (tc.expect.replayedRoots !== undefined) expect(r.roots.map((x) => (x.varFile ? `${x.root} [${x.varFile}]` : x.root))).toEqual(tc.expect.replayedRoots);
      if (tc.expect.rootDiagnostics !== undefined) expect(r.roots.flatMap((x) => x.diagnostics)).toEqual(tc.expect.rootDiagnostics);
      if (tc.expect.reasonsNotContain) {
        const joined = r.combined.gate.reasons.join(' ');
        for (const s of tc.expect.reasonsNotContain) expect(joined).not.toContain(s);
      }
      checkAnalysisExpectations(r.combined.changes, r.combined, tc.expect);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    return;
  }

  if (tc.kind === 'plan') {
    const changes = readPlan(tc.plan);
    const result = analyze(changes, {
      policy: tc.policy,
      ...(tc.now ? { now: new Date(tc.now) } : {}),
    });
    checkAnalysisExpectations(changes, result, tc.expect);
    return;
  }
}
