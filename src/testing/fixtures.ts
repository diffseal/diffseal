import { extractManaged } from '../app/managed.js';
import { expect } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import type { AccessFact, EnvRead, ResourceRef } from '../app/facts.js';
import { GoIndex, extractGo } from '../app/go.js';
import { extractPython } from '../app/python.js';
import { scanApp } from '../app/scan.js';
import { extractTs } from '../app/typescript.js';
import { reveal, type AnalysisResult, type PolicyConfig, type ResourceChange } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { InfraIndex } from '../reconcile/infraIndex.js';
import { reconcile } from '../reconcile/reconcile.js';
import { compareEvaluations } from '../terraform/compare.js';
import { discoverRoots } from '../terraform/config.js';
import { evaluateRoot } from '../terraform/expand.js';
import { MemorySource } from '../terraform/source.js';

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

export interface AppFixtureCase {
  kind: 'app';
  name: string;
  files: Record<string, string>;
  entryFiles?: string[];
  goModule?: string;
  addedLines?: Record<string, number[]>;
  expect: {
    facts?: Array<{
      service?: string;
      operation?: string;
      actions?: string[];
      resource?: ResourceRef;
      index?: string;
      file?: string;
    }>;
    exactResources?: ResourceRef[];
    resourceKinds?: Array<ResourceRef['kind']>;
    exactActionResourcePairs?: Array<[string, ResourceRef]>;
    forbiddenResources?: ResourceRef[];
    forbiddenActions?: string[];
    envReads?: Array<{ name: string; hasDefault?: boolean }>;
    exactEnvReadNames?: string[];
  };
}

export interface ReconcileFixtureCase {
  kind: 'reconcile';
  name: string;
  infra: Record<string, string>;
  roots?: string[];
  app?: Record<string, string>;
  facts?: Array<Partial<AccessFact> & Pick<AccessFact, 'actions' | 'resource' | 'service'>>;
  envReads?: EnvRead[];
  options?: {
    roleNames?: string[];
    entries?: string[];
    rootsUnder?: string;
    pairWithChangedEnv?: boolean;
    fileEnv?: Record<string, string[]>;
    externallyDefinedEnv?: string[];
  };
  expect: {
    exactStatuses?: string[];
    forbiddenStatuses?: string[];
    links?: Array<{
      status?: string;
      statusNot?: string;
      access?: string;
      actionContains?: string;
      role?: string;
      root?: string;
      detailContains?: string;
      suggestion?: {
        file?: string;
        target?: string;
        code?: string;
      };
    }>;
  };
}

export type FixtureCase = TerraformFixtureCase | PlanFixtureCase | AppFixtureCase | ReconcileFixtureCase;

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

export function runFixtureCase(tc: FixtureCase): void {
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

  if (tc.kind === 'plan') {
    const changes = readPlan(tc.plan);
    const result = analyze(changes, {
      policy: tc.policy,
      ...(tc.now ? { now: new Date(tc.now) } : {}),
    });
    checkAnalysisExpectations(changes, result, tc.expect);
    return;
  }

  if (tc.kind === 'app') {
    const allFiles = Object.entries(tc.files).map(([path, content]) => ({ path, content }));
    const targetFiles = tc.entryFiles
      ? allFiles.filter((f) => tc.entryFiles!.includes(f.path))
      : allFiles;
    const addedLines = tc.addedLines
      ? new Map(Object.entries(tc.addedLines).map(([k, v]) => [k, new Set(v)]))
      : undefined;

    const facts: AccessFact[] = [];
    const envReads: EnvRead[] = [];
    if (tc.files['go.mod'] !== undefined) {
      const r = scanApp(new MemorySource(tc.files), { entries: tc.entryFiles, addedLines });
      facts.push(...r.facts);
      envReads.push(...r.envReads);
    } else {
      const goFiles = targetFiles.filter((f) => f.path.endsWith('.go'));
      const tsFiles = targetFiles.filter((f) => /\.(ts|tsx|js|mjs)$/.test(f.path));
      const pyFiles = targetFiles.filter((f) => f.path.endsWith('.py'));

      if (goFiles.length) {
        const index = tc.goModule ? new GoIndex(tc.goModule, allFiles.filter((f) => f.path.endsWith('.go'))) : undefined;
        const r = extractGo(goFiles, { addedLines, index });
        facts.push(...r.facts);
        envReads.push(...r.envReads);
      }
      if (tsFiles.length) {
        const r = extractTs(tsFiles, { addedLines });
        facts.push(...r.facts);
        envReads.push(...r.envReads);
      }
      const managedFiles = targetFiles.filter(f=>/\.(java|kt|cs)$/.test(f.path));
      if(managedFiles.length){const r=extractManaged(managedFiles,{addedLines});facts.push(...r.facts);envReads.push(...r.envReads);}
      if (pyFiles.length) {
        const r = extractPython(pyFiles, { addedLines });
        facts.push(...r.facts);
        envReads.push(...r.envReads);
      }
    }

    if (tc.expect.exactResources !== undefined) {
      expect(facts.map((f) => f.resource)).toEqual(tc.expect.exactResources);
    }
    if (tc.expect.resourceKinds !== undefined) {
      expect(facts.map((f) => f.resource.kind)).toEqual(tc.expect.resourceKinds);
    }
    if (tc.expect.exactActionResourcePairs !== undefined) {
      expect(facts.map((f) => [f.actions[0], f.resource])).toEqual(tc.expect.exactActionResourcePairs);
    }
    if (tc.expect.facts) {
      expect(facts.length).toBeGreaterThanOrEqual(tc.expect.facts.length);
      tc.expect.facts.forEach((fe, idx) => {
        const f = facts[idx];
        if (fe.service !== undefined) expect(f.service).toBe(fe.service);
        if (fe.operation !== undefined) expect(f.operation).toBe(fe.operation);
        if (fe.actions !== undefined) expect(f.actions).toEqual(fe.actions);
        if (fe.resource !== undefined) expect(f.resource).toEqual(fe.resource);
        if (fe.index !== undefined) expect(f.index).toBe(fe.index);
        if (fe.file !== undefined) expect(f.file).toBe(fe.file);
      });
    }
    if (tc.expect.forbiddenResources) {
      for (const bad of tc.expect.forbiddenResources) {
        expect(facts.some((f) => JSON.stringify(f.resource) === JSON.stringify(bad))).toBe(false);
      }
    }
    if (tc.expect.forbiddenActions) {
      const allActions = facts.flatMap((f) => f.actions);
      for (const bad of tc.expect.forbiddenActions) {
        expect(allActions).not.toContain(bad);
      }
    }
    if (tc.expect.envReads !== undefined) {
      expect(envReads.length).toBe(tc.expect.envReads.length);
      tc.expect.envReads.forEach((ee, idx) => {
        const actual = envReads[idx];
        expect(actual.name).toBe(ee.name);
        if (ee.hasDefault !== undefined) expect(Boolean(actual.hasDefault)).toBe(ee.hasDefault);
      });
    }
    if (tc.expect.exactEnvReadNames !== undefined) {
      expect(envReads.map((e) => e.name)).toEqual(tc.expect.exactEnvReadNames);
    }
    return;
  }

  if (tc.kind === 'reconcile') {
    const infraSource = new MemorySource(tc.infra);
    const roots = tc.roots ?? (discoverRoots(infraSource).length ? discoverRoots(infraSource) : ['infra/prod']);
    const idx = new InfraIndex(roots.map((r) => evaluateRoot(infraSource, r)));
    let facts: AccessFact[] = [];
    let envReads: EnvRead[] = tc.envReads ?? [];
    let fileEnv: Map<string, string[]> | undefined = tc.options?.fileEnv
      ? new Map(Object.entries(tc.options.fileEnv))
      : undefined;
    if (tc.app) {
      const scan = scanApp(new MemorySource(tc.app), { entries: tc.options?.entries });
      facts = scan.facts;
      envReads = scan.envReads;
      fileEnv = scan.fileEnv;
    } else if (tc.facts) {
      facts = tc.facts.map((f) => ({
        operation: f.operation ?? f.actions[0]?.split(':')[1] ?? 'Op',
        file: f.file ?? 'app.go',
        line: f.line ?? 1,
        ...f,
      }));
    }
    const links = reconcile(facts, envReads, idx, {
      roleNames: tc.options?.roleNames,
      fileEnv,
      ...(tc.options?.externallyDefinedEnv ? { externallyDefinedEnv: new Set(tc.options.externallyDefinedEnv) } : {}),
      pairWithChangedEnv: tc.options?.pairWithChangedEnv,
    });
    if (tc.expect.exactStatuses !== undefined) {
      expect(links.map((l) => l.status)).toEqual(tc.expect.exactStatuses as typeof links[number]['status'][]);
    }
    if (tc.expect.forbiddenStatuses) {
      for (const s of tc.expect.forbiddenStatuses) {
        expect(links.map((l) => l.status)).not.toContain(s as typeof links[number]['status']);
      }
    }
    if (tc.expect.links) {
      for (let i = 0; i < tc.expect.links.length; i++) {
        const le = tc.expect.links[i];
        const l =
          le.actionContains !== undefined
            ? links.find((x) => x.actions.some((a) => a.includes(le.actionContains!)))
            : links.length === tc.expect.links.length
              ? links[i]
              : le.access !== undefined
                ? links.find((x) => x.access === le.access)
                : links[0];
        expect(l).toBeDefined();
        if (!l) continue;
        if (le.status !== undefined) expect(l.status).toBe(le.status as typeof l.status);
        if (le.statusNot !== undefined) expect(l.status).not.toBe(le.statusNot as typeof l.status);
        if (le.role !== undefined) expect(l.role).toBe(le.role);
        if (le.root !== undefined) expect(l.root).toBe(le.root);
        if (le.detailContains !== undefined) expect(l.detail).toContain(le.detailContains);
        if (le.suggestion) {
          if (le.suggestion.file !== undefined) expect(l.suggestion?.file).toBe(le.suggestion.file);
          if (le.suggestion.target !== undefined) expect(l.suggestion?.target).toBe(le.suggestion.target);
          if (le.suggestion.code !== undefined) expect(l.suggestion?.code).toBe(le.suggestion.code);
        }
      }
    }
  }
}
