import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { analyze } from './analysis/analyze.js';
import type { Gate, PolicyConfig } from './core/model.js';
import { readPlan } from './plan/readPlan.js';
import { compareEvaluations } from './terraform/compare.js';
import { evaluateRoot } from './terraform/expand.js';
import { MemorySource } from './terraform/source.js';
import { combineRoots, replayCommit } from './replay/replay.js';
import { spawnSync } from 'node:child_process';
import * as os from 'node:os';

function invariant(g: Gate) {
  expect(g.items.map((i) => i.text)).toEqual(g.reasons);
  expect(g.result === 'block').toBe(g.items.some((i) => i.level === 'block'));
}

test('gate properties hold across specification fixtures, combined roots and demo scenarios', async () => {
  const files = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(path.join(dir, e.name)) : [path.join(dir, e.name)]);
  for (const file of files(path.resolve(import.meta.dirname, '../fixtures')).filter((f) => f.endsWith('.json'))) {
    const suite = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const c of suite.cases ?? []) {
      if (c.kind !== 'plan' && c.kind !== 'terraform') continue;
      const changes = c.kind === 'plan' ? readPlan(c.plan) : compareEvaluations(evaluateRoot(new MemorySource(c.base ?? {}), c.root ?? '.'), evaluateRoot(new MemorySource(c.head), c.root ?? '.'));
      const result = analyze(changes, { policy: c.policy as PolicyConfig, now: c.now ? new Date(c.now) : undefined });
      invariant(result.gate);
      const combined = combineRoots(['prod', 'test'].map((root) => ({ root, changes, result, diagnostics: [] })));
      invariant(combined.gate);
      for (const text of combined.gate.reasons) expect(text.startsWith('prod, test: ')).toBe(true);
    }
  }
  const demo = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../fixtures/demo/snapshots.fixture'), 'utf8'));
  for (const scenario of demo.heads) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-gate-'));
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
      if (r.status) throw new Error(r.stderr);
    };
    const write = (files: Record<string, string>) => { for (const [name, value] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true }); fs.writeFileSync(path.join(dir, name), value); } };
    try {
      git('init', '-q'); write(demo.base); git('add', '.'); git('commit', '-qm', 'base');
      for (const name of Object.keys(demo.base)) if (!(name in scenario.files)) fs.rmSync(path.join(dir, name));
      write(scenario.files); git('add', '.'); git('commit', '-qm', 'head');
      const r = await replayCommit({ repo: dir, head: 'HEAD' }); invariant(r.combined.gate); r.roots.forEach((root) => invariant(root.result.gate));
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  }
});
