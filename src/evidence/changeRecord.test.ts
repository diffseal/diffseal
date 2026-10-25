import { describe, expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { changeRecord, manifest } from './changeRecord.js';

describe('changeRecord', () => {
  const result = analyze(
    readPlan(
      plan([
        rc('aws_db_instance.db', 'aws_db_instance', ['delete', 'create'], { storage_encrypted: true }, { before: { storage_encrypted: false }, replacePaths: [['storage_encrypted']] }),
        rc('aws_sns_topic.t', 'aws_sns_topic', ['create'], { name: 't' }),
      ])
    )
  );
  const commit = { sha: 'a'.repeat(40), parents: ['b'.repeat(40)], subject: 'feat: x', author: 'Dev', date: '2026-10-01T10:00:00+02:00' };

  test('records what changed, the gate, findings with controls, and approvals when supplied', () => {
    const r = changeRecord({
      commit,
      base: 'b'.repeat(40),
      roots: ['envs/prod/svc'],
      result,
      appLinks: [],
      approvals: { pr: 42, approvedBy: [{ login: 'reviewer', at: '2026-10-01T09:00:00Z' }], mergedBy: 'reviewer' },
      engine: { version: 'test', replaceCatalog: 'x@1' },
    });
    expect(r.schema).toBe('terratrust.change-record/v1');
    expect(r.change.commit).toBe(commit.sha);
    expect(r.gate.result).toBe('block');
    expect(r.resources.map((x) => [x.address, x.action])).toEqual([
      ['aws_db_instance.db', 'replace'],
      ['aws_sns_topic.t', 'create'],
    ]);
    expect(r.controls.some((c) => c.control === 'ISO27001:A.8.24')).toBe(true);
    expect(r.approvals?.approvedBy[0].login).toBe('reviewer');
  });

  test('controls carry the verified references of other frameworks for the rule category', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, appLinks: [], engine: { version: 't', replaceCatalog: 'x' } });
    const rds = r.controls.find((c) => c.rule === 'rds.encryption')!;
    expect(rds.category).toBe('encryption-at-rest');
    expect(rds.frameworks.nis2?.some((x) => x.ref.includes('21(2)(h)'))).toBe(true);
  });

  test('says when approvals are unknown instead of leaving them out silently', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, appLinks: [], engine: { version: 't', replaceCatalog: 'x' } });
    expect(r.approvals).toBeNull();
    expect(r.notes.join(' ')).toContain('approvals');
  });

  test('notes Terraform that did not parse, by file and line (round 3)', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, appLinks: [], diagnostics: ['main.tf:7: expected "}"'], engine: { version: 't', replaceCatalog: 'x' } });
    expect(r.notes.join(' ')).toContain('main.tf:7');
  });

  test('the manifest lists a sha256 per file, sorted', () => {
    const m = manifest({ 'b.json': '{}', 'a.json': 'x' });
    expect(m.split('\n')[0]).toMatch(/^[0-9a-f]{64}  a\.json$/);
  });
});
