import { describe, expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { readPlan } from '../plan/readPlan.js';
import { plan, rc } from '../testing/planFixtures.js';
import { addGateItem, type AnalysisResult, type Gate, type ResourceChange } from '../core/model.js';
import { changeRecord, manifest, MAX_RECORD_BYTES } from './changeRecord.js';

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
      approvals: { pr: 42, approvedBy: [{ login: 'reviewer', at: '2026-10-01T09:00:00Z' }], mergedBy: 'reviewer' },
      engine: { version: 'test', replaceCatalog: 'x@1' },
    });
    expect(r.schema).toBe('diffseal.change-record/v1');
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
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, engine: { version: 't', replaceCatalog: 'x' } });
    const rds = r.controls.find((c) => c.rule === 'rds.encryption')!;
    expect(rds.category).toBe('encryption-at-rest');
    expect(rds.frameworks.nis2?.some((x) => x.ref.includes('21(2)(h)'))).toBe(true);
  });

  test('v1 JSON keeps one row per ISO control with SOC 2 in the existing frameworks field', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, engine: { version: 't', replaceCatalog: 'x' } });
    const rows = r.controls.filter((c) => c.rule === 'rds.encryption');
    expect(JSON.parse(JSON.stringify(rows))).toEqual([{
      control: 'ISO27001:A.8.24', rule: 'rds.encryption', resource: 'aws_db_instance.db', status: 'PASS', detail: 'Storage encrypted',
      category: 'encryption-at-rest', frameworks: expect.objectContaining({ soc2_tsc: [{ ref: 'CC6.1', fit: 'direct' }] }),
    }]);
    expect(r.schema).toBe('diffseal.change-record/v1');
  });

  test('SOC 2-only logging and service deletion findings remain visible in v1 records', () => {
    const result = analyze(readPlan(plan([
      rc('aws_s3_bucket_logging.logs', 'aws_s3_bucket_logging', ['create'], {}),
      rc('aws_securityhub_account.account', 'aws_securityhub_account', ['delete'], null),
    ])));
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, engine: { version: 't', replaceCatalog: 'x' } });
    expect(JSON.parse(JSON.stringify(r.controls))).toEqual([
      {
        control: 'SOC2:CC7.2', rule: 's3.access-logging', resource: 'aws_s3_bucket_logging.logs',
        status: 'WARN', detail: expect.any(String), category: 'logging',
        frameworks: expect.objectContaining({ soc2_tsc: [{ ref: 'CC7.2', fit: 'supporting' }] }),
      },
      {
        control: 'SOC2:CC7.2', rule: 'securityhub.disabled', resource: 'aws_securityhub_account.account',
        status: 'FAIL', detail: expect.any(String), category: 'logging',
        frameworks: expect.objectContaining({ soc2_tsc: [{ ref: 'CC7.2', fit: 'supporting' }] }),
      },
    ]);
    expect(r.schema).toBe('diffseal.change-record/v1');
  });

  test('says when approvals are unknown instead of leaving them out silently', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, engine: { version: 't', replaceCatalog: 'x' } });
    expect(r.approvals).toBeNull();
    expect(r.notes.join(' ')).toContain('approvals');
  });

  test('notes Terraform that did not parse, by file and line (round 3)', () => {
    const r = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, diagnostics: ['main.tf:7: expected "}"'], engine: { version: 't', replaceCatalog: 'x' } });
    expect(r.notes.join(' ')).toContain('main.tf:7');
  });

  describe('a record over the upload limit', () => {
    // A large monorepo: thousands of resources, a few with risks, two that raise the gate.
    const change = (address: string, action: ResourceChange['action'], confidence: ResourceChange['confidence'] = 'proven'): ResourceChange =>
      ({ address, type: 'aws_sns_topic', name: 'x', mode: 'managed', action, before: null, after: {}, references: {}, confidence });
    const pad = 'x'.repeat(120);
    const changes: ResourceChange[] = [
      change('aws_db_instance.orders', 'delete'),
      change('aws_iam_role_policy.ci', 'update'),
      change('aws_sqs_queue.medium', 'update'),
      change('aws_sqs_queue.preexisting', 'update'),
      ...Array.from({ length: 2500 }, (_, i) => change(`module.unknown_${pad}.aws_sns_topic.t[${i}]`, 'update', 'unknown')),
      ...Array.from({ length: 2500 }, (_, i) => change(`module.low_${pad}.aws_sns_topic.t[${i}]`, 'create')),
      ...Array.from({ length: 2500 }, (_, i) => change(`module.plain_${pad}.aws_sns_topic.t[${i}]`, 'create')),
    ];
    const blast: AnalysisResult['blast'] = [
      { severity: 'CRITICAL', resource: 'aws_db_instance.orders', type: 'aws_db_instance', action: 'delete', reason: 'deletes the database', dataLoss: true, downtime: 'yes' },
      { severity: 'MEDIUM', resource: 'aws_sqs_queue.medium', type: 'aws_sqs_queue', action: 'update', reason: 'changes delivery', dataLoss: false, downtime: 'possible' },
      ...Array.from({ length: 2500 }, (_, i) => ({ severity: 'LOW' as const, resource: `module.low_${pad}.aws_sns_topic.t[${i}]`, type: 'aws_sns_topic', action: 'create' as const, reason: 'new topic', dataLoss: false, downtime: 'no' as const })),
    ];
    const finding = (resource: string, status: 'FAIL' | 'PASS', preExisting?: boolean): AnalysisResult['findings'][number] =>
      ({ ruleId: 'iam.least-privilege', title: 'Least privilege', status, resource, controls: ['ISO27001:A.8.2'], detail: `${status} detail`, ...(preExisting ? { preExisting } : {}) });
    const findings = [finding('aws_iam_role_policy.ci', 'FAIL'), finding('aws_sqs_queue.preexisting', 'FAIL', true)];
    const gate: Gate = { result: 'pass', reasons: [], items: [] };
    addGateItem(gate, { kind: 'risk', level: 'block', rule: 'blast-radius', resource: 'aws_db_instance.orders', text: 'CRITICAL: aws_db_instance.orders: deletes the database' });
    addGateItem(gate, { kind: 'control', level: 'review', rule: 'iam.least-privilege', resource: 'aws_iam_role_policy.ci', text: 'FAIL iam.least-privilege: aws_iam_role_policy.ci: FAIL detail' });
    addGateItem(gate, { kind: 'coverage', level: 'review', text: 'Terraform changed outside every analyzed root (x.tf); it was not checked' });
    gate.result = 'block';
    const big: AnalysisResult = { changes, findings, blast, gate, cost: { items: [], fixedMonthlyDeltaUsd: 0, basis: '' } };
    const roots = Array.from({ length: 40 }, (_, i) => `services/svc-${i}`);
    const record = changeRecord({ commit, base: 'b'.repeat(40), roots, result: big, engine: { version: 't', replaceCatalog: 'x' } });
    const kept = new Set(record.resources.map((r) => r.address));

    test('the untrimmed record is over the limit, so the test means something', () => {
      const full = changeRecord({ commit, base: 'b'.repeat(40), roots, result: big, engine: { version: 't', replaceCatalog: 'x' }, maxBytes: Infinity });
      expect(full.resources.length).toBe(changes.length);
      expect(Buffer.byteLength(JSON.stringify(full))).toBeGreaterThan(MAX_RECORD_BYTES);
    });

    test('fits under 900 KiB', () => {
      expect(MAX_RECORD_BYTES).toBe(900 * 1024);
      expect(Buffer.byteLength(JSON.stringify(record))).toBeLessThanOrEqual(MAX_RECORD_BYTES);
    });

    test('keeps the gate, its reasons and items, the roots, and what raises the gate', () => {
      expect(record.gate).toEqual(gate);
      expect(record.roots).toEqual(roots);
      // The service checks these: items repeat the reasons, and block is exactly an item at block.
      expect(record.gate.items.map((i) => i.text)).toEqual(record.gate.reasons);
      expect(record.gate.result === 'block').toBe(record.gate.items.some((i) => i.level === 'block'));
      for (const address of ['aws_db_instance.orders', 'aws_iam_role_policy.ci']) expect(kept.has(address)).toBe(true);
      expect(record.risks.some((r) => r.resource === 'aws_db_instance.orders' && r.severity === 'CRITICAL')).toBe(true);
      expect(record.controls.some((c) => c.resource === 'aws_iam_role_policy.ci' && c.status === 'FAIL')).toBe(true);
    });

    test('leaves out the lowest risk first: unknown and unchanged, then no risk, then LOW', () => {
      expect([...kept].some((a) => a.startsWith('module.unknown_'))).toBe(false);
      expect(kept.has('aws_sqs_queue.medium')).toBe(true);
      expect(record.risks.some((r) => r.resource === 'aws_sqs_queue.medium')).toBe(true);
      const plain = [...kept].filter((a) => a.startsWith('module.plain_')).length;
      const low = [...kept].filter((a) => a.startsWith('module.low_')).length;
      expect(low).toBeGreaterThan(0);
      if (plain) expect(low).toBe(2500);
      // A FAIL that does not raise the gate weighs as a HIGH risk, so it goes after LOW and MEDIUM.
      expect(kept.has('aws_sqs_queue.preexisting')).toBe(true);
      // Risks and findings of a resource left out go with it.
      expect(record.risks.every((r) => kept.has(r.resource))).toBe(true);
      expect(record.controls.every((c) => kept.has(c.resource))).toBe(true);
    });

    test('a note says how many entries were left out and where the full list is', () => {
      const left = changes.length - record.resources.length;
      expect(left).toBeGreaterThan(0);
      const note = record.notes.find((n) => n.includes('left out'));
      expect(note).toContain(`${left} of ${changes.length} resource entries`);
      expect(note).toContain('full list');
    });

    test('the note points to the replay report, or to the place the caller names', () => {
      const note = (r: typeof record) => r.notes.find((n) => n.includes('left out'))!;
      expect(note(record).endsWith('The full list is in the replay report for this commit (the JSON that diffseal replay writes).')).toBe(true);
      const named = changeRecord({ commit, base: 'b'.repeat(40), roots, result: big, engine: { version: 't', replaceCatalog: 'x' }, fullListIn: 'the diffseal-ccccccc artifact of this run' });
      // The artifact expires; the replay report can be written again from the commit.
      expect(note(named).endsWith('The full list is in the diffseal-ccccccc artifact of this run, and in the replay report for this commit (the JSON that diffseal replay writes).')).toBe(true);
      expect(Buffer.byteLength(JSON.stringify(named))).toBeLessThanOrEqual(MAX_RECORD_BYTES);
    });

    test('with several roots, a resource is matched to the gate by its address without the root labels', () => {
      // combineRoots labels changes per root (`a: x`) and collapses identical rows (`a, b: x`); gate items keep the bare address.
      const labelled: AnalysisResult = {
        ...big,
        changes: changes.flatMap((c) => ['svc/a', 'svc/b'].map((l) => ({ ...c, address: `${l}: ${c.address}` }))),
        blast: blast.map((b) => ({ ...b, resource: `svc/a, svc/b: ${b.resource}` })),
        // Many FAILs that do not raise the gate rank as high as the one that does.
        findings: [...findings, ...Array.from({ length: 2000 }, (_, i) => finding(`module.pre_${pad}.aws_iam_role_policy.p[${i}]`, 'FAIL', true))]
          .map((f) => ({ ...f, resource: `svc/a, svc/b: ${f.resource}` })),
        gate: { ...gate, items: gate.items.map((i) => ({ ...i, text: `svc/a, svc/b: ${i.text}` })), reasons: gate.reasons.map((r) => `svc/a, svc/b: ${r}`) },
      };
      const r = changeRecord({ commit, base: 'b'.repeat(40), roots, result: labelled, engine: { version: 't', replaceCatalog: 'x' } });
      expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(MAX_RECORD_BYTES);
      expect(r.gate).toEqual(labelled.gate);
      const addresses = new Set(r.resources.map((x) => x.address));
      for (const a of ['aws_db_instance.orders', 'aws_iam_role_policy.ci']) {
        expect(addresses.has(`svc/a: ${a}`)).toBe(true);
        expect(addresses.has(`svc/b: ${a}`)).toBe(true);
      }
      expect(r.risks.some((x) => x.resource === 'svc/a, svc/b: aws_db_instance.orders')).toBe(true);
      expect(r.controls.some((x) => x.resource === 'svc/a, svc/b: aws_iam_role_policy.ci' && x.status === 'FAIL')).toBe(true);
      // A resource's rows in every root go together, and take the rank of its collapsed risk or finding.
      for (const a of addresses) expect(addresses.has(a.startsWith('svc/a: ') ? a.replace('svc/a: ', 'svc/b: ') : a.replace('svc/b: ', 'svc/a: '))).toBe(true);
      expect([...addresses].some((a) => a.includes('module.unknown_'))).toBe(false);
      const pre = r.controls.filter((x) => x.resource.includes('module.pre_')).length;
      expect(pre).toBeGreaterThan(0);
      // The FAILs that do not raise the gate rank as HIGH, so every LOW and MEDIUM resource went before them.
      expect(r.risks.map((x) => x.resource)).toEqual(['svc/a, svc/b: aws_db_instance.orders']);
      expect(addresses.has('svc/a: aws_sqs_queue.medium')).toBe(false);
    });

    test('root labels holding brackets do not hide what raises the gate', () => {
      const labelled: AnalysisResult = {
        ...big,
        changes: changes.flatMap((c) => ['services/[prod]', 'services/[dev]'].map((l) => ({ ...c, address: `${l}: ${c.address}` }))),
        blast: blast.map((b) => ({ ...b, resource: `services/[prod], services/[dev]: ${b.resource}` })),
        findings: findings.map((f) => ({ ...f, resource: `services/[prod], services/[dev]: ${f.resource}` })),
      };
      const r = changeRecord({ commit, base: 'b'.repeat(40), roots, result: labelled, engine: { version: 't', replaceCatalog: 'x' } });
      expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(MAX_RECORD_BYTES);
      const addresses = new Set(r.resources.map((x) => x.address));
      for (const l of ['services/[prod]', 'services/[dev]']) expect(addresses.has(`${l}: aws_db_instance.orders`)).toBe(true);
      expect(r.risks.some((x) => x.resource.endsWith(': aws_db_instance.orders'))).toBe(true);
      expect([...addresses].some((a) => a.includes('module.unknown_'))).toBe(false);
    });

    test('a blocked gate lists only what blocks, and every other new FAIL and HIGH risk is kept too', () => {
      // decideGate stops at the blocking rows, so these raise the gate without a gate item of their own.
      const raising: AnalysisResult = {
        ...big,
        blast: [...blast, { severity: 'HIGH', resource: 'aws_lb_listener.web', type: 'aws_lb_listener', action: 'delete', reason: 'cuts traffic', dataLoss: false, downtime: 'yes' }],
        findings: [...findings, ...Array.from({ length: 2000 }, (_, i) => finding(`module.new_${pad}.aws_iam_role_policy.p[${i}]`, 'FAIL'))],
      };
      const full = changeRecord({ commit, base: 'b'.repeat(40), roots, result: raising, engine: { version: 't', replaceCatalog: 'x' }, maxBytes: Infinity });
      const r = changeRecord({ commit, base: 'b'.repeat(40), roots, result: raising, engine: { version: 't', replaceCatalog: 'x' } });
      expect(r.resources.length).toBeLessThan(full.resources.length);
      expect(r.controls.filter((c) => c.status === 'FAIL' && !c.preExisting).length).toBe(full.controls.filter((c) => c.status === 'FAIL' && !c.preExisting).length);
      expect(r.risks.some((x) => x.resource === 'aws_lb_listener.web')).toBe(true);
    });

    test('a record under the limit is not changed', () => {
      const small = changeRecord({ commit, base: 'b'.repeat(40), roots: [], result, engine: { version: 't', replaceCatalog: 'x' } });
      expect(small.resources.length).toBe(result.changes.length);
      expect(small.notes.some((n) => n.includes('left out'))).toBe(false);
    });
  });

  test('the manifest lists a sha256 per file, sorted', () => {
    const m = manifest({ 'b.json': '{}', 'a.json': 'x' });
    expect(m.split('\n')[0]).toMatch(/^[0-9a-f]{64}  a\.json$/);
  });
});
