import { scrubDeep, sensitiveLeaves, type AnalysisResult, type Gate, type PolicyConfig, type PolicyException, type ResourceChange } from '../core/model.js';
import { DEFAULT_POLICY, evaluatePolicies } from '../policy/engine.js';
import { analyzeBlastRadius } from './blastRadius.js';
import { estimateCost } from './cost.js';

const CHANGED = new Set(['create', 'update', 'replace', 'delete', 'import', 'forget', 'move']);

/**
 * Analyze a set of resources. `all` may include unchanged (no-op) resources and data sources; they are
 * used as context (a bucket's encryption helper, a role's policy document) but never billed or gated.
 */
export function analyze(all: ResourceChange[], opts: { policy?: PolicyConfig; now?: Date } = {}): AnalysisResult {
  const policy = { ...DEFAULT_POLICY, ...opts.policy };
  const changes = all.filter((c) => c.mode === 'managed' && CHANGED.has(c.action));
  const findings = evaluatePolicies(all, policy);
  const blast = analyzeBlastRadius(changes);
  const cost = estimateCost(changes);
  const expired = applyExceptions(findings, blast, policy.exceptions, opts.now ?? new Date());
  const gate = decideGate(findings, blast, policy.blockOn);
  for (const e of expired) {
    const what = `Exception for ${e?.rule ?? 'every rule'} on ${e?.resource ?? '(no resource)'}`;
    gate.reasons.push(
      isWellFormed(e)
        ? `${what} expired ${e.expires}; it no longer applies`
        : `${what} is malformed: it needs a resource and an expires date as YYYY-MM-DD; it does not apply`
    );
  }
  if (expired.length && gate.result === 'pass') gate.result = 'review';
  // Rules and the grant diff read sensitive values; nothing they wrote may contain one.
  const hidden = all.flatMap((c) => [...sensitiveLeaves(c.before), ...sensitiveLeaves(c.after)]);
  return { changes, ...scrubDeep({ findings, blast, cost, gate }, hidden) };
}

const globMatch = (pattern: string, value: string) =>
  new RegExp('^' + pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$').test(value);

function isWellFormed(e: PolicyException): boolean {
  return typeof e?.resource === 'string' && typeof e.expires === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(e.expires) && !Number.isNaN(Date.parse(e.expires));
}

/** Mark findings and blast rows accepted by unexpired exceptions; return expired exceptions that matched. */
function applyExceptions(findings: AnalysisResult['findings'], blast: AnalysisResult['blast'], exceptions: PolicyException[] = [], now: Date): PolicyException[] {
  const today = now.toISOString().slice(0, 10);
  const expired = new Set<PolicyException>();
  // A well-formed exception names a resource and expires on a real YYYY-MM-DD date. Anything else is
  // treated as expired, so a typo can never become a permanent exemption.
  const valid = isWellFormed;
  const match = (rule: string, resource: string) =>
    exceptions.filter((e) => (!e?.rule || e.rule === rule) && typeof e?.resource === 'string' && globMatch(e.resource, resource));
  const accept = (hits: PolicyException[]) => {
    const live = hits.find((e) => valid(e) && e.expires >= today);
    for (const e of hits) if (!valid(e) || e.expires < today) expired.add(e);
    return live ? { reason: live.reason, owner: live.owner, expires: live.expires } : undefined;
  };
  for (const f of findings) {
    const a = accept(match(f.ruleId, f.resource));
    if (a) f.accepted = a;
  }
  for (const b of blast) {
    const a = accept(match('blast-radius', b.resource));
    if (a) b.accepted = a;
  }
  return [...expired];
}

function decideGate(findings: AnalysisResult['findings'], blast: AnalysisResult['blast'], blockOn: PolicyConfig['blockOn']): Gate {
  const reasons: string[] = [];
  const blocking = blast.filter((b) => !b.accepted && blockOn?.includes(b.severity));
  for (const b of blocking) reasons.push(`${b.severity}: ${b.resource}: ${b.reason}`);
  if (blocking.length) return { result: 'block', reasons };

  // CRITICAL rows that policy chose not to block are still reviewed, never passed.
  const highBlast = blast.filter((b) => (b.severity === 'HIGH' || b.severity === 'CRITICAL') && !b.accepted);
  const newFails = findings.filter((f) => f.status === 'FAIL' && !f.preExisting && !f.accepted);
  for (const b of highBlast) reasons.push(`${b.severity}: ${b.resource}: ${b.reason}`);
  for (const f of newFails) reasons.push(`FAIL ${f.ruleId}: ${f.resource}: ${f.detail}`);
  return { result: reasons.length ? 'review' : 'pass', reasons };
}

