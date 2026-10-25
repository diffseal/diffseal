import type { AnalysisResult, BlastFinding, Finding, Severity } from '../core/model.js';

export interface AppLinkRow {
  status: 'GRANTED' | 'NOT_GRANTED' | 'MISSING' | 'UNRESOLVED';
  callsite: string;
  access: string;
  detail: string;
}

export interface ReportMeta {
  /** e.g. "Plan review" or "Replay of 032f697f1". */
  title: string;
  subtitle?: string;
  /** Free-form caveats shown above the footer, e.g. static-analysis assumptions. */
  notes?: string[];
  appLinks?: AppLinkRow[];
  suggestions?: Suggestion[];
  version?: string;
}

export interface Suggestion {
  target: string;
  file: string;
  line: number;
  code: string;
}

/** "Suggested fixes" section: one code block per policy, statements deduplicated. */
export function renderSuggestions(suggestions: Suggestion[]): string[] {
  if (!suggestions.length) return [];
  const byTarget = new Map<string, { s: Suggestion; code: Set<string> }>();
  for (const s of suggestions) {
    const k = `${s.file}:${s.line}:${s.target}`;
    const e = byTarget.get(k) ?? { s, code: new Set<string>() };
    e.code.add(s.code);
    byTarget.set(k, e);
  }
  const out = ['', '### Suggested fixes', ''];
  for (const { s, code } of byTarget.values()) {
    out.push(`Add to \`${s.target}\` in \`${s.file}:${s.line}\`:`, '', '```hcl', ...[...code].join('\n\n').split('\n'), '```', '');
  }
  if (suggestions.some((x) => x.code.includes('<region>') || x.code.includes('<account-id>'))) {
    out.push('<sub>Replace the `<region>` and `<account-id>` placeholders, or use a reference to the resource if Terraform manages it.</sub>');
  }
  return out;
}

/** GitHub rejects comment bodies over 65,536 characters. */
const MAX_CHARS = 60_000;
const MAX_ROWS = 40;

const GATE_LABEL: Record<AnalysisResult['gate']['result'], string> = {
  pass: 'PASS',
  review: 'REVIEW',
  block: 'BLOCK',
};

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function cell(v: unknown): string {
  return String(v ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .replace(/</g, '&lt;')
    .trim();
}

const code = (s: string) => '`' + s.replace(/`/g, "'") + '`';

export function renderMarkdown(result: AnalysisResult, meta: ReportMeta): string {
  const out: string[] = [];
  const attention = result.findings.filter((f) => !f.preExisting && !f.accepted && (f.status === 'FAIL' || f.status === 'WARN' || f.status === 'UNKNOWN'));
  const counts = countBy(result.changes.map((c) => c.action));

  out.push(`## TerraTrust: ${meta.title}`);
  if (meta.subtitle) out.push(`_${cell(meta.subtitle)}_`);
  out.push('');
  out.push(`**Gate: ${GATE_LABEL[result.gate.result]}**`);
  if (result.gate.reasons.length) {
    out.push('');
    for (const r of result.gate.reasons.slice(0, 8)) out.push(`- ${cell(r)}`);
    if (result.gate.reasons.length > 8) out.push(`- ...and ${result.gate.reasons.length - 8} more`);
  }
  out.push('');
  out.push('| Changes | Findings to review | Fixed monthly cost |');
  out.push('| :-- | :-- | :-- |');
  out.push(
    `| ${Object.entries(counts).map(([a, n]) => `${n} ${a}`).join(', ') || 'none'} | ${summarizeStatuses(attention)} | ${formatUsd(result.cost.fixedMonthlyDeltaUsd)} |`
  );

  if (meta.appLinks?.length) {
    out.push('', '### What the code needs from AWS', '', '| Status | Code | Access | Detail |', '| :-- | :-- | :-- | :-- |');
    const order = ['NOT_GRANTED', 'MISSING', 'UNRESOLVED', 'GRANTED'];
    const rows = [...meta.appLinks].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status));
    for (const l of rows.slice(0, MAX_ROWS)) out.push(`| ${l.status.replace('_', ' ')} | ${code(l.callsite)} | ${cell(l.access)} | ${cell(l.detail)} |`);
    if (rows.length > MAX_ROWS) out.push(`| | ...and ${rows.length - MAX_ROWS} more | | |`);
  }

  out.push(...renderSuggestions(meta.suggestions ?? []));

  const notable = result.blast.filter((b) => b.severity !== 'INFO' || b.action !== 'create');
  if (result.blast.length) {
    out.push('', '### Changes', '', '| Risk | Resource | Action | Why |', '| :-- | :-- | :-- | :-- |');
    const rows = [...notable, ...result.blast.filter((b) => !notable.includes(b))];
    for (const b of rows.slice(0, MAX_ROWS)) out.push(blastRow(b));
    if (rows.length > MAX_ROWS) out.push(`| | ...and ${rows.length - MAX_ROWS} more | | |`);
  }

  if (attention.length) {
    out.push('', '### Findings', '', '| Status | Check | Resource | Detail | Controls |', '| :-- | :-- | :-- | :-- | :-- |');
    for (const f of sortFindings(attention).slice(0, MAX_ROWS)) out.push(findingRow(f));
    if (attention.length > MAX_ROWS) out.push(`| | | ...and ${attention.length - MAX_ROWS} more | | |`);
  }

  const costRows = result.cost.items.filter((i) => i.kind !== 'usage');
  if (costRows.length) {
    out.push('', '### Cost', '', '| Resource | Monthly | Basis |', '| :-- | :-- | :-- |');
    for (const i of costRows.slice(0, MAX_ROWS)) {
      out.push(`| ${code(i.resource)} | ${i.monthlyDeltaUsd === undefined ? 'n/a' : formatUsd(i.monthlyDeltaUsd)} | ${cell(i.note)} |`);
    }
  }

  const evidence = result.findings.filter((f) => !attention.includes(f));
  if (evidence.length) {
    out.push('', `<details><summary>Passing, accepted and pre-existing checks (${evidence.length})</summary>`, '');
    out.push('| Status | Check | Resource | Detail | Controls |', '| :-- | :-- | :-- | :-- | :-- |');
    for (const f of sortFindings(evidence).slice(0, 150)) out.push(findingRow(f));
    out.push('', '</details>');
  }

  const notes = [...(meta.notes ?? []), ...(costRows.length ? [result.cost.basis] : [])];
  out.push('', '---');
  for (const n of notes) out.push(`<sub>${cell(n)}</sub><br>`);
  out.push(`<sub>TerraTrust ${meta.version ?? ''}. Controls cite ISO/IEC 27001:2022 Annex A; whether a check is required is set by your policy, not by the standard.</sub>`);

  let md = out.join('\n') + '\n';
  if (md.length > MAX_CHARS) {
    md = md.slice(0, MAX_CHARS) + '\n\n_Report truncated to fit a GitHub comment. Use `--json` for the full result._\n';
  }
  return md;
}

const acceptedNote = (a: { reason: string; owner?: string; expires: string }) => `accepted until ${a.expires}${a.owner ? ` by ${a.owner}` : ''}: ${a.reason}`;

function blastRow(b: BlastFinding): string {
  const severity = b.accepted ? `${b.severity} (accepted)` : b.severity;
  const reason = b.accepted ? `${b.reason}. ${acceptedNote(b.accepted)}` : b.reason;
  return `| ${severity} | ${code(b.resource)} | ${b.action} | ${cell(reason)} |`;
}

function findingRow(f: Finding): string {
  if (f.accepted) {
    return `| ${f.status} (accepted) | ${cell(f.title)} | ${code(f.resource)} | ${cell(`${f.detail}. ${acceptedNote(f.accepted)}`)} | ${f.controls.map((c) => c.replace('ISO27001:', '')).join(', ')} |`;
  }
  const status = f.preExisting ? `${f.status} (pre-existing)` : f.status;
  const detail = f.remediation ? `${f.detail}. Fix: ${f.remediation}` : f.detail;
  return `| ${status} | ${cell(f.title)} | ${code(f.resource)} | ${cell(detail)} | ${f.controls.map((c) => c.replace('ISO27001:', '')).join(', ')} |`;
}

function sortFindings(fs: Finding[]): Finding[] {
  const order = ['FAIL', 'WARN', 'UNKNOWN', 'INFO', 'PASS'];
  return [...fs].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.resource.localeCompare(b.resource));
}

function summarizeStatuses(fs: Finding[]): string {
  if (!fs.length) return 'none';
  const c = countBy(fs.map((f) => f.status));
  return ['FAIL', 'WARN', 'UNKNOWN'].filter((s) => c[s]).map((s) => `${c[s]} ${s}`).join(', ');
}

function countBy(xs: string[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const x of xs) out[x] = (out[x] ?? 0) + 1;
  return out;
}

function formatUsd(n: number): string {
  if (n === 0) return '$0';
  return `${n > 0 ? '+' : '-'}$${Math.abs(n).toFixed(2)}`;
}

export { SEVERITY_ORDER };
