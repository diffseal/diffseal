import type { AnalysisResult, BlastFinding, Finding, Severity } from '../core/model.js';

export interface ReportMeta {
  /** One line of context under the heading, e.g. "Plan review of `tfplan.json`." Markdown, not escaped. */
  title?: string;
  /** Short caveats for the footer, e.g. static-analysis assumptions. */
  notes?: string[];
  version?: string;
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

/**
 * Plain text for a table cell or a sentence: one line, no HTML, and no emphasis. A resource pattern
 * like provider/*\/name must keep its asterisks; underscores inside identifiers cannot form emphasis.
 */
export function cell(v: unknown): string {
  return String(v ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .replace(/</g, '&lt;')
    .replace(/[*~]/g, '\\$&')
    .replace(/(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])/g, '\\_')
    .trim();
}

/** Inline code on one line: a line break in a path or address must not start a new Markdown block. */
const code = (s: string) => '`' + s.replace(/`/g, "'").replace(/\r\n|\r|\n/g, ' ') + '`';
/** Inline code inside a table row, where GFM splits cells on a pipe even within a code span. */
const codeCell = (s: string) => code(s).replace(/\|/g, '\\|');

export function renderMarkdown(result: AnalysisResult, meta: ReportMeta): string {
  const out: string[] = [];
  const attention = result.findings.filter((f) => !f.preExisting && !f.accepted && (f.status === 'FAIL' || f.status === 'WARN' || f.status === 'UNKNOWN'));

  out.push(`## Diffseal: ${GATE_LABEL[result.gate.result]}`);
  if (meta.title) out.push('', meta.title);
  const callout = renderCallout(result.gate, { blast: result.blast, findings: result.findings });
  if (callout.length) out.push('', ...callout);
  out.push('', summaryLine(result, attention));

  const notable = result.blast.filter((b) => b.severity !== 'INFO' || b.action !== 'create');
  if (result.blast.length) {
    out.push('', '### Resources', '', '| Risk | Resource | Action | Why |', '| :-- | :-- | :-- | :-- |');
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
      out.push(`| ${codeCell(i.resource)} | ${i.monthlyDeltaUsd === undefined ? 'n/a' : formatUsd(i.monthlyDeltaUsd)} | ${cell(i.note)} |`);
    }
  }

  const evidence = result.findings.filter((f) => !attention.includes(f));
  if (evidence.length) {
    out.push('', `<details><summary>${evidenceSummary(evidence)}</summary>`, '');
    out.push('| Status | Check | Resource | Detail | Controls |', '| :-- | :-- | :-- | :-- | :-- |');
    for (const f of sortFindings(evidence).slice(0, 150)) out.push(findingRow(f));
    out.push('', '</details>');
  }

  const notes = [...(meta.notes ?? []), ...(costRows.length ? [result.cost.basis] : [])];
  out.push('', '---', footer(meta.version, notes));

  let md = out.join('\n') + '\n';
  if (md.length > MAX_CHARS) {
    md = md.slice(0, MAX_CHARS) + '\n\n_Report truncated to fit a GitHub comment. Use `--json` for the full result._\n';
  }
  return md;
}

/** "1 change", "2 changes". */
const plural = (n: number, word: string, many = word + 's') => `${n} ${n === 1 ? word : many}`;

/** Explains what the footer leaves out: how Diffseal reads Terraform, proven and likely, the controls. */
export const HOW_IT_WORKS = 'https://github.com/diffseal/diffseal/blob/main/docs/guide/faq.md';

/** One line of facts about this report. Every comment repeats it, so general explanations live behind the link. */
export function footer(version: string | undefined, notes: string[]): string {
  return `<sub>${[`Diffseal${version ? ' ' + version : ''}.`, ...notes.map(cell), `[How it works](${HOW_IT_WORKS})`].join(' ')}</sub>`;
}

const CALLOUT: Record<'review' | 'block', [kind: string, lead: string]> = {
  block: ['CAUTION', 'Blocked. Check these before merging:'],
  review: ['WARNING', 'Check these before merging:'],
};

/**
 * The gate's reasons as a GitHub alert box. Reasons built from a change or finding are
 * rewritten as a sentence naming it; any other reason is shown as written.
 */
function renderCallout(
  gate: AnalysisResult['gate'],
  from: { blast?: BlastFinding[]; findings?: Finding[] }
): string[] {
  if (gate.result === 'pass') return [];
  const known = new Map<string, string>();
  // With several roots, the replay puts the same root label in front of the resource and the reason.
  for (const b of from.blast ?? []) {
    for (const [label, addr] of labelSplits(b.resource)) known.set(`${label}${b.severity}: ${addr}: ${b.reason}`, `${rootLabel(label)}${code(addr)}: ${cell(b.reason)}`);
  }
  for (const f of from.findings ?? []) {
    for (const [label, addr] of labelSplits(f.resource)) known.set(`${label}FAIL ${f.ruleId}: ${addr}: ${f.detail}`, `${rootLabel(label)}${code(addr)}: ${cell(f.title)}. ${cell(f.detail)}`);
  }
  const items = [...new Set(gate.reasons.map((r) => known.get(r) ?? cell(r)))];
  const [kind, lead] = CALLOUT[gate.result];
  return [
    `> [!${kind}]`,
    `> **${lead}**`,
    '>',
    ...items.slice(0, 8).map((i) => `> - ${i}`),
    ...(items.length > 8 ? [`> - ...and ${items.length - 8} more`] : []),
  ];
}

const rootLabel = (label: string) => (label ? `${cell(label)} ` : '');

/** Every way to read "label: address" as a root label prefix and an address, including no label. */
function labelSplits(resource: string): [label: string, address: string][] {
  const out: [string, string][] = [['', resource]];
  for (let i = resource.indexOf(': '); i >= 0; i = resource.indexOf(': ', i + 1)) out.push([resource.slice(0, i + 2), resource.slice(i + 2)]);
  return out;
}

const DONE: Record<string, string> = { create: 'created', update: 'updated', replace: 'replaced', delete: 'deleted' };

function summaryLine(result: AnalysisResult, attention: Finding[]): string {
  const counts = countBy(result.changes.map((c) => c.action));
  const parts = [Object.keys(counts).length ? `Changes: ${Object.entries(counts).map(([a, n]) => `${n} ${DONE[a] ?? a}`).join(', ')}.` : 'No resource changes.'];
  if (attention.length) parts.push(`${plural(attention.length, 'finding')} to review.`);
  if (result.cost.fixedMonthlyDeltaUsd !== 0) parts.push(`Fixed monthly cost: ${formatUsd(result.cost.fixedMonthlyDeltaUsd)}.`);
  return parts.join(' ');
}

function evidenceSummary(fs: Finding[]): string {
  const n = (p: (f: Finding) => boolean) => fs.filter(p).length;
  const parts = [
    [n((f) => f.accepted !== undefined), 'accepted'],
    [n((f) => !f.accepted && f.preExisting === true), 'pre-existing'],
    [n((f) => !f.accepted && !f.preExisting && f.status === 'PASS'), 'passed'],
    [n((f) => !f.accepted && !f.preExisting && f.status !== 'PASS'), 'informational'],
  ].filter(([k]) => k) as [number, string][];
  return `${plural(fs.length, 'other check')}: ${parts.map(([k, w]) => `${k} ${w}`).join(', ')}`;
}

const acceptedNote = (a: { reason: string; owner?: string; expires: string }) => `accepted until ${a.expires}${a.owner ? ` by ${a.owner}` : ''}: ${a.reason}`;

function blastRow(b: BlastFinding): string {
  const severity = b.accepted ? `${b.severity} (accepted)` : b.severity;
  const reason = b.accepted ? `${b.reason}. ${acceptedNote(b.accepted)}` : b.reason;
  return `| ${severity} | ${codeCell(b.resource)} | ${b.action}${b.confidence ? ` (${b.confidence})` : ''} | ${cell(reason)} |`;
}

function findingRow(f: Finding): string {
  const controls = f.controls.map((c) => c.replace('ISO27001:', '').replace('SOC2:', 'SOC 2 ')).join(', ');
  if (f.accepted) {
    return `| ${f.status} (accepted) | ${cell(f.title)} | ${codeCell(f.resource)} | ${cell(`${f.detail}. ${acceptedNote(f.accepted)}`)} | ${controls} |`;
  }
  const status = f.preExisting ? `${f.status} (pre-existing)` : f.status;
  const detail = f.remediation ? `${f.detail}. Fix: ${f.remediation}` : f.detail;
  return `| ${status} | ${cell(f.title)} | ${codeCell(f.resource)} | ${cell(detail)} | ${controls} |`;
}

function sortFindings(fs: Finding[]): Finding[] {
  const order = ['FAIL', 'WARN', 'UNKNOWN', 'INFO', 'PASS'];
  return [...fs].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.resource.localeCompare(b.resource));
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
