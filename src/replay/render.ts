import { cell, renderMarkdown } from '../report/markdown.js';
import { rootNames, type ReplayResult } from './replay.js';

export const VERSION = '0.6.0-beta';

/**
 * The replay report. A pull request check passes `commit: false`: there the head is the merge commit
 * GitHub creates, and its subject and author say nothing about the change.
 */
export function renderReplay(r: ReplayResult, opts: { commit?: boolean } = {}): string {
  // Only facts about this change: which commits were compared, and the roots when the resource names do not say.
  const notes = [`Compared \`${r.base.slice(0, 9)}\` with \`${r.head.slice(0, 9)}\`.`];
  if (r.roots.length > 1 || r.roots.some((x) => x.movedFrom || x.deleted)) notes.push(`Roots: ${rootNames(r.roots).join(', ')}.`);
  const diagnostics = r.roots.flatMap((x) => x.diagnostics);
  if (diagnostics.length) notes.push(`HCL diagnostics: ${diagnostics.slice(0, 3).join('; ')}${diagnostics.length > 3 ? ' ...' : ''}`);
  const c = r.commit;
  return renderMarkdown(r.combined, {
    title: opts.commit === false ? undefined : `Commit \`${c.sha.slice(0, 9)}\` ${cell(c.subject)}, by ${cell(c.author)} on ${c.date.slice(0, 10)}.`,
    notes,
    version: VERSION,
  });
}

/** One CSV row per replayed commit: the change population an auditor samples from. */
export function csvRow(r: ReplayResult): string[] {
  const c = r.combined;
  const by = (a: string) => c.changes.filter((x) => x.action === a).length;
  return [
    r.commit.sha,
    r.commit.date,
    r.commit.author,
    r.commit.subject,
    c.gate.result,
    String(by('create')),
    String(by('update')),
    String(by('replace')),
    String(by('delete')),
    String(c.blast.filter((b) => b.severity === 'CRITICAL' || b.severity === 'HIGH').length),
    String(c.findings.filter((f) => f.status === 'FAIL' && !f.preExisting).length),
    String(c.findings.filter((f) => f.status === 'WARN' && !f.preExisting).length),
    c.cost.fixedMonthlyDeltaUsd.toFixed(2),
    r.roots.map((x) => x.root).join(' '),
  ];
}

export const CSV_HEADER = ['commit', 'date', 'author', 'subject', 'gate', 'creates', 'updates', 'replaces', 'deletes', 'high_risk', 'new_fails', 'new_warns', 'fixed_monthly_usd', 'roots'];

export function toCsv(rows: string[][]): string {
  return rows.map((r) => r.map((v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v)).join(',')).join('\n') + '\n';
}
