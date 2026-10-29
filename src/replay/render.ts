import type { AppLink } from '../reconcile/reconcile.js';
import type { AppLinkRow } from '../report/markdown.js';
import { cell, renderMarkdown } from '../report/markdown.js';
import { shortRootLabels, type ReplayResult } from './replay.js';

export const VERSION = '0.5.5-beta';

/** App links as report rows; identical results in several roots become one row naming the roots. */
export function appLinkRows(links: AppLink[]): AppLinkRow[] {
  const labels = shortRootLabels([...new Set(links.flatMap((l) => (l.root ? [l.root] : [])))]);
  const groups = new Map<string, { link: AppLink; roots: string[] }>();
  for (const l of links) {
    const k = JSON.stringify([l.status, l.callsite, l.access, l.detail.replace(/\(([^)]*), [^ ]+:\d+\)/, '($1)')]);
    const g = groups.get(k);
    if (g) g.roots.push(l.root ?? '');
    else groups.set(k, { link: l, roots: [l.root ?? ''] });
  }
  return [...groups.values()].map(({ link, roots }) => {
    const where = roots.filter(Boolean).map((r) => labels[r] || r).join(', ');
    return { status: link.status, callsite: link.callsite, access: link.access, detail: where ? `${where}: ${link.detail}` : link.detail };
  });
}

/**
 * The replay report. A pull request check passes `commit: false`: there the head is the merge commit
 * GitHub creates, and its subject and author say nothing about the change.
 */
export function renderReplay(r: ReplayResult, opts: { commit?: boolean } = {}): string {
  const appLinks = appLinkRows(r.appLinks);
  // Only facts about this change: which commits were compared, and the roots when the resource names do not say.
  const notes = [`Compared \`${r.base.slice(0, 9)}\` with \`${r.head.slice(0, 9)}\`.`];
  if (r.roots.length > 1) notes.push(`Roots: ${r.roots.map((x) => x.root).join(', ')}.`);
  const diagnostics = r.roots.flatMap((x) => x.diagnostics);
  if (diagnostics.length) notes.push(`HCL diagnostics: ${diagnostics.slice(0, 3).join('; ')}${diagnostics.length > 3 ? ' ...' : ''}`);
  const c = r.commit;
  return renderMarkdown(r.combined, {
    title: opts.commit === false ? undefined : `Commit \`${c.sha.slice(0, 9)}\` ${cell(c.subject)}, by ${cell(c.author)} on ${c.date.slice(0, 10)}.`,
    notes,
    appLinks,
    suggestions: r.appLinks.flatMap((l) => (l.suggestion ? [l.suggestion] : [])),
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
