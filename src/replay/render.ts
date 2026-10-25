import type { AppLink } from '../reconcile/reconcile.js';
import type { AppLinkRow } from '../report/markdown.js';
import { renderMarkdown } from '../report/markdown.js';
import { shortRootLabels, type ReplayResult } from './replay.js';

export const VERSION = '0.2.0-beta';

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

export function renderReplay(r: ReplayResult): string {
  const appLinks = appLinkRows(r.appLinks);
  const likely = r.combined.changes.filter((c) => c.confidence !== 'proven').length;
  const notes = [
    `Static replay of ${r.base.slice(0, 9)}..${r.head.slice(0, 9)}: configuration at both commits was evaluated without state, credentials or provider calls.`,
    `Roots: ${r.roots.map((x) => x.root).join(', ') || 'none affected'}.`,
  ];
  if (likely) notes.push(`${likely} change(s) depend on values only known after apply; their action is likely, not proven.`);
  const diagnostics = r.roots.flatMap((x) => x.diagnostics);
  if (diagnostics.length) notes.push(`HCL diagnostics: ${diagnostics.slice(0, 3).join('; ')}${diagnostics.length > 3 ? ' ...' : ''}`);
  return renderMarkdown(r.combined, {
    title: `${r.commit.sha.slice(0, 9)} ${r.commit.subject}`,
    subtitle: `${r.commit.author}, ${r.commit.date.slice(0, 10)}. ${r.terraformFiles.length} Terraform file(s) changed.`,
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
