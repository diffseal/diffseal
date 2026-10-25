import * as path from 'node:path';
import type { CheckAppResult } from '../app/checkApp.js';
import { VERSION, appLinkRows } from '../replay/render.js';
import { cell, renderSuggestions } from './markdown.js';

const ORDER = ['NOT_GRANTED', 'MISSING', 'UNRESOLVED', 'GRANTED'];

export function renderAppCheck(r: CheckAppResult): string {
  const rows = appLinkRows(r.links).sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));
  const count = (st: string) => rows.filter((x) => x.status === st).length;
  return [
    `## TerraTrust: what ${path.basename(path.resolve(r.app))} needs from AWS`,
    '',
    `**Gate: ${r.gate.result.toUpperCase()}**`,
    '',
    '| Granted | Not granted | Missing env | Unresolved |',
    '| :-- | :-- | :-- | :-- |',
    `| ${count('GRANTED')} | ${count('NOT_GRANTED')} | ${count('MISSING')} | ${count('UNRESOLVED')} |`,
    '',
    rows.length ? '| Status | Code | Access | Detail |\n| :-- | :-- | :-- | :-- |' : 'No AWS SDK calls or infrastructure env vars found.',
    ...rows.map((l) => `| ${l.status.replace('_', ' ')} | \`${l.callsite}\` | ${cell(l.access)} | ${cell(l.detail)} |`),
    ...renderSuggestions(r.links.flatMap((l) => (l.suggestion ? [l.suggestion] : []))),
    '',
    '---',
    ...[...r.notes, `Infrastructure: ${r.infra}, ${r.roots.length} Terraform root(s).`].map((n) => `<sub>${cell(n)}</sub><br>`),
    `<sub>TerraTrust ${VERSION}</sub>`,
    '',
  ].join('\n');
}
