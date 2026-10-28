import * as path from 'node:path';
import type { CheckAppResult } from '../app/checkApp.js';
import { VERSION, appLinkRows } from '../replay/render.js';
import { cell, footer, plural, renderAppLinks, renderCallout, renderSuggestions } from './markdown.js';

export function renderAppCheck(r: CheckAppResult): string {
  const rows = appLinkRows(r.links);
  return [
    `## Diffseal: ${r.gate.result.toUpperCase()}`,
    '',
    `What \`${cell(path.basename(path.resolve(r.app)))}\` needs from AWS.`,
    ...prefixBlank(renderCallout(r.gate, { links: rows })),
    ...(rows.length ? renderAppLinks(rows) : ['', 'No AWS SDK calls or infrastructure env vars found.']),
    ...renderSuggestions(r.links.flatMap((l) => (l.suggestion ? [l.suggestion] : []))),
    '',
    '---',
    footer(VERSION, [...r.notes, `Infrastructure: ${r.infra}, ${plural(r.roots.length, 'Terraform root')}.`]),
    '',
  ].join('\n');
}

const prefixBlank = (lines: string[]) => (lines.length ? ['', ...lines] : []);
