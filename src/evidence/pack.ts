/** Unsigned evidence exports. The replay engine reads Git objects, never the working tree. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { assertOutsideRepo, protectedRoots, writeOutput } from '../io/output.js';
import { git } from '../terraform/source.js';
import { replayCommit } from '../replay/replay.js';
import { CSV_HEADER, csvRow, toCsv, VERSION } from '../replay/render.js';
import { REPLACE_CATALOG_SOURCE } from '../terraform/replaceCatalog.js';
import { changeRecord, manifest, type Approvals, type ChangeRecord } from './changeRecord.js';
const json = (v: unknown) => JSON.stringify(v, null, 2) + '\n';
const md = (v: unknown) =>
  String(v ?? 'not supplied')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*_[\]{}()|#!]/g, '\\$&')
    .replace(/[\r\n]+/g, ' ');
export interface EvidenceOptions {
  repo: string;
  since: string;
  until: string;
  outDir: string;
  approvals?: Map<string, Approvals>;
}
export interface EvidenceResult {
  selected: number;
  records: number;
  failures: number;
  outDir: string;
  signing: { manifestPath: string; sha256: string };
}
/** Paid sealing can sign these exact manifest bytes after verifying pack scope and completeness. No key is read here. */
export function evidenceSigningInput(outDir: string): Buffer {
  return fs.readFileSync(path.join(outDir, 'MANIFEST.sha256'));
}
export async function evidencePack(opts: EvidenceOptions): Promise<EvidenceResult> {
  const bound = (text: string): number => {
    const m = text.match(/^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?$/);
    if (!m) throw new Error('Evidence dates must be YYYY-MM-DD or RFC3339 with a timezone');
    const [year, month, day] = m.slice(1, 4).map(Number),
      leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (
      month < 1 ||
      month > 12 ||
      day < 1 ||
      day > days[month - 1] ||
      (m[4] !== undefined && (Number(m[4]) > 23 || Number(m[5]) > 59 || Number(m[6]) > 59))
    )
      throw new Error('Invalid evidence calendar date');
    return Date.parse(text);
  };
  const since = bound(opts.since),
    until = bound(opts.until);
  if (!Number.isFinite(since) || !Number.isFinite(until) || until <= since)
    throw new Error('evidence needs a valid --since before --until');
  for (const [sha, approval] of opts.approvals ?? []) {
    const valid =
      /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(sha) &&
      approval &&
      typeof approval === 'object' &&
      Array.isArray(approval.approvedBy) &&
      approval.approvedBy.every(
        (r) =>
          r &&
          typeof r.login === 'string' &&
          r.login.trim().length > 0 &&
          (!r.at || (typeof r.at === 'string' && r.at.includes('T') && Number.isFinite(bound(r.at)))),
      ) &&
      (approval.pr === undefined || (Number.isSafeInteger(approval.pr) && approval.pr > 0)) &&
      (approval.mergedBy === undefined ||
        (typeof approval.mergedBy === 'string' && approval.mergedBy.trim().length > 0));
    if (!valid)
      throw new Error('Invalid approvals entry: use full commit SHAs and an approvedBy array of reviewer objects');
  }
  const head = git(opts.repo, ['rev-parse', '--verify', 'HEAD^{commit}']).trim();
  const commits = git(opts.repo, ['rev-list', '--first-parent', '--reverse', '--timestamp', head, '--'])
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [time, sha] = line.split(' ');
      return { time: Number(time) * 1000, sha };
    })
    .filter((c) => c.time >= since && c.time < until);
  const outDir = path.resolve(opts.outDir),
    protect = protectedRoots([opts.repo]);
  assertOutsideRepo(outDir, protect);
  if (fs.existsSync(outDir) && (!fs.statSync(outDir).isDirectory() || fs.readdirSync(outDir).length))
    throw new Error('Evidence output must be a new or empty folder');
  fs.mkdirSync(path.dirname(outDir), { recursive: true });
  const stage = fs.mkdtempSync(path.join(path.dirname(outDir), '.evidence-'));
  const digests = new Map<string, string>();
  const emit = (name: string, content: string) => {
    writeOutput(path.join(stage, name), content, protect);
    digests.set(name, manifest({ [name]: content }).trimEnd());
  };
  const rows = [CSV_HEADER],
    population: string[] = [],
    errors: Array<{ commit: string; error: string }> = [];
  const gates: Record<string, number> = { pass: 0, review: 0, block: 0 };
  const changes: Record<string, number> = {};
  const controls = new Map<string, Record<string, number>>(),
    exceptions = new Map<string, string>();
  let records = 0,
    approved = 0,
    supplied = 0;
  try {
    fs.mkdirSync(path.join(stage, 'records'));
    for (const { sha } of commits) {
      const approvals = opts.approvals?.get(sha);
      if (approvals) {
        supplied++;
        if (approvals.approvedBy.length) approved++;
      }
      let replay;
      try {
        replay = await replayCommit({ repo: opts.repo, head: sha });
      } catch (e) {
        const error = (e as Error).message;
        errors.push({ commit: sha, error });
        rows.push([sha, '', '', '', 'error', '', '', '', '', '', '', '', '', '']);
        population.push(`| ${sha} | ERROR | ${md(error)} |`);
        continue;
      }
      const record = changeRecord({
        commit: replay.commit,
        base: replay.base,
        roots: replay.roots.map((r) => r.root),
        result: replay.combined,
        appLinks: replay.appLinks,
        approvals,
        engine: { version: VERSION, replaceCatalog: REPLACE_CATALOG_SOURCE },
        diagnostics: replay.roots.flatMap((r) => r.diagnostics),
      });
      emit(`records/${sha}.json`, json(record));
      records++;
      gates[record.gate.result]++;
      rows.push(csvRow(replay));
      population.push(
        `| [${sha.slice(0, 9)}](records/${sha}.json) | ${record.gate.result.toUpperCase()} | ${md(record.change.subject)} |`,
      );
      for (const resource of record.resources) changes[resource.action] = (changes[resource.action] ?? 0) + 1;
      for (const control of record.controls) {
        const total = controls.get(control.control) ?? {};
        total[control.status] = (total[control.status] ?? 0) + 1;
        if (control.accepted) total.ACCEPTED = (total.ACCEPTED ?? 0) + 1;
        controls.set(control.control, total);
      }
      for (const item of [...record.controls, ...record.risks]) {
        const a = item.accepted as { reason?: string; owner?: string; expires?: string } | undefined;
        if (!a) continue;
        const key = JSON.stringify([sha, item.resource, a]);
        exceptions.set(
          key,
          `| ${sha.slice(0, 9)} | ${md(item.resource)} | ${md(a.owner)} | ${md(a.expires)} | ${md(a.reason)} |`,
        );
      }
    }
    const approvalPercent = commits.length ? Math.round((100 * approved) / commits.length) : 0;
    const scope = {
      schema: 'diffseal.evidence-pack/v1',
      repository: path.basename(path.resolve(opts.repo)),
      head,
      since: new Date(since).toISOString(),
      until: new Date(until).toISOString(),
      selection: 'first-parent commits, committer time, inclusive since and exclusive until',
      selected: commits.length,
      records,
      failures: errors.length,
      complete: errors.length === 0,
      approvals: {
        supplied,
        withReviewers: approved,
        missing: commits.length - supplied,
        provenance: 'caller-supplied, not independently verified',
      },
      engine: { version: VERSION, replaceCatalog: REPLACE_CATALOG_SOURCE },
      signing: { status: 'unsigned', payload: 'MANIFEST.sha256', encoding: 'utf8', hook: 'evidenceSigningInput' },
    };
    emit('pack.json', json(scope));
    const safeRows = rows.map((row, i) =>
      row.map((value, col) => {
        const text = value.replace(/\r\n?/g, '\n');
        return i > 0 && [2, 3, 13].includes(col) && /^\s*[=+@-]/.test(text) ? "'" + text : text;
      }),
    );
    emit('summary.csv', toCsv(safeRows));
    if (errors.length) emit('errors.json', json(errors));
    emit(
      'index.md',
      `# Evidence pack\n\nPeriod: ${scope.since} inclusive to ${scope.until} exclusive, UTC. Commit selection uses committer timestamps; the dates in change records are the original author timestamps.\n\nSelected commits: ${commits.length}. Records: ${records}. Failed replays: ${errors.length}.\n\n${errors.length ? 'INCOMPLETE: failed commits are listed in errors.json.' : 'All selected first-parent commits were replayed, including commits with no infrastructure findings.'}\n\nCompleteness refers to replay coverage, not full understanding of every input. Review per-record notes and unknown results.\n\nThis pack is unsigned. Its hashes detect changes but do not authenticate its author. Approvals are supplied metadata, not verified GitHub evidence. Static analysis is not a certification of compliance or proof of a deployed change.\n\n## Gates\n\n| Gate | Commits |\n| --- | --- |\n${Object.entries(
        gates,
      )
        .map(([g, n]) => `| ${g.toUpperCase()} | ${n} |`)
        .join('\n')}\n\n## Changes\n\n| Action | Resources |\n| --- | --- |\n${
        Object.entries(changes)
          .sort()
          .map(([a, n]) => `| ${md(a)} | ${n} |`)
          .join('\n') || '| none | 0 |'
      }\n\n## Findings by control (ISO 27001 and SOC 2)\n\nCounts include pre-existing checks and may count the same resource under several controls. Accepted findings are also counted under their original status.\n\n| Control | PASS | WARN | FAIL | UNKNOWN | INFO | Accepted |\n| --- | --- | --- | --- | --- | --- | --- |\n${
        [...controls]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([c, n]) => `| ${md(c)} | ${n.PASS ?? 0} | ${n.WARN ?? 0} | ${n.FAIL ?? 0} | ${n.UNKNOWN ?? 0} | ${n.INFO ?? 0} | ${n.ACCEPTED ?? 0} |`)
          .join('\n') || '| none | 0 | 0 | 0 | 0 | 0 | 0 |'
      }\n\n## Exceptions used at the time of the change\n\n| Commit | Resource | Owner | Expiry | Reason |\n| --- | --- | --- | --- | --- |\n${[...exceptions.values()].join('\n') || '| none | | | | |'}\n\n## Approvals coverage\n\nCommits with supplied reviewers: ${approved} / ${commits.length} (${approvalPercent}%). Supplied entries: ${supplied}. No supplied entry: ${commits.length - supplied}. An empty reviewer list is not counted as approved.\n\n## Population\n\n| Commit | Gate | Subject or replay error |\n| --- | --- | --- |\n${population.join('\n')}\n\nScope and signing hook: pack.json. Verify every entry in MANIFEST.sha256 before using this evidence.\n`,
    );
    const seal =
      [...digests.keys()]
        .sort()
        .map((name) => digests.get(name))
        .join('\n') + '\n';
    writeOutput(path.join(stage, 'MANIFEST.sha256'), seal, protect);
    fs.renameSync(stage, outDir);
    return {
      selected: commits.length,
      records,
      failures: errors.length,
      outDir,
      signing: {
        manifestPath: path.join(outDir, 'MANIFEST.sha256'),
        sha256: createHash('sha256').update(seal).digest('hex'),
      },
    };
  } catch (e) {
    fs.rmSync(stage, { recursive: true, force: true });
    throw e;
  }
}
