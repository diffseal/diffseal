import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * The full reports of an Action run, written to files so a later workflow step can keep them as an
 * artifact. The job summary is cut short on a large change, and a large change record leaves out its
 * lowest-risk resources; these files keep everything.
 */

export const REPORT_FILES = { json: 'report.json', markdown: 'report.md', record: 'change-record.json' } as const;

/** `diffseal-` and the short commit the Action reviewed, or `diffseal-report` when it reviewed no known commit. */
export function artifactName(sha: string | undefined): string {
  return sha && /^[0-9a-f]{7,64}$/.test(sha) ? `diffseal-${sha.slice(0, 7)}` : 'diffseal-report';
}

/**
 * Where the change record says the full list is: the artifact, and the run's page when the runner gives
 * its URL. The record outlives the run, so the URL is what lets a reader find the artifact.
 */
export function artifactPlace(name: string, env: NodeJS.ProcessEnv): string {
  const server = env.GITHUB_SERVER_URL ?? '', repo = env.GITHUB_REPOSITORY ?? '', run = env.GITHUB_RUN_ID ?? '';
  const url = /^https:\/\/[A-Za-z0-9.-]+(:\d+)?$/.test(server) && /^[\w.-]+\/[\w.-]+$/.test(repo) && /^\d+$/.test(run)
    ? ` (${server}/${repo}/actions/runs/${run})`
    : '';
  return `the ${name} artifact of this run${url}`;
}

/** Writes the reports to a new directory under `parent` and returns its path. */
export function writeReports(parent: string, reports: { json: unknown; markdown: string; record?: string }): string {
  fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(path.join(parent, 'diffseal-'));
  fs.writeFileSync(path.join(dir, REPORT_FILES.json), JSON.stringify(reports.json, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, REPORT_FILES.markdown), reports.markdown);
  // The record's text as given, byte for byte: a trimmed record names its SHA-256.
  if (reports.record !== undefined) fs.writeFileSync(path.join(dir, REPORT_FILES.record), reports.record);
  return dir;
}
