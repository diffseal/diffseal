import { addGateItem, type Gate } from './core/model.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { analyze } from './analysis/analyze.js';
import { readPlan } from './plan/readPlan.js';
import { renderMarkdown } from './report/markdown.js';
import { VERSION, renderReplay, replayJson } from './replay/render.js';
import { replayCommit } from './replay/replay.js';
import { uploadRun, uploadComment } from './action/upload.js';
import { artifactName, artifactPlace, writeReports } from './action/report.js';
import type { ReplayResult } from './replay/replay.js';
import { upsertComment } from './action/comment.js';
import { actionExitCode, eventBase, needsBase, pullRequestBase, readPolicy } from './action/inputs.js';

function eventBaseSha(): string | undefined {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  return eventPath ? eventBase(JSON.parse(fs.readFileSync(eventPath, 'utf8'))) : undefined;
}

function pullRequestNumber(): number | undefined {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) return undefined;
  return (JSON.parse(fs.readFileSync(eventPath, 'utf8')) as { pull_request?: { number: number } }).pull_request?.number;
}

/*
 * GitHub Action entrypoint. Inputs arrive as INPUT_* environment variables (never interpolated into a
 * shell). The step summary is always written before the exit code is decided, so a failing gate still
 * shows its report.
 */


function input(name: string, fallback = ''): string {
  return (process.env[`INPUT_${name.toUpperCase()}`] ?? fallback).trim();
}

function setOutput(name: string, value: string) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

/** Printed for the removed application code check, so an old workflow fails with one clear line. */
const APP_MODE_REMOVED = 'mode: app was removed in v0.6.0-beta; Diffseal reviews Terraform only';

async function main(): Promise<number> {
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const mode = input('mode', 'pr');
  if (mode === 'app') {
    console.error(APP_MODE_REMOVED);
    return 1;
  }
  const policyPath = input('policy');
  const base = needsBase(mode, policyPath) ? pullRequestBase(workspace, input('base'), eventBaseSha()) : undefined;
  const { policy, changed: policyChanged } = policyPath ? readPolicy(workspace, policyPath, base) : { policy: {}, changed: false };

  let markdown: string;
  // The report kept as a file has every row; the summary and comment are limited to fit a comment.
  // Rendered only when written, so a failure there cannot stop the review.
  let fullMarkdown: () => string;
  let gate: 'pass' | 'review' | 'block';
  let hasReport = true;
  let replay: ReplayResult | undefined;
  let json: unknown;
  if (mode === 'plan') {
    const planFile = path.resolve(workspace, input('plan-json', 'tfplan.json'));
    const result = analyze(readPlan(JSON.parse(fs.readFileSync(planFile, 'utf8'))), { policy });
    if (policyChanged) reviewPolicyChange(result.gate, policyPath);
    const meta = { title: `Plan review of \`${path.basename(planFile)}\`.`, version: VERSION };
    markdown = renderMarkdown(result, meta);
    fullMarkdown = () => renderMarkdown(result, { ...meta, full: true });
    gate = result.gate.result;
    json = result;
  } else if (mode === 'pr') {
    const r = await replayCommit({
      repo: workspace,
      moduleCache: input('module-cache') ? path.resolve(workspace, input('module-cache')) : undefined,
      head: 'HEAD',
      base,
      // Replay reads the policy file from the same base it compares with, also when the event has no
      // pull request base (a push or a merge queue run without one compares with HEAD^1).
      policyFile: policyPath ? path.relative(workspace, path.resolve(workspace, policyPath)) : undefined,
      // A live check: exceptions are judged now, not on a commit date the author controls.
      now: new Date(),
      rootsUnder: input('roots-under') || undefined,
    });
    replay = r;
    markdown = renderReplay(r, { commit: false });
    fullMarkdown = () => renderReplay(r, { commit: false, full: true });
    gate = r.combined.gate.result;
    hasReport = Boolean(r.roots.length || r.combined.gate.reasons.length || policyChanged);
    json = replayJson(r);
  } else {
    throw new Error(`Unknown mode "${mode}". Use pr or plan.`);
  }

  // The artifact a later workflow step keeps the full reports in, named after the commit reviewed.
  const artifact = artifactName(replay?.commit.sha ?? process.env.GITHUB_SHA);
  let fullRecord: string | undefined;
  const uploaded = await uploadRun({
    upload: input('upload'),
    url: input('upload-url', 'https://api.diffseal.com'),
    mode,
    eventName: process.env.GITHUB_EVENT_NAME,
    event: process.env.GITHUB_EVENT_PATH ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')) : undefined,
    advisory: input('advisory', 'false') === 'true',
    replay,
    // Only a workflow that keeps the artifact sets report-artifact, so the record names it only then.
    artifact: input('report-artifact', 'false') === 'true' ? artifactPlace(artifact, process.env) : undefined,
    onRecord: (text) => { fullRecord = text; },
  });
  if (uploaded) setOutput('upload-id', uploaded.id);
  markdown = uploadComment(markdown, gate, uploaded);
  // The outputs are set only once the reports are written, so a workflow uploads them only after a review.
  try {
    const dir = writeReports(process.env.RUNNER_TEMP || os.tmpdir(), { json, markdown: uploadComment(fullMarkdown(), gate, uploaded), record: fullRecord });
    setOutput('report-dir', dir);
    setOutput('artifact-name', artifact);
  } catch (e) {
    console.warn(`Diffseal: the full report could not be written: ${(e as Error).message}`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
  setOutput('gate', gate);
  if (input('comment', 'true') === 'true') {
    try {
      const pr = pullRequestNumber();
      if (pr && input('github-token')) {
        await upsertComment(markdown, {
          api: process.env.GITHUB_API_URL ?? 'https://api.github.com',
          repo: process.env.GITHUB_REPOSITORY ?? '',
          pr,
          token: input('github-token'),
          author: input('comment-author', 'github-actions[bot]'),
          onlyUpdate: !hasReport,
        });
      }
    } catch (e) {
      console.warn(`Diffseal: ${(e as Error).message}. Give the job pull-requests: write, or set comment: false.`);
    }
  }
  console.log(`Diffseal gate: ${gate}`);
  const strict = input('strict', 'false') === 'true';
  const advisory = input('advisory', 'false') === 'true';
  return actionExitCode(gate, { strict, advisory });
}

/** Replay mode adds its own reason for a changed policy file; plan mode gets it here, before rendering. */
function reviewPolicyChange(gate: Gate, policyPath: string): void {
  if (gate.result === 'pass') gate.result = 'review';
  addGateItem(gate, { kind: 'policy', level: 'review', text: `${policyPath} changed in this pull request. Diffseal applied the version on the base branch. The new version applies once this pull request is merged.` });
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`Diffseal: ${(e as Error).message}`);
    process.exit(1);
  }
);
