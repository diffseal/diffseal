import * as fs from 'node:fs';
import * as path from 'node:path';
import { analyze } from './analysis/analyze.js';
import { checkApp } from './app/checkApp.js';
import { readPlan } from './plan/readPlan.js';
import { renderAppCheck } from './report/appCheck.js';
import { renderMarkdown } from './report/markdown.js';
import { VERSION, renderReplay } from './replay/render.js';
import { replayCommit } from './replay/replay.js';
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

async function main(): Promise<number> {
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const mode = input('mode', 'pr');
  const policyPath = input('policy');
  const base = needsBase(mode, policyPath) ? pullRequestBase(workspace, input('base'), eventBaseSha()) : undefined;
  const { policy, changed: policyChanged } = policyPath ? readPolicy(workspace, policyPath, base) : { policy: {}, changed: false };
  const roles = input('role').split(',').map((x) => x.trim()).filter(Boolean);
  const entries = input('entry').split(',').map((x) => x.trim()).filter(Boolean);

  let markdown: string;
  let gate: 'pass' | 'review' | 'block';
  let hasReport = true;
  if (mode === 'plan') {
    const planFile = path.resolve(workspace, input('plan-json', 'tfplan.json'));
    const result = analyze(readPlan(JSON.parse(fs.readFileSync(planFile, 'utf8'))), { policy });
    if (policyChanged) reviewPolicyChange(result.gate, policyPath);
    markdown = renderMarkdown(result, { title: `Plan review of \`${path.basename(planFile)}\`.`, version: VERSION });
    gate = result.gate.result;
  } else if (mode === 'app') {
    const r = await checkApp({
      app: workspace,
      moduleCache: input('module-cache') ? path.resolve(workspace, input('module-cache')) : undefined,
      rev: 'HEAD',
      base,
      infra: input('infra-path') ? path.resolve(workspace, input('infra-path')) : undefined,
      rootsUnder: input('roots-under') || undefined,
      roles,
      entries,
    });
    if (policyChanged) reviewPolicyChange(r.gate, policyPath);
    markdown = renderAppCheck(r);
    gate = r.gate.result;
    hasReport = Boolean(r.links.length || r.gate.reasons.length || policyChanged);
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
    markdown = renderReplay(r, { commit: false });
    gate = r.combined.gate.result;
    hasReport = Boolean(r.roots.length || r.appLinks.length || r.combined.gate.reasons.length || policyChanged);
  } else {
    throw new Error(`Unknown mode "${mode}". Use pr, plan or app.`);
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
      console.warn(`TerraTrust: ${(e as Error).message}. Give the job pull-requests: write, or set comment: false.`);
    }
  }
  console.log(`TerraTrust gate: ${gate}`);
  const strict = input('strict', 'false') === 'true';
  const advisory = input('advisory', 'false') === 'true';
  return actionExitCode(gate, { strict, advisory });
}

/** Replay mode adds its own reason for a changed policy file; plan and app mode get it here, before rendering. */
function reviewPolicyChange(gate: { result: 'pass' | 'review' | 'block'; reasons: string[] }, policyPath: string): void {
  if (gate.result === 'pass') gate.result = 'review';
  gate.reasons.push(`${policyPath} changed in this pull request. TerraTrust applied the version on the base branch. The new version applies once this pull request is merged.`);
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`TerraTrust: ${(e as Error).message}`);
    process.exit(1);
  }
);
