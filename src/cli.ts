#!/usr/bin/env node
import { fetchModules } from './terraform/modulesFetch.js';
import { verifyPack, keySource, verificationSummary } from './evidence/verify.js';
import { evidencePack } from './evidence/pack.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from './analysis/analyze.js';
import type { AnalysisResult, PolicyConfig } from './core/model.js';
import { protectedRoots, writeOutput } from './io/output.js';
import { readPlan } from './plan/readPlan.js';
import { renderMarkdown } from './report/markdown.js';
import { CSV_HEADER, VERSION, csvRow, renderReplay, toCsv } from './replay/render.js';
import { replayCommit, rootNames, type ReplayResult } from './replay/replay.js';
import { git } from './terraform/source.js';
import { changeRecord, loadApprovals, manifest } from './evidence/changeRecord.js';
import { REPLACE_CATALOG_SOURCE } from './terraform/replaceCatalog.js';

const HELP = `Diffseal ${VERSION}: change review for Terraform on AWS

Usage:
  diffseal review    --plan <plan.json> [--out <report.md>] [--json <result.json>] [--policy <policy.json>] [--strict]
  diffseal replay    --repo <path> (--commit <rev> | --range <a..b> | --since <date>) [--limit <n>]
                       [--base <rev>] [--roots-under <dir>] [--out-dir <dir>] [--policy <policy.json>] [--approvals <file.json>]
  diffseal evidence --since <date> --until <date> --repo <path> [--approvals <file.json>] [--out-dir <folder>]
  diffseal verify <folder> [--keys <file>] [--account <login>] [--period <label>] [--allow-unsigned] [--json]
  diffseal modules fetch [--repo <path>] [--cache <dir>]
  diffseal demo
  diffseal --version

Commands:
  review     Review the output of \`terraform show -json <planfile>\`: blast radius, policy checks, fixed-cost changes.
  replay     Replay commits of a local clone without credentials or terraform. Reads git objects only, and never
             checks out, writes to, or sends anything from the repository. Reports go to --out-dir (default ./dry-runs):
             one Markdown report per commit, a change record per commit in records/ (ISO 27001 A.8.32 evidence),
             summary.csv (the change population) and MANIFEST.sha256. --approvals adds who approved each change.
  evidence   Export an unsigned audit period, inclusive since and exclusive until in UTC.
             Replays every first-parent commit in that period. An incomplete export exits 1; historic gates do not fail export.
  verify     Verify manifest, file set, Ed25519 signature, key validity and optional scope offline.
  modules    Fetch public module packages and write a verified lock file. This command uses the network.
             replay accepts --module-cache <dir> and never fetches implicitly.
  demo       Run review on the example plan in a repository checkout (development only).

Exit codes: 0 pass, 1 error, 2 gate failed (BLOCK, or REVIEW with --strict).
`;

interface Args {
  _: string[];
  flags: Map<string, string | true>;
}

const BOOLEAN_FLAGS = new Set(['--strict', '--help', '-h', '--version', '-v', '--allow-unsigned']);

function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('-')) {
      out._.push(a);
      continue;
    }
    if (BOOLEAN_FLAGS.has(a) || (argv[0] === 'verify' && a === '--json')) {
      out.flags.set(a, true);
      continue;
    }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`);
    out.flags.set(a, v);
    i++;
  }
  return out;
}

const str = (args: Args, flag: string) => {
  const v = args.flags.get(flag);
  return typeof v === 'string' ? v : undefined;
};

function loadPolicy(args: Args): PolicyConfig {
  const p = str(args, '--policy');
  return p ? (JSON.parse(fs.readFileSync(p, 'utf8')) as PolicyConfig) : {};
}

function json(value: unknown): string {
  return JSON.stringify(value, null, 2) + '\n';
}

function runReview(args: Args): number {
  const planFile = str(args, '--plan');
  if (!planFile) throw new Error('review needs --plan <tfplan.json> (the output of `terraform show -json <planfile>`)');
  const result = analyze(readPlan(JSON.parse(fs.readFileSync(planFile, 'utf8'))), { policy: loadPolicy(args) });
  const md = renderMarkdown(result, { title: `Plan review of \`${path.basename(planFile)}\`.`, version: VERSION });
  const out = str(args, '--out');
  if (out) {
    writeOutput(out, md);
    console.error(`Wrote ${out}`);
  } else {
    process.stdout.write(md);
  }
  const jsonOut = str(args, '--json');
  if (jsonOut) writeOutput(jsonOut, json(result));
  console.error(`Gate: ${result.gate.result}`);
  if (args.flags.has('--strict') && result.gate.result !== 'pass') return 2;
  return result.gate.result === 'block' ? 2 : 0;
}

function commitsToReplay(args: Args, repo: string): string[] {
  const commit = str(args, '--commit');
  if (commit) return [commit];
  const limit = str(args, '--limit');
  const range = str(args, '--range');
  const since = str(args, '--since');
  if (!range && !since) throw new Error('replay needs --commit, --range or --since');
  const revArgs = ['rev-list', '--first-parent', '--reverse', ...(since ? [`--since=${since}`] : []), range ?? 'HEAD', '--'];
  const shas = git(repo, revArgs).split('\n').filter(Boolean);
  return limit ? shas.slice(-Number(limit)) : shas;
}

async function runReplay(args: Args): Promise<number> {
  const repo = str(args, '--repo');
  if (!repo) throw new Error('replay needs --repo <path to a local clone>');
  const outDir = str(args, '--out-dir') ?? 'dry-runs';
  const protect = protectedRoots([repo]);
  const commits = commitsToReplay(args, repo);
  const policy = loadPolicy(args);
  const approvalsFile = str(args, '--approvals');
  const approvals = approvalsFile ? loadApprovals(fs.readFileSync(approvalsFile, 'utf8')) : new Map();
  const written: Record<string, string> = {};
  const emit = (name: string, content: string) => {
    writeOutput(path.join(outDir, name), content, protect);
    written[name] = content;
  };
  const rows: string[][] = [CSV_HEADER];
  const summary: string[] = [];
  let blocked = 0;
  const failed: string[] = [];

  for (const sha of commits) {
    let r: ReplayResult;
    try {
      r = await replayCommit({ repo, moduleCache: str(args, '--module-cache'), head: sha, base: str(args, '--base'), policy, rootsUnder: str(args, '--roots-under') });
    } catch (e) {
      console.error(`${sha.slice(0, 9)}: ${(e as Error).message}`);
      failed.push(sha);
      rows.push([sha, '', '', '', 'error', '', '', '', '', '', '', '', '', (e as Error).message]);
      summary.push(`| ${sha.slice(0, 9)} | error | | ${(e as Error).message.replace(/\|/g, '\\|')} |`);
      continue;
    }
    // Commits with nothing to report are left out of a range; anything with a gate reason stays in the evidence.
    if (!r.roots.length && !r.combined.gate.reasons.length && commits.length > 1) continue;
    const name = r.commit.sha.slice(0, 9);
    emit(`${name}.md`, renderReplay(r));
    emit(`${name}.json`, json(serializable(r)));
    const record = changeRecord({
      commit: r.commit,
      base: r.base,
      roots: rootNames(r.roots),
      result: r.combined,
      approvals: approvals.get(r.commit.sha) ?? approvals.get(name),
      engine: { version: VERSION, replaceCatalog: REPLACE_CATALOG_SOURCE },
      diagnostics: r.roots.flatMap((x) => x.diagnostics),
    });
    emit(`records/${r.commit.sha}.json`, json(record));
    rows.push(csvRow(r));
    summary.push(summaryLine(r.commit.sha, r.commit.subject, r.combined));
    if (r.combined.gate.result === 'block') blocked++;
    console.error(`${name} ${r.combined.gate.result.padEnd(6)} ${r.combined.changes.length} change(s)  ${r.commit.subject}`);
  }

  if (commits.length > 1) {
    emit('summary.csv', toCsv(rows));
    emit('summary.md', `# Replay summary\n\n| Commit | Gate | Changes | Subject |\n| :-- | :-- | :-- | :-- |\n${summary.join('\n')}\n`);
  }
  // A manifest of everything this run wrote, so the evidence can be checked with `shasum -a 256 -c`.
  writeOutput(path.join(outDir, 'MANIFEST.sha256'), manifest(written), protect);
  console.error(`Reports in ${path.resolve(outDir)}`);
  if (failed.length) {
    console.error(`${failed.length} commit(s) could not be replayed; they are listed as errors in the summary.`);
    return 1;
  }
  return blocked ? 2 : 0;
}

async function runEvidence(args: Args): Promise<number> {
  const repo = str(args, '--repo'), since = str(args, '--since'), until = str(args, '--until');
  if (!repo || !since || !until) throw new Error('evidence needs --repo, --since and --until');
  const approvals = str(args, '--approvals');
  const result = await evidencePack({repo,since,until,outDir:str(args,'--out-dir')??'dry-runs/evidence',approvals:approvals?loadApprovals(fs.readFileSync(approvals,'utf8')):undefined});
  console.error(`Evidence: ${result.records} records from ${result.selected} selected commits, ${result.failures} failures. Folder: ${result.outDir}`);
  return result.failures ? 1 : 0;
}

async function runDemo(): Promise<number> {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const plan = path.join(root, 'examples', 'unsafe-tfplan.json');
  if (!fs.existsSync(plan)) throw new Error('demo needs a repository checkout. Clone https://github.com/diffseal/diffseal and run bun run demo.');
  const result = analyze(readPlan(JSON.parse(fs.readFileSync(plan, 'utf8'))));
  process.stdout.write(renderMarkdown(result, { title: 'Plan review of `examples/unsafe-tfplan.json`.', version: VERSION }));
  return 0;
}

function summaryLine(sha: string, subject: string, r: AnalysisResult): string {
  return `| [${sha.slice(0, 9)}](${sha.slice(0, 9)}.md) | ${r.gate.result} | ${r.changes.length} | ${subject.replace(/\|/g, '\\|')} |`;
}

/** Drop the git sources (not serializable) from a replay result. */
function serializable(r: ReplayResult) {
  const { headSource, baseSource, ...rest } = r;
  void headSource;
  void baseSource;
  return { version: VERSION, ...rest, roots: rest.roots.map(({ root, result, diagnostics, varFile, baseVarFile, movedFrom, deleted }) => ({ root, ...(varFile ? { varFile } : {}), ...(baseVarFile ? { baseVarFile } : {}), ...(movedFrom ? { movedFrom } : {}), ...(deleted ? { deleted } : {}), result, diagnostics })) };
}

/** Printed when a removed command is used, so an old script fails with one clear line. */
const CHECK_APP_REMOVED = 'check-app was removed in v0.6.0-beta; Diffseal reviews Terraform only';

const COMMANDS = new Set(['review', 'replay', 'evidence', 'verify', 'modules', 'demo']);

export async function main(argv: string[]): Promise<number> {
  let args: Args | undefined;
  try {
    args = parseArgs(argv);
  } catch (e) {
    if (!argv.includes('check-app')) {
      console.error((e as Error).message);
      return 1;
    }
  }
  // An old check-app call, also when one of its flags came first and took the command as its value.
  if (argv.includes('check-app') && !COMMANDS.has(args?._[0] ?? '')) {
    console.error(CHECK_APP_REMOVED);
    return 1;
  }
  if (!args) return 1;
  const cmd = args._[0];
  if (args.flags.has('--version') || args.flags.has('-v')) {
    console.log(VERSION);
    return 0;
  }
  if (args.flags.has('--help') || args.flags.has('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  if (!cmd) {
    process.stdout.write(HELP);
    return 1;
  }
  try {
    if (cmd === 'modules' && args._[1] === 'fetch') {
      const lock = await fetchModules({ repo: str(args, '--repo'), cache: str(args, '--cache') });
      console.log(`Locked ${lock.modules.length} module packages`);
      return 0;
    }
    if (cmd === 'verify') {
      const folder = args._[1];
      if (!folder) throw new Error('verify needs <folder>');
      const options = { keys: str(args, '--keys'), account: str(args, '--account'), period: str(args, '--period'), allowUnsigned: args.flags.has('--allow-unsigned') };
      const result = verifyPack(folder, options);
      for (const line of keySource(options)) console.error(line);
      console.error(verificationSummary(result));
      if (args.flags.has('--json')) process.stdout.write(json(result));
      else if (result.ok) console.log('Verified.');
      else for (const failure of result.failures) console.error(failure);
      return result.ok ? 0 : 1;
    }
    if (cmd === 'review') return runReview(args);
    if (cmd === 'replay') return await runReplay(args);
    if (cmd === 'evidence') return await runEvidence(args);
    if (cmd === 'demo') return await runDemo();
    console.error(`Unknown command "${cmd}".\n`);
    process.stdout.write(HELP);
    return 1;
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    return 1;
  }
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
