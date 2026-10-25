import * as fs from 'node:fs';
import * as path from 'node:path';
import type { PolicyConfig } from '../core/model.js';
import { GitSource, git, resolveCommit } from '../terraform/source.js';

/**
 * The commit a pull request is compared with. An explicit `base` input wins. Otherwise the event's
 * base sha is used through its merge base with HEAD: for a merge checkout that is the base itself,
 * for a head checkout it is where the branch started, so commits that landed on the base branch
 * later are not counted as the pull request's own.
 */
export function pullRequestBase(workspace: string, explicit: string, eventBaseSha: string | undefined): string | undefined {
  const resolve = (rev: string) => {
    try {
      return resolveCommit(workspace, rev);
    } catch {
      throw new Error(`base commit ${rev} is not in this checkout. Check out with fetch-depth: 0 so the pull request's base is available.`);
    }
  };
  if (explicit) return resolve(explicit);
  if (!eventBaseSha) return undefined;
  return git(workspace, ['merge-base', '--end-of-options', resolve(eventBaseSha), 'HEAD']).trim();
}

/** pr and app modes compare with the base; plan mode only needs it to read the policy file. */
export function needsBase(mode: string, policyPath: string): boolean {
  return mode !== 'plan' || Boolean(policyPath);
}

/**
 * The policy file, read from the base commit so a pull request cannot relax the policy it is judged
 * by. It must be inside the repository: a path outside it has no base version to read.
 */
export function readPolicy(workspace: string, policyPath: string, base: string | undefined): { policy: PolicyConfig; changed: boolean } {
  const rel = path.relative(workspace, path.resolve(workspace, policyPath));
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`policy ${policyPath} must be a file inside the repository, so its version at the base can be read`);
  }
  const atHead = fs.existsSync(path.join(workspace, rel)) ? fs.readFileSync(path.join(workspace, rel), 'utf8') : undefined;
  const atBase = base ? new GitSource(workspace, base).readFile(rel) : atHead;
  return { policy: atBase ? (JSON.parse(atBase) as PolicyConfig) : {}, changed: atBase !== atHead };
}

/** The base sha of a pull_request or merge_group event; other events (push, dispatch) have none. */
export function eventBase(event: unknown): string | undefined {
  const e = event as { pull_request?: { base?: { sha?: unknown } }; merge_group?: { base_sha?: unknown } } | undefined;
  const sha = e?.pull_request?.base?.sha ?? e?.merge_group?.base_sha;
  return typeof sha === 'string' ? sha : undefined;
}

/** Exit code for the GitHub Action step. Advisory mode reports and comments without failing the job. */
export function actionExitCode(gate: 'pass' | 'review' | 'block', opts: { strict: boolean; advisory: boolean }): number {
  if (opts.advisory) return 0;
  return gate === 'block' || (opts.strict && gate === 'review') ? 2 : 0;
}


