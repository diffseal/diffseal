import { defaultModuleCache } from '../terraform/moduleCache.js';
import { deploymentIndex } from './deployments.js';
import * as path from 'node:path';
import type { Gate } from '../core/model.js';
import { InfraIndex } from '../reconcile/infraIndex.js';
import { reconcile, type AppLink } from '../reconcile/reconcile.js';
import { discoverRoots } from '../terraform/config.js';
import { evaluateRoot } from '../terraform/expand.js';
import { FsSource, GitSource, changedPaths, resolveCommit, unifiedDiff, worktreeChanges, worktreeDiff, type FileSource } from '../terraform/source.js';
import { parseAddedLines } from './diff.js';
import { discoverLink, type DiscoveredLink } from './link.js';
import { isAppFile, scanApp } from './scan.js';

export interface CheckAppOptions {
  /** Application repository (a local clone). */
  app: string;
  moduleCache?: string;
  /** Commit to check; defaults to HEAD. Ignored with `worktree`. */
  rev?: string;
  /** Only check calls added since this commit (pull request mode). */
  base?: string;
  /** Read the app's working tree instead of a commit (local development). */
  worktree?: boolean;
  /** Infrastructure repository; defaults to .diffseal.json, then the app repository itself. */
  infra?: string;
  infraRev?: string;
  rootsUnder?: string;
  roles?: string[];
  /** Entry points (Go main package directories, or app directories) to limit the scan to one binary. */
  entries?: string[];
}

export interface CheckAppResult {
  app: string;
  infra: string;
  /** Local path of the infrastructure repository. */
  infraPath: string;
  link: DiscoveredLink;
  roots: string[];
  links: AppLink[];
  gate: Gate;
  notes: string[];
  deployments?: import('./deployments.js').DeploymentMapping[];
}

export async function checkApp(opts: CheckAppOptions): Promise<CheckAppResult> {
  const appSource: FileSource = opts.worktree ? new FsSource(opts.app) : new GitSource(opts.app, opts.rev ?? 'HEAD');
  const notes: string[] = [];
  // With a base, link settings come from the base: a change cannot choose the role or env it is judged by.
  const baseSource = opts.base ? new GitSource(opts.app, resolveCommit(opts.app, opts.base)) : undefined;
  const link = discoverLink(appSource, baseSource);
  const linkChanged = baseSource !== undefined && baseSource.readFile('.diffseal.json') !== appSource.readFile('.diffseal.json');
  if (linkChanged) notes.push('.diffseal.json changed in this change. The base version was applied; the change applies after it is reviewed and merged.');

  let addedLines;
  if (opts.base) {
    const base = resolveCommit(opts.app, opts.base);
    if (opts.worktree) {
      // Pull request mode on uncommitted work: diff the working tree against the base, and treat
      // untracked application files as entirely new.
      const { changed, untracked } = worktreeChanges(opts.app, base);
      const files = changed.filter((c) => c.status !== 'D' && isAppFile(c.path)).map((c) => c.path);
      addedLines = parseAddedLines(worktreeDiff(opts.app, base, files));
      for (const f of untracked.filter(isAppFile)) {
        const lines = (appSource.readFile(f) ?? '').split('\n').length;
        addedLines.set(f, new Set(Array.from({ length: lines }, (_, i) => i + 1)));
      }
    } else {
      const head = (appSource as GitSource).sha;
      const files = changedPaths(opts.app, base, head).filter((c) => c.status !== 'D' && isAppFile(c.path)).map((c) => c.path);
      addedLines = parseAddedLines(unifiedDiff(opts.app, base, head, files));
    }
    notes.push(`Only calls added since ${base.slice(0, 9)}${opts.worktree ? ', including uncommitted and untracked files,' : ''} are checked.`);
  }
  const scan = await scanApp(appSource, { addedLines, entries: opts.entries });
  if (opts.entries?.length) notes.push(`Scanned the code reachable from ${opts.entries.join(', ')}.`);

  const infraRepo = opts.infra ?? (link.infra?.repo ? path.resolve(opts.app, link.infra.repo) : opts.app);
  const infraRev = opts.infraRev ?? link.infra?.rev;
  const infraSource: FileSource = opts.worktree && !infraRev ? new FsSource(infraRepo, opts.moduleCache ?? defaultModuleCache()) : new GitSource(infraRepo, infraRev ?? 'HEAD', opts.moduleCache ?? defaultModuleCache());
  const roots = discoverRoots(infraSource, opts.rootsUnder ?? link.infra?.rootsUnder);
  const index = new InfraIndex(roots.map((r) => evaluateRoot(infraSource, r)));

  const deployments = deploymentIndex(appSource, index);
  index.computes.push(...deployments.computes);
  notes.push(...deployments.notes);

  const explicitRoles = Boolean(opts.roles?.length || JSON.parse((baseSource ?? appSource).readFile('.diffseal.json') ?? '{}').roles?.length);
  const roles = opts.roles?.length ? opts.roles : link.roles ?? [];
  for (const r of roles) {
    if (!index.rolesNamed(r).length) notes.push(`Role ${r} is not defined in ${roots.length} Terraform root(s) of ${infraRepo}.`);
  }
  if (deployments.files.size && !explicitRoles) notes.push('Deployment bindings select roles for matched source files; repository role hints apply only to unmatched files.');
  else if (roles.length) notes.push(`Runs as ${roles.join(', ')} (from ${opts.roles?.length ? '--role' : link.sources.join(', ')}).`);

  const links = reconcile(scan.facts, scan.envReads, index, {
    roleNames: roles.length ? roles : undefined,
    fileEnv: scan.fileEnv,
    fileComputes: explicitRoles ? undefined : deployments.files,
    externallyDefinedEnv: new Set(link.env),
    pairWithChangedEnv: Boolean(opts.base),
  });
  const attention = links.filter((l) => l.status === 'NOT_GRANTED' || l.status === 'MISSING');
  return {
    app: opts.app,
    infraPath: infraRepo,
    infra: infraSource instanceof GitSource ? `${infraRepo}@${infraSource.sha.slice(0, 9)}` : `${infraRepo} (working tree)`,
    link,
    roots,
    links,
    ...(deployments.mappings.length ? {deployments:deployments.mappings} : {}),
    gate: {
      result: attention.length || linkChanged ? 'review' : 'pass',
      items: [...attention.map((l) => ({ kind: 'access' as const, level: 'review' as const, rule: l.status, resource: l.callsite, text: `${l.status}: ${l.callsite}: ${l.access}` })), ...(linkChanged ? [{ kind: 'policy' as const, level: 'review' as const, text: '.diffseal.json changed' }] : [])],
      reasons: [...attention.map((l) => `${l.status}: ${l.callsite}: ${l.access}`), ...(linkChanged ? ['.diffseal.json changed'] : [])],
    },
    notes,
  };
}
