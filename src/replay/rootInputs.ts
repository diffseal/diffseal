import * as path from 'node:path';
import { readConfigFile } from '../configFile.js';
import { normalize } from '../terraform/source.js';

/**
 * The `roots` mapping of `.diffseal.json`: per root directory, the environments it is deployed as.
 *
 * ```json
 * { "roots": {
 *     "infra/app": { "environments": [{ "workspace": "prod", "varFiles": ["../common.tfvars", "prod.tfvars"] }] },
 *     "ops/services/*": { "workspaces": ["test", "prod"] } } }
 * ```
 *
 * `varFiles` are relative to the root directory, as `-var-file` is when Terraform runs there, and are
 * loaded in order. `workspaces` adds one environment per name, without var-files. A key may use `*`
 * for any characters inside one path segment; an exact key wins over a pattern, and among patterns
 * the first in the file wins.
 */
export interface MappedEnvironment {
  /** Unset means `default`. */
  workspace?: string;
  /** Paths relative to the root directory. */
  varFiles: string[];
}

export interface RootMappings {
  entries: Array<{ pattern: string; environments: MappedEnvironment[] }>;
  /** Why parts of the mapping were ignored. */
  problems: string[];
}

/** At most this many mapped environments are evaluated per root. */
export const MAX_MAPPED_ENVIRONMENTS = 16;

const WORKSPACE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,89}$/;

export function readRootMappings(source: { readFile(p: string): string | undefined | null }): RootMappings {
  const out: RootMappings = { entries: [], problems: [] };
  const text = readConfigFile(source);
  if (!text) return out;
  let cfg: unknown;
  try {
    cfg = JSON.parse(text);
  } catch {
    return out;
  }
  const roots = cfg && typeof cfg === 'object' ? (cfg as { roots?: unknown }).roots : undefined;
  if (roots === undefined) return out;
  if (!roots || typeof roots !== 'object' || Array.isArray(roots)) {
    out.problems.push('roots must be an object of root directories');
    return out;
  }
  for (const [key, value] of Object.entries(roots as Record<string, unknown>)) {
    const pattern = normalize(key);
    if (pattern.startsWith('/') || pattern === '..' || pattern.startsWith('../')) {
      out.problems.push(`roots: "${key}" is not a directory inside the repository`);
      continue;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      out.problems.push(`roots."${key}" must be an object with workspaces or environments`);
      continue;
    }
    const v = value as { workspaces?: unknown; environments?: unknown };
    const envs: MappedEnvironment[] = [];
    const bad = (what: string) => out.problems.push(`roots."${key}": ${what}`);
    if (v.workspaces !== undefined) {
      if (!Array.isArray(v.workspaces)) bad('workspaces must be a list of names');
      else for (const w of v.workspaces) {
        if (typeof w === 'string' && WORKSPACE_NAME.test(w)) envs.push({ workspace: w === 'default' ? undefined : w, varFiles: [] });
        else bad(`workspace ${JSON.stringify(w)} is not a workspace name`);
      }
    }
    if (v.environments !== undefined) {
      if (!Array.isArray(v.environments)) bad('environments must be a list');
      else for (const e of v.environments) {
        if (!e || typeof e !== 'object' || Array.isArray(e)) {
          bad('each environment must be an object with workspace and varFiles');
          continue;
        }
        const { workspace, varFiles } = e as { workspace?: unknown; varFiles?: unknown };
        if (workspace !== undefined && (typeof workspace !== 'string' || !WORKSPACE_NAME.test(workspace))) {
          bad(`workspace ${JSON.stringify(workspace)} is not a workspace name`);
          continue;
        }
        if (varFiles !== undefined && (!Array.isArray(varFiles) || varFiles.some((f) => typeof f !== 'string' || !f || f.startsWith('/')))) {
          bad('varFiles must be a list of paths relative to the root directory');
          continue;
        }
        envs.push({ workspace: workspace === 'default' ? undefined : (workspace as string | undefined), varFiles: (varFiles as string[] | undefined) ?? [] });
      }
    }
    if (!envs.length) {
      bad('names no environment');
      continue;
    }
    // The same environment listed twice is evaluated once.
    const seen = new Set<string>();
    out.entries.push({ pattern, environments: envs.filter((x) => !seen.has(JSON.stringify(x)) && seen.add(JSON.stringify(x))) });
  }
  return out;
}

const matches = (pattern: string, root: string) =>
  new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')}$`).test(root);

/** The mapped environments of a root, with var-file paths resolved to repository paths, or undefined. */
export function mappedEnvironments(m: RootMappings, root: string): Array<{ workspace?: string; varFiles: string[] }> | undefined {
  const r = normalize(root);
  const entry = m.entries.find((e) => e.pattern === r) ?? m.entries.find((e) => e.pattern.includes('*') && matches(e.pattern, r));
  if (!entry) return undefined;
  return entry.environments.map((e) => ({ ...(e.workspace ? { workspace: e.workspace } : {}), varFiles: e.varFiles.map((f) => normalize(path.posix.join(r, f))) }));
}

/** True when a resolved var-file path stays inside the repository. */
export const insideRepository = (p: string) => p !== '..' && !p.startsWith('../') && !p.startsWith('/');
