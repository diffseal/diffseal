import type { FileSource } from '../terraform/source.js';

/**
 * How an application repository links to the Terraform that provisions it. Read from `.diffseal.json`
 * in the app repository, the ECS task definitions and Kubernetes service accounts (IRSA) it deploys,
 * and command-line flags (which win).
 */
export interface AppLinkConfig {
  /** Trusted reusable workflow settings, read from the base branch through git show. */
  replay?: { rootsUnder?: string; policyFile?: string; moduleCache?: string };
  infra?: { repo?: string; rev?: string; rootsUnder?: string };
  /** IAM roles the app runs as, by name or ARN. */
  roles?: string[];
  /** Env vars set outside Terraform (task definitions, deploy scripts). */
  env?: string[];
  /** Policy thresholds and accepted exceptions; see PolicyConfig. */
  policy?: Record<string, unknown>;
  exceptions?: unknown[];
}

export interface DiscoveredLink extends AppLinkConfig {
  /** Where each piece of the link came from, for the report. */
  sources: string[];
}

const TASKDEF = /(^|\/)([^/]*task-?def[^/]*|[^/]*task-definition[^/]*)\.json$/i;

/**
 * @param configFrom where to read `.diffseal.json`; a pull request reads it from its base, so it
 *   cannot pick its own role, infrastructure or env vars. Deployment files are read from `app`: they
 *   are what will run.
 */
export function discoverLink(app: FileSource, configFrom: FileSource = app): DiscoveredLink {
  const out: DiscoveredLink = { roles: [], env: [], sources: [] };
  const cfgText = configFrom.readFile('.diffseal.json');
  if (cfgText) {
    const cfg = JSON.parse(cfgText) as AppLinkConfig;
    out.infra = cfg.infra;
    out.roles!.push(...(cfg.roles ?? []));
    out.env!.push(...(cfg.env ?? []));
    out.sources.push('.diffseal.json');
  }
  for (const p of app.allFiles().filter((f) => TASKDEF.test(f) && !/node_modules\//.test(f))) {
    let def: { taskRoleArn?: unknown; containerDefinitions?: Array<{ environment?: Array<{ name?: string }>; secrets?: Array<{ name?: string }> }> };
    try {
      def = JSON.parse(app.readFile(p) ?? '');
    } catch {
      continue;
    }
    if (typeof def.taskRoleArn === 'string' && !def.taskRoleArn.includes('${')) {
      out.roles!.push(def.taskRoleArn);
      out.sources.push(`${p} (taskRoleArn)`);
    }
    for (const c of def.containerDefinitions ?? []) {
      for (const e of [...(c.environment ?? []), ...(c.secrets ?? [])]) if (e.name) out.env!.push(e.name);
    }
  }
  // EKS (IRSA): ServiceAccount manifests and Helm values carry the role in an annotation; workload
  // manifests and Helm values list container env. CI files, comments and other kinds are ignored.
  const IRSA = /["']?eks\.amazonaws\.com\/role-arn["']?\s*:\s*["']?(arn:aws[\w-]*:iam::\d{12}:role\/[\w+=,.@/-]+)/g;
  const WORKLOAD = /^kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|ReplicaSet)\s*$/m;
  for (const p of app.allFiles().filter((f) => /\.ya?ml$/.test(f) && !/(^|\/)(node_modules|\.github|\.gitlab|\.circleci)\//.test(f)).sort()) {
    const text = (app.readFile(p) ?? '')
      .split('\n')
      .filter((l) => !l.trim().startsWith('#'))
      .join('\n');
    const helmValues = /(^|\/)values[^/]*\.ya?ml$/.test(p);
    if (helmValues || /^kind:\s*ServiceAccount\s*$/m.test(text)) {
      for (const m of text.matchAll(IRSA)) {
        out.roles!.push(m[1]);
        out.sources.push(`${p} (eks.amazonaws.com/role-arn)`);
      }
    }
    if ((helmValues || WORKLOAD.test(text)) && /^\s*-?\s*env:\s*$/m.test(text)) {
      for (const m of text.matchAll(/^\s*-\s*name:\s*["']?([A-Z][A-Z0-9_]*)["']?\s*$/gm)) out.env!.push(m[1]);
    }
  }
  out.roles = [...new Set(out.roles)];
  out.env = [...new Set(out.env)];
  return out;
}
