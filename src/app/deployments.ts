import * as path from 'node:path';
/** Statically rendered Kubernetes workloads. No Helm, kubectl or customer command is run. */
import { parseAllDocuments } from 'yaml';
import type { FileSource } from '../terraform/source.js';
import { Unknown, isUnknown } from '../core/model.js';
import type { Compute, InfraIndex } from '../reconcile/infraIndex.js';
export interface DeploymentMapping {
  source: string;
  kind: string;
  namespace: string;
  serviceAccount: string;
  images: string[];
  entries: string[];
  roles: string[];
}
export interface DeploymentIndex {
  computes: Compute[];
  files: Map<string, Compute[]>;
  mappings: DeploymentMapping[];
  notes: string[];
}
const object = (v: unknown): Record<string, any> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, any>) : {};
const literal = (v: unknown): v is string => typeof v === 'string' && !v.includes('${') && !v.includes('{{');
export function deploymentIndex(app: FileSource, index: InfraIndex): DeploymentIndex {
  const out: DeploymentIndex = { computes: [], files: new Map(), mappings: [], notes: [] };
  const docs: Array<{ file: string; value: Record<string, any> }> = [];
  for (const file of app
    .allFiles()
    .filter((p) => /\.ya?ml$/.test(p) && !/(^|\/)(node_modules|vendor|\.git|\.github)\//.test(p))
    .sort()) {
    const text = app.readFile(file) ?? '';
    if (text.length > 2 * 1024 * 1024) {
      out.notes.push(`${file}: YAML is too large to index`);
      continue;
    }
    try {
      for (const doc of parseAllDocuments(text)) {
        if (doc.errors.length) continue;
        const value = object(doc.toJS({ maxAliasCount: 50 }));
        if (value.kind === 'List' && Array.isArray(value.items))
          for (const item of value.items) docs.push({ file, value: object(item) });
        else docs.push({ file, value });
      }
    } catch {
      out.notes.push(`${file}: YAML could not be indexed`);
    }
  }
  const customKo = app.allFiles().filter(p=>/(^|\/)\.ko\.ya?ml$/.test(p)).some(file=>{
    try { const doc=parseAllDocuments(app.readFile(file)??'')[0];
      const config=object(doc?.toJS({maxAliasCount:50}));
      return Array.isArray(config.builds)&&config.builds.some((b:unknown)=>object(b).main!==undefined||object(b).dir!==undefined);
    } catch { return true; }
  });
  const koEntry = (image: string): string | undefined => {
    if (!image.startsWith('ko://')) return;
    if(customKo){out.notes.push('custom ko main/dir configuration is not resolved');return;}
    const pkg = image.slice(5);
    for (const file of app.allFiles().filter((p) => p === 'go.mod' || p.endsWith('/go.mod'))) {
      const module = (app.readFile(file) ?? '').match(/^module\s+(\S+)/m)?.[1];
      if (module && (pkg === module || pkg.startsWith(module + '/'))) {
        const entry = path.posix.join(path.posix.dirname(file), pkg.slice(module.length).replace(/^\//, ''));
        if (entry !== '..' && !entry.startsWith('../')) return entry;
      }
    }
  };
  for (const { file, value: d } of docs) {
    if (!['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob'].includes(d.kind)) continue;
    const metadata = object(d.metadata),
      namespace = literal(metadata.namespace) ? metadata.namespace : 'default';
    const spec = object(
      d.kind === 'Pod'
        ? d.spec
        : d.kind === 'CronJob'
          ? d.spec?.jobTemplate?.spec?.template?.spec
          : d.spec?.template?.spec,
    );
    const serviceAccount = literal(spec.serviceAccountName) ? spec.serviceAccountName : 'default';
    if (
      (metadata.namespace !== undefined && !literal(metadata.namespace)) ||
      (spec.serviceAccountName !== undefined && !literal(spec.serviceAccountName))
    ) {
      out.notes.push(`${file}: unrendered namespace or service account`);
      continue;
    }
    const associations = index.evaluations.flatMap((ev) =>
      ev.instances
        .filter(
          (i) =>
            i.type === 'aws_eks_pod_identity_association' &&
            i.attrs.namespace === namespace &&
            i.attrs.service_account === serviceAccount,
        )
        .map((instance) => ({ root: ev.root, instance })),
    );
    const accounts = docs.filter(
      ({ value: v }) =>
        v.kind === 'ServiceAccount' &&
        object(v.metadata).name === serviceAccount &&
        (object(v.metadata).namespace ?? 'default') === namespace,
    );
    const annotations = accounts
      .map(({ value: v }) => object(object(v.metadata).annotations)['eks.amazonaws.com/role-arn'])
      .filter(literal);
    if (associations.length > 1 || annotations.length > 1 || (associations.length && annotations.length)) {
      out.notes.push(`${file}: ambiguous workload identity for ${namespace}/${serviceAccount}`);
      continue;
    }
    let named: typeof index.roles = [],
      root = '',
      identity = '';
    if (associations.length === 1) {
      const { root: associationRoot, instance } = associations[0];
      root = associationRoot;
      identity = instance.address;
      const roleValue = instance.attrs.role_arn;
      const refs = (instance.references.role_arn ?? []).filter((r) => r.includes('aws_iam_role.'));
      const exact = isUnknown(roleValue) ? roleValue.refs.filter((r) => r.includes('aws_iam_role.')) : [];
      named = literal(roleValue)
        ? index.rolesNamed(roleValue)
        : index.roles.filter(
            (r) => r.root === root && (exact.length ? exact.includes(r.instance) : refs.includes(r.address)),
          );
    } else if (annotations.length === 1) {
      named = index.rolesNamed(annotations[0]);
      root = named[0]?.root ?? '';
      identity = `IRSA:${namespace}/${serviceAccount}`;
    } else continue;
    if (named.some((r) => r.accountUncertain) || new Set(named.map((r) => r.root)).size > 1) {
      out.notes.push(`${file}: workload role account is uncertain`);
      continue;
    }
    for (const container of [
      ...(Array.isArray(spec.containers) ? spec.containers : []),
      ...(Array.isArray(spec.initContainers) ? spec.initContainers : []),
    ]) {
      const c = object(container),
        env: Record<string, unknown> = {};
      const configMap = (name: unknown): Record<string, any> | undefined => {
        if (!literal(name)) return;
        const matches = docs.filter(
          ({ value: v }) =>
            v.kind === 'ConfigMap' &&
            object(v.metadata).name === name &&
            (object(v.metadata).namespace ?? 'default') === namespace,
        );
        return matches.length === 1 ? object(matches[0].value.data) : undefined;
      };
      for (const from of Array.isArray(c.envFrom) ? c.envFrom : []) {
        const cm = configMap(object(from).configMapRef?.name);
        if (cm)
          for (const [key, value] of Object.entries(cm))
            env[String(object(from).prefix ?? '') + key] = literal(value)
              ? value
              : new Unknown('ConfigMap value is not static');
      }
      for (const entry of Array.isArray(c.env) ? c.env : []) {
        const e = object(entry);
        if (!literal(e.name)) continue;
        const ref = object(object(e.valueFrom).configMapKeyRef),
          cm = configMap(ref.name);
        env[e.name] = literal(e.value)
          ? e.value
          : cm && literal(ref.key) && literal(cm[ref.key])
            ? cm[ref.key]
            : new Unknown('Kubernetes environment value is not statically known');
      }
      const opaqueEnv = (Array.isArray(c.envFrom) ? c.envFrom : []).some(
        (from) => !configMap(object(from).configMapRef?.name),
      );
      const roles = [...new Set(named.map((r) => r.address))];
      const compute: Compute = {
        root,
        address: `${identity}:${file}:${String(c.name ?? 'container')}`,
        type: 'kubernetes',
        env,
        ...(opaqueEnv ? { opaqueEnv: true } : {}),
        roles,
        roleInstances: named.map((r) => r.instance),
      };
      out.computes.push(compute);
      const entry = literal(c.image) ? koEntry(c.image) : undefined;
      if (entry)
        for (const sourceFile of app.allFiles().filter((p) => entry === '.' || p.startsWith(entry + '/')))
          out.files.set(sourceFile, [...(out.files.get(sourceFile) ?? []), compute]);
      out.mappings.push({
        source: file,
        kind: d.kind,
        namespace,
        serviceAccount,
        images: literal(c.image) ? [c.image] : [],
        entries: entry ? [entry] : [],
        roles: named.flatMap((r) => (r.name ? [r.name] : [])),
      });
    }
  }
  for (const file of app
    .allFiles()
    .filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p))
    .sort()) {
    let workflow: Record<string, any>;
    try {
      const doc = parseAllDocuments(app.readFile(file) ?? '')[0];
      if (!doc || doc.errors.length) continue;
      workflow = object(doc.toJS({ maxAliasCount: 50 }));
    } catch {
      continue;
    }
    for (const [jobId, rawJob] of Object.entries(object(workflow.jobs))) {
      const job = object(rawJob);
      if (job.strategy || job.uses) continue;
      const steps = Array.isArray(job.steps) ? job.steps.map(object) : [];
      for (const deploy of steps.filter(
        (step) =>
          typeof step.uses === 'string' && step.uses.startsWith('aws-actions/amazon-ecs-deploy-task-definition@'),
      )) {
        const reference = object(deploy.with)['task-definition'];
        const renderId =
          typeof reference === 'string'
            ? reference.match(/^\$\{\{\s*steps\.([\w-]+)\.outputs\.task-definition\s*\}\}$/)?.[1]
            : undefined;
        const render = steps.find(
          (step) =>
            step.id === renderId &&
            typeof step.uses === 'string' &&
            step.uses.startsWith('aws-actions/amazon-ecs-render-task-definition@'),
        );
        if (
          !render ||
          steps.indexOf(render) >= steps.indexOf(deploy) ||
          steps.filter((step) => step.id === renderId).length !== 1
        )
          continue;
        const inputs = object(render.with),
          taskFile = inputs['task-definition'],
          containerName = inputs['container-name'],
          image = inputs.image;
        if (!literal(taskFile) || !literal(containerName) || typeof image !== 'string') continue;
        let entry = koEntry(image);
        const buildId = image.match(/^\$\{\{\s*steps\.([\w-]+)\.outputs\.image\s*\}\}$/)?.[1];
        if (buildId) {
          const build = steps.find((step) => step.id === buildId);
          if (
            !build ||
            steps.indexOf(build) >= steps.indexOf(render) ||
            steps.filter((step) => step.id === buildId).length !== 1
          )
            continue;
          const command = typeof build?.run === 'string' ? build.run.trim() : '';
          const pkg = command.match(
            /^echo "image=\$\(ko build (\.\/[A-Za-z0-9_./-]+)\)"\s*>>\s*"\$GITHUB_OUTPUT"$/,
          )?.[1];
          const wd = build?.['working-directory'] ?? object(object(job.defaults).run)['working-directory'] ?? '.';
          if (pkg && !customKo && literal(wd) && !object(build?.env).KO_CONFIG_PATH && !object(job.env).KO_CONFIG_PATH)
            entry = path.posix.normalize(path.posix.join(wd, pkg));
        }
        if (!entry || entry === '..' || entry.startsWith('../') || path.posix.isAbsolute(entry)) {
          out.notes.push(`${file}: ECS pipeline build entry is not statically known`);
          continue;
        }
        let task: Record<string, any>;
        try {
          task = object(JSON.parse(app.readFile(taskFile) ?? ''));
        } catch {
          continue;
        }
        const container = (Array.isArray(task.containerDefinitions) ? task.containerDefinitions : [])
          .map(object)
          .find((c) => c.name === containerName);
        if (!container || !literal(task.taskRoleArn)) continue;
        const roles = index.rolesNamed(task.taskRoleArn).filter((r) => !r.accountUncertain);
        const env: Record<string, unknown> = {};
        for (const e of Array.isArray(container.environment) ? container.environment : [])
          if (literal(e.name))
            env[e.name] = literal(e.value) ? e.value : new Unknown('Rendered task environment is unknown');
        for (const e of Array.isArray(container.secrets) ? container.secrets : [])
          if (literal(e.name)) env[e.name] = new Unknown('Task secret is not read');
        for (const field of ['environment-variables', 'secrets'])
          if (typeof inputs[field] === 'string')
            for (const line of inputs[field].split('\n')) {
              const pair = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
              if (pair)
                env[pair[1]] =
                  field === 'environment-variables' && literal(pair[2])
                    ? pair[2]
                    : new Unknown('Rendered environment or secret is unknown');
            }

        const grouped = new Map<string, typeof roles>();
        for (const role of roles) grouped.set(role.root, [...(grouped.get(role.root) ?? []), role]);
        const computes: Compute[] = [...grouped].map(([root, rs]) => ({
          root,
          address: `pipeline:${file}:${jobId}:${String(render.id)}`,
          type: 'ecs-pipeline',
          env,
          ...(container.environmentFiles?.length || inputs['environment-files'] ? { opaqueEnv: true } : {}),
          roles: rs.map((r) => r.address),
          roleInstances: rs.map((r) => r.instance),
        }));
        out.computes.push(...computes);
        for (const sourceFile of app.allFiles().filter((p) => entry === '.' || p.startsWith(entry + '/')))
          out.files.set(sourceFile, [...(out.files.get(sourceFile) ?? []), ...computes]);
        out.mappings.push({
          source: `${file}:${jobId}`,
          kind: 'ECS pipeline',
          namespace: '',
          serviceAccount: '',
          images: [image],
          entries: [entry],
          roles: roles.flatMap((r) => (r.name ? [r.name] : [])),
        });
        out.notes.push(`${file}: ECS pipeline maps ${entry} through ${taskFile} to ${task.taskRoleArn}`);
      }
    }
  }
  return out;
}
