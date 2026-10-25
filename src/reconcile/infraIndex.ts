import { configAddress, instancesCompatible, isUnknown, sensitiveLeaves, type Attrs } from '../core/model.js';
import { parsePolicy, type Statement } from '../policy/iam.js';
import { environmentOf } from '../terraform/environment.js';
import type { RootEvaluation, StaticInstance } from '../terraform/expand.js';

/** What the infrastructure says about who runs code, with which role, and what that role may do. */

export interface Compute {
  root: string;
  address: string;
  type: string;
  env: Record<string, unknown>;
  /** An external envFrom or environment file can define names and values we cannot enumerate. */
  opaqueEnv?: boolean;
  roles: string[];
  /** Exact role instances the role argument was built from (`aws_iam_role.r[1]`), when known. */
  roleInstances: string[];
}

export interface Role {
  root: string;
  /** Config address (no instance key). */
  address: string;
  /** Instance address, e.g. `aws_iam_role.r["a"]` for roles made with for_each or count. */
  instance: string;
  name?: string;
  path: string;
  providerAddress?: string;
  /**
   * Matched by a role ARN in a root whose providers target several accounts: which account created
   * this role is not known statically, so it may not be the role the ARN names.
   */
  accountUncertain?: boolean;
}

export interface RoleStatement {
  /** `Unknown`: the effect is not known statically, so the statement may allow or deny. */
  effect: 'Allow' | 'Deny' | 'Unknown';
  /** Root whose configuration holds the statement; its references resolve there. */
  root?: string;
  /**
   * Set for a statement from another root whose AWS account is not known to be the role's: it may
   * apply to this role or to a namesake in another account. It can make access undetermined, never proven.
   */
  uncertainAccount?: boolean;
  actions: unknown[];
  notActions?: unknown[];
  resources: unknown[];
  /** Set for NotResource statements: the statement applies to every resource except these. */
  notResources?: unknown[];
  /** The statement has a Condition, so whether it applies depends on the request. */
  conditional?: boolean;
  /** The policy resource that holds the statement, for "add it here" suggestions. */
  policy: string;
  source: { file: string; line: number };
  /** `document`: an aws_iam_policy_document data source (HCL statement blocks); `json`: a JSON/jsonencode policy. */
  style: 'document' | 'json';
  /** Module address of the holder, so suggested references can be written relative to it. */
  module?: string;
}

export interface RoleGrants {
  statements: RoleStatement[];
  /** AWS managed policies attached by ARN; their contents are not evaluated. */
  managedPolicies: string[];
  /** Policies attached to the role whose contents could not be read statically. */
  opaque: string[];
  /** Other roots with policies naming the role whose account is not known to be the role's. */
  uncertainRoots: string[];
  /** AWS managed policies attached to a namesake in a root whose account is not known statically. */
  uncertainManaged: string[];
  /** The role's permissions boundary: its statements when readable, or what could not be read. */
  boundary?: { statements: RoleStatement[]; opaque?: string };
}

const list = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

/** A policy statement as reconciliation reads it; an effect not known statically stays undecided. */
function roleStatement(st: Statement, where: Pick<RoleStatement, 'policy' | 'source' | 'style' | 'module' | 'root' | 'uncertainAccount'>): RoleStatement {
  const { uncertainAccount, ...holder } = where;
  return {
    effect: st.Effect === 'Deny' ? 'Deny' : isUnknown(st.Effect) ? 'Unknown' : 'Allow',
    actions: list(st.Action),
    notActions: st.NotAction === undefined ? undefined : list(st.NotAction),
    resources: list(st.Resource),
    ...(st.NotResource !== undefined ? { notResources: list(st.NotResource) } : {}),
    ...(st.Condition !== undefined && st.Condition !== null ? { conditional: true } : {}),
    ...holder,
    ...(uncertainAccount ? { uncertainAccount } : {}),
  };
}

/** The name argument of resources and data sources that identify an AWS resource by name. */
const NAME_ATTR: Record<string, string> = {
  aws_s3_bucket: 'bucket',
  aws_sqs_queue: 'name',
  aws_sns_topic: 'name',
  aws_secretsmanager_secret: 'name',
  aws_dynamodb_table: 'name',
  aws_sfn_state_machine: 'name',
  aws_ssm_parameter: 'name',
  aws_lambda_function: 'function_name',
  aws_kinesis_stream: 'name',
  aws_cloudwatch_event_bus: 'name',
  aws_kms_alias: 'name',
};

export class InfraIndex {
  readonly computes: Compute[] = [];
  readonly roles: Role[] = [];
  private readonly byConfig = new Map<string, StaticInstance[]>();

  /** Printable pieces of every sensitive value in the evaluated roots, to scrub from reports. */
  get sensitiveLeaves(): string[] {
    this.leaves ??= this.evaluations.flatMap((e) => e.instances.flatMap((i) => sensitiveLeaves(i.attrs)));
    return this.leaves;
  }
  private leaves?: string[];

  constructor(readonly evaluations: RootEvaluation[]) {
    for (const ev of evaluations) {
      for (const i of ev.instances) {
        const key = `${ev.root}|${i.configAddress}`;
        this.byConfig.set(key, [...(this.byConfig.get(key) ?? []), i]);
        if (i.mode !== 'managed') continue;
        if (i.type === 'aws_lambda_function' || i.type === 'aws_ecs_task_definition') {
          const roleAttr = i.type === 'aws_lambda_function' ? 'role' : 'task_role_arn';
          const roleValue = i.attrs[roleAttr];
          this.computes.push({
            root: ev.root,
            address: i.address,
            type: i.type,
            env: environmentOf(i.type, i.attrs) ?? {},
            roles: (i.references[roleAttr] ?? []).filter((r) => r.includes('aws_iam_role.')),
            roleInstances: isUnknown(roleValue) ? roleValue.refs.filter((r) => r.includes('aws_iam_role.')) : [],
          });
        }
        if (i.type === 'aws_iam_role') {
          this.roles.push({
            root: ev.root,
            address: i.configAddress,
            instance: i.address,
            name: typeof i.attrs.name === 'string' ? i.attrs.name : undefined,
            path: typeof i.attrs.path === 'string' ? i.attrs.path : '/',
            ...(i.providerAddress ? {providerAddress:i.providerAddress} : {}),
          });
        }
      }
    }
  }

  /** The instance at this address; for an address without its key, the first instance of the resource. */
  instance(root: string, address: string): StaticInstance | undefined {
    const all = this.byConfig.get(`${root}|${configAddress(address)}`);
    return all?.find((i) => i.address === address) ?? all?.[0];
  }

  computesSetting(envName: string): Compute[] {
    return this.computes.filter((c) => envName in c.env || c.opaqueEnv);
  }

  /**
   * Role instances a compute's role reference can mean: the exact instance it was built from when
   * known (`role = aws_iam_role.r[1].arn`), else those whose instance keys agree with the compute's.
   */
  rolesFor(c: Compute): Role[] {
    const candidates = this.roles.filter((r) => r.root === c.root && c.roles.includes(r.address));
    const exact = candidates.filter((r) => c.roleInstances.includes(r.instance));
    return exact.length ? exact : candidates.filter((r) => keysCompatible(c.address, r.instance));
  }

  /** Roles by name; accepts `name`, `path/name` or a role ARN. */
  rolesNamed(nameOrArn: string): Role[] {
    const account = nameOrArn.match(/^arn:aws[\w-]*:iam::(\d{12}):role/)?.[1];
    const isArn = /^arn:aws[\w-]*:iam::\d*:role\//.test(nameOrArn);
    const tail = nameOrArn.replace(/^arn:aws[\w-]*:iam::\d*:role/, '');
    const name = tail.split('/').filter(Boolean).pop() ?? tail;
    // An ARN carries the role's path (`role/dev/worker` is path /dev/); a bare name matches any path.
    const path = isArn ? tail.slice(0, tail.length - name.length) : undefined;
    return this.roles
      .filter((r) => {
        if (r.name !== name) return false;
        if (path !== undefined && r.path !== path && !isUnknown(this.instance(r.root, r.instance)?.attrs.path)) return false;
        const accounts = this.accountsOf(r.root, r.instance);
        return !account || !accounts.length || accounts.includes(account);
      })
      .map((r) => {
        const accounts=this.accountsOf(r.root,r.instance);
        const explicitAlias=/(?:^|\.)aws\./.test(r.providerAddress?.split('::')[1]??'');
        const unresolved=accounts.length>1||(!accounts.length&&(explicitAlias||(this.evaluations.find(e=>e.root===r.root)?.accounts.length??0)>0));
        return account&&unresolved?{...r,accountUncertain:true}:r;
      });
  }

  accountsOf(root:string,instance?:string):string[]{
    const ev=this.evaluations.find(e=>e.root===root);
    const selected=instance?ev?.instances.find(i=>i.address===instance)?.providerAccounts:undefined;
    return [...new Set(selected??ev?.accounts??[])];
  }

  grants(role: Role): RoleGrants {
    const statements: RoleStatement[] = [];
    const managed: string[] = [];
    const ev = this.evaluations.find((e) => e.root === role.root);
    const accounts = this.accountsOf(role.root,role.instance);
    const namesRole = (v: unknown) => typeof v === 'string' && role.name !== undefined && (v === role.name || v.endsWith(`:role${role.path}${role.name}`));
    // A policy belongs to this role instance when its role argument names it, or (when the name is not
    // known statically) when it references the role and the instance keys agree. In another root only
    // the name can tie them: the role itself, or a data source that looks it up by name.
    // 'ref': the policy references the role resource itself. 'name': it names a role of the same name,
    // which in a root with providers for several accounts may be a namesake in another account.
    const pointsAtRole = (i: StaticInstance, attr: string, root: string): 'ref' | 'name' | false => {
      const values = list(i.attrs[attr]);
      const refs = i.references[attr] ?? [];
      const byRef = root === role.root && refs.includes(role.address);
      if (values.some(namesRole)) return byRef ? 'ref' : 'name';
      // Known names that are not this role's settle it (roles = ["a", "b"], or r["a"].name for role b).
      if (role.name !== undefined && values.length && values.every((v) => typeof v === 'string')) return false;
      if (byRef) {
        // A value built from `aws_iam_role.r[1].id` names that instance exactly; key agreement is the fallback.
        const exact = values.flatMap((v) => (isUnknown(v) ? v.refs : [])).filter((r) => configAddress(r) === role.address && r !== role.address);
        if (exact.length) return exact.some((r) => r === role.instance || r.startsWith(`${role.instance}.`)) ? 'ref' : false;
        if (keysCompatible(i.address, role.instance)) return 'ref';
      }
      return refs.some((r) => r.includes('data.aws_iam_role.') && namesRole(this.instance(root, r)?.attrs.name)) ? 'name' : false;
    };
    const opaque: string[] = [];
    const uncertainRoots = new Set<string>();
    const uncertainManaged: string[] = [];
    const elsewhere = (what: string, root: string) => {
      uncertainRoots.add(root);
      return `${what} in ${root} (whether it targets the same AWS account is not known statically)`;
    };

    const add = (policy: unknown, holder: StaticInstance, attr = 'policy', root = role.root, uncertainAccount = false) => {
      const parsed = parsePolicy(policy);
      if (parsed.kind !== 'ok') {
        opaque.push(uncertainAccount ? elsewhere(holder.address, root) : holder.address);
        return;
      }
      // Statements written in a policy document data source are edited there, not in the resource that uses it.
      const doc = (holder.references[attr] ?? [])
        .filter((r) => r.includes('data.aws_iam_policy_document.'))
        .map((r) => this.instance(root, r))
        .find(Boolean);
      const where = doc ?? holder;
      for (const st of parsed.statements as Statement[]) {
        statements.push(
          roleStatement(st, { policy: where.configAddress, source: where.source, style: doc ? 'document' : 'json', module: where.moduleAddress, root, uncertainAccount })
        );
      }
      if (uncertainAccount) uncertainRoots.add(root);
    };

    // Policies can attach to the role from any analyzed root that targets the same account. When either
    // account is not known statically, another root's policy may name a namesake in another account
    // (staging's "orders-task" is not prod's): it can make access undetermined, never proven.
    // A root with several provider accounts (aliases) does not say which one the role uses, so only a
    // single account on both sides, and the same one, is a known match.
    for(const other of this.evaluations){
      for(const i of other.instances){
        if(i.mode!=='managed')continue;
        const targetAccounts=i.providerAccounts??other.accounts;
        if(accounts.length&&targetAccounts.length&&!accounts.some(a=>targetAccounts.includes(a)))continue;
        const sameProvider=Boolean(role.providerAddress&&i.providerAddress===role.providerAddress);
        const known=sameProvider||(accounts.length===1&&targetAccounts.length===1&&accounts[0]===targetAccounts[0])||(!role.providerAddress&&!i.providerAddress&&other===ev&&accounts.length<=1);
        const how=(attr:string)=>pointsAtRole(i,attr,other.root);
        const uncertainFor=(_match:'ref'|'name')=>!known;
        const inline = i.type === 'aws_iam_role_policy' ? how('role') : false;
        if (inline) add(i.attrs.policy, i, 'policy', other.root, uncertainFor(inline));
        const attachment =
          (i.type === 'aws_iam_role_policy_attachment' && how('role')) || (i.type === 'aws_iam_policy_attachment' && how('roles')) || false;
        const uncertain = attachment ? uncertainFor(attachment) : !known;
        if (attachment) {
          const policy = this.attachedPolicy(other.root, i);
          if (policy && policy !== 'ambiguous') add(policy.attrs.policy, policy, 'policy', other.root, uncertain);
          // An AWS managed policy from a root that may be another account: judged in reconcile by what it holds.
          else if (uncertain && typeof i.attrs.policy_arn === 'string' && /:aws:policy\//.test(i.attrs.policy_arn)) {
            uncertainManaged.push(i.attrs.policy_arn);
            uncertainRoots.add(other.root);
          }
          // What another account's root attaches cannot prove or rule out anything: undetermined.
          else if (uncertain) opaque.push(elsewhere(i.address, other.root));
          else if (policy === 'ambiguous') opaque.push(i.address);
          else if (typeof i.attrs.policy_arn === 'string' && /:aws:policy\//.test(i.attrs.policy_arn)) managed.push(i.attrs.policy_arn);
          else opaque.push(i.address);
        }
        // A registry or git module given the role may attach policies the index cannot see.
        if (i.externalModule && Object.keys(i.attrs).some((a) => a !== 'source' && a !== 'version' && pointsAtRole(i, a, other.root))) {
          const label = `${i.address} (${i.externalModule.source ?? 'module'})`;
          opaque.push(uncertain ? elsewhere(label, other.root) : label);
        }
      }
    }
    for (const i of ev?.instances ?? []) {
      if (i.mode !== 'managed') continue;
      if (i.type === 'aws_iam_role' && i.address === role.instance) {
        for (const p of list(i.attrs.inline_policy) as Attrs[]) add(p?.policy, i);
        const arns = i.attrs.managed_policy_arns;
        const policies=(ev?.instances??[]).filter(p=>p.mode==='managed'&&p.type==='aws_iam_policy');
        for(const arn of list(arns)){
          if(typeof arn==='string'&&/:aws:policy\//.test(arn)){managed.push(arn);continue;}
          let selected:StaticInstance|undefined;
          if(isUnknown(arn)){
            const exact=policies.filter(p=>arn.refs.some(ref=>ref===p.address||ref.startsWith(p.address+'.')));
            if(exact.length===1)selected=exact[0];
            else if(!exact.length){
              const candidates=policies.filter(p=>arn.refs.includes(p.configAddress));
              if(candidates.length===1)selected=candidates[0];
            }
          }else if(typeof arn==='string'){
            selected=policies.find(p=>p.attrs.arn===arn);
          }
          if(selected)add(selected.attrs.policy,selected);
          else opaque.push(`${i.address}.managed_policy_arns`);
        }
      }
    }
    const boundary = this.boundaryOf(role, ev?.instances ?? []);
    return {
      statements,
      managedPolicies: managed,
      uncertainManaged,
      opaque: [...new Set(opaque)],
      uncertainRoots: [...uncertainRoots],
      ...(boundary ? { boundary } : {}),
    };
  }

  /**
   * The aws_iam_policy instance an attachment points at: the exact instance its policy_arn was built
   * from when known (for_each/count), else the only compatible one; several candidates are ambiguous.
   */
  private attachedPolicy(root: string, attachment: StaticInstance): StaticInstance | 'ambiguous' | undefined {
    const arn = attachment.attrs.policy_arn;
    const all = (attachment.references.policy_arn ?? []).flatMap((a) => this.byConfig.get(`${root}|${configAddress(a)}`) ?? []).filter((p) => p.type === 'aws_iam_policy');
    if (isUnknown(arn)) {
      const exact = all.find((p) => arn.refs.includes(p.address));
      if (exact) return exact;
    }
    const compatible = all.filter((p) => keysCompatible(attachment.address, p.address));
    if (compatible.length > 1) return 'ambiguous';
    return compatible[0];
  }

  /** A permissions boundary caps what the role's policies grant: an action must be allowed by both. */
  private boundaryOf(role: Role, instances: StaticInstance[]): RoleGrants['boundary'] {
    const inst = instances.find((i) => i.type === 'aws_iam_role' && i.address === role.instance);
    const value = inst?.attrs.permissions_boundary;
    if (!inst || value === undefined || value === null || value === '') return undefined;
    // The exact policy instance the boundary ARN was built from (bound["b"]); with several instances
    // and no exact reference, which one applies is not known.
    const candidates = (inst.references.permissions_boundary ?? [])
      .flatMap((a) => this.byConfig.get(`${role.root}|${configAddress(a)}`) ?? [])
      .filter((p) => p.type === 'aws_iam_policy');
    const exact = isUnknown(value) ? candidates.find((p) => value.refs.includes(p.address)) : undefined;
    const policy = exact ?? (candidates.length === 1 ? candidates[0] : undefined);
    const parsed = policy ? parsePolicy(policy.attrs.policy) : undefined;
    if (!policy || parsed?.kind !== 'ok') return { statements: [], opaque: typeof value === 'string' ? value : `${inst.address}.permissions_boundary` };
    return {
      statements: (parsed.statements as Statement[]).map((st) =>
        roleStatement(st, { policy: policy.configAddress, source: policy.source, style: 'json', module: policy.moduleAddress, root: role.root })
      ),
    };
  }

  /** Name of the AWS resource a Terraform address refers to, if it is configured literally. */
  nameOf(root: string, address: string): string | undefined {
    const all = this.byConfig.get(`${root}|${configAddress(address)}`) ?? [];
    // Only the exact instance, or the only one: another instance's name would be a different resource.
    const i = all.find((x) => x.address === address) ?? (all.length === 1 ? all[0] : undefined);
    if (!i) return undefined;
    const attr = NAME_ATTR[i.type];
    const v = attr ? i.attrs[attr] : undefined;
    return typeof v === 'string' ? v : undefined;
  }

  /** Config address of the resource or data source of one of `types` with this name, in a root. */
  addressByName(root: string, types: string[], name: string): string | undefined {
    const ev = this.evaluations.find((e) => e.root === root);
    const hit = ev?.instances.find((i) => types.includes(i.type) && NAME_ATTR[i.type] !== undefined && i.attrs[NAME_ATTR[i.type]] === name);
    return hit?.configAddress;
  }

  /** Instance addresses of every resource of `types` in the root whose name is `name`. */
  instancesByName(root: string, types: string[], name: string, account?: string): string[] {
    const ev = this.evaluations.find((e) => e.root === root);
    return (ev?.instances ?? []).filter((i) => {const accounts=i.providerAccounts??ev?.accounts??[];return (!account||!accounts.length||accounts.includes(account))&&i.mode === 'managed' && types.includes(i.type) && NAME_ATTR[i.type] !== undefined && i.attrs[NAME_ATTR[i.type]] === name;}).map((i) => i.address);
  }

  typeOf(root: string, address: string): string | undefined {
    return this.instance(root, address)?.type;
  }
}

export function isKnownString(v: unknown): v is string {
  return typeof v === 'string' && !isUnknown(v);
}

/** Two instance addresses can refer to the same for_each/count element (module keys included). */
export const keysCompatible = instancesCompatible;
