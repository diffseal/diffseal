import { UNKNOWN_PART, configAddress, isRedacted, isUnknown, reveal, scrubDeep } from '../core/model.js';
import { parsePolicy } from '../policy/iam.js';
import { ANY_OF, IAM_PREFIX, UNSCOPED_OPERATIONS, serviceHint } from '../app/actions.js';
import type { AccessFact, EnvRead, ResourceRef } from '../app/facts.js';
import type { InfraIndex, Role, RoleStatement } from './infraIndex.js';
import { MANAGED_POLICY_ACTIONS, managedPolicyName } from './managedPolicies.js';

export type LinkStatus = 'GRANTED' | 'NOT_GRANTED' | 'UNRESOLVED' | 'MISSING';

export interface AppLink {
  status: LinkStatus;
  confidence: 'proven' | 'likely';
  callsite: string;
  actions: string[];
  /** The resource as the code names it, with what it resolved to. */
  resource: string;
  via?: string;
  note?: string;
  /** Readable summary: "sns:Publish on $TOPIC_ARN (asset-events) (via pubsub.NewSNSPublisher)". */
  access: string;
  root?: string;
  role?: string;
  detail: string;
  /** For NOT_GRANTED: a statement to add, and where. */
  suggestion?: { target: string; file: string; line: number; code: string };
}

export interface ReconcileOptions {
  /** Roles the app runs as, by name or ARN (from a task definition in the app repo, or configuration). */
  roleNames?: string[];
  /** Env vars read anywhere in each file, used to find the compute when a call itself names no env var. */
  fileEnv?: Map<string, string[]>;
  /** Env vars defined outside the Terraform (e.g. an app-repo task definition); never reported missing. */
  externallyDefinedEnv?: Set<string>;
  /** Pair unresolved resources with env vars read in the same change. Only meaningful for diffs. */
  pairWithChangedEnv?: boolean;
}

/** What a resource reference resolves to: a name (glob allowed), an S3 object path, Terraform addresses. */
interface Identity {
  any?: boolean;
  service?: string;
  name?: string;
  path?: string;
  /** aws, aws-cn, aws-us-gov: from an ARN, when known. */
  partition?: string;
  /** From an ARN, when known; may be a glob. */
  account?: string;
  region?: string;
  addresses: string[];
  /** Root the addresses belong to: `aws_s3_bucket.data` in one root is not the one in another. */
  root?: string;
  /**
   * Step Functions resource type from an ARN; executions also carry their name (`name` is the state
   * machine), a state machine its version or alias. `unknown`: a Terraform reference with text after
   * it (`${aws_sfn_state_machine.sm.arn}:*`, or built through replace()), which may name either.
   */
  sfn?: { type: 'stateMachine' | 'execution' | 'express' | 'unknown'; execution?: string; qualifier?: string };
  /** A secret name taken from an ARN, so it includes the random suffix (or a pattern for it). */
  secretArn?: boolean;
  /** A secret ARN whose six-character tail is known to be AWS's suffix (Terraform declares the base name). */
  secretFullArn?: boolean;
  label: string;
}

const globWith = (pattern: string, flags: string) =>
  new RegExp('^' + pattern.split('').map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[.+^${}()|[\]\\]/g, '\\$&'))).join('') + '$', flags);
/** IAM actions match case-insensitively. */
const actionGlob = (pattern: string) => globWith(pattern, 'i');
/** Resource names, paths, accounts and regions are case-sensitive: `prod/FOO` is not `prod/foo`. */
const glob = (pattern: string) => globWith(pattern, '');

/** Whether a granted glob matches the value the code needs, or every expansion of the pattern it needs. */
const covers = (grant: string, need: string) => (/[*?]/.test(need) ? globCovers(grant, need) : glob(grant).test(need));

/**
 * True when every string the glob `need` matches is matched by `grant` (`*` any run, `?` one
 * character). Sound: it never answers yes when some expansion of `need` falls outside `grant`.
 */
export function globCovers(grant: string, need: string): boolean {
  const memo = new Map<number, boolean>();
  const go = (i: number, j: number): boolean => {
    const key = i * (need.length + 1) + j;
    const hit = memo.get(key);
    if (hit !== undefined) return hit;
    let r: boolean;
    if (j === need.length) r = [...grant.slice(i)].every((c) => c === '*');
    else if (i === grant.length) r = false;
    // A `*` in the grant takes the next piece of the need (and stays), or matches nothing more.
    else if (grant[i] === '*') r = go(i, j + 1) || go(i + 1, j);
    // A `*` in the need stands for any run, which only a `*` in the grant covers.
    else if (need[j] === '*') r = false;
    else if (need[j] === '?') r = grant[i] === '?' && go(i + 1, j + 1);
    else r = (grant[i] === '?' || grant[i] === need[j]) && go(i + 1, j + 1);
    memo.set(key, r);
    return r;
  };
  return go(0, 0);
}

const ARN_SDK: Record<string, string> = { states: 'sfn', events: 'eventbridge' };

function parseArn(arn: string): Identity | undefined {
  let secretArn = false;
  const parts = arn.split(':');
  if (parts[0] !== 'arn' || parts.length < 6) return undefined;
  const svc = parts[2];
  let res = parts.slice(5).join(':');
  let path: string | undefined;
  let sfn: Identity['sfn'];
  if (svc === 's3') {
    const slash = res.indexOf('/');
    if (slash >= 0) {
      path = res.slice(slash + 1);
      res = res.slice(0, slash);
    }
  } else if (svc === 'secretsmanager') {
    // Kept in ARN form (`prod/db-AbCdEf`, `prod/db-??????`, `prod/db-*`): see secretForm().
    res = res.replace(/^secret:/, '');
    secretArn = true;
  } else if (svc === 'states') {
    // stateMachine:NAME[:version-or-alias], execution:NAME:EXECUTION, express:NAME:EXECUTION. IAM
    // matches the ARN string, so a version or alias is not the unqualified machine, like a Lambda qualifier.
    const m = res.match(/^(stateMachine|execution|express):([^:]*)(?::(.*))?$/);
    if (m) {
      res = m[2];
      sfn =
        m[1] === 'stateMachine'
          ? { type: 'stateMachine', ...(m[3] !== undefined ? { qualifier: m[3] } : {}) }
          : { type: m[1] as 'execution' | 'express', execution: m[3] || '*' };
    }
  } else {
    res = res.replace(/^(table|parameter|function|topic|key|alias|event-bus|stream|deliverystream|log-group|thing|rule)[/:]/, '');
    if (svc === 'dynamodb') {
      const [table, ...rest] = res.split('/');
      res = table;
      if (rest.length) path = rest.join('/');
    }
    // Lambda keeps its qualifier: function:worker:prod and function:worker:dev are different resources.
  }
  const known = (x: string | undefined) => (x && !x.includes('{?}') && !x.includes('…') ? x : undefined);
  return { ...(secretArn ? { secretArn } : {}), service: ARN_SDK[svc] ?? svc, name: res, path, ...(sfn ? { sfn } : {}), partition: known(parts[1]), account: known(parts[4]), region: known(parts[3]), addresses: [], label: arn };
}

function fromString(value: string, service?: string): Identity {
  const arn = parseArn(value);
  if (arn) return arn;
  // https://sqs.<region>.amazonaws.com/<account>/<name>, or the legacy https://<region>.queue.amazonaws.com/...
  const sqs = value.match(/^https:\/\/(?:sqs\.([^./]+)|([^./]+)\.queue)\.[^/]+\/([^/]+)\/([^/]+)$/);
  if (sqs) {
    const known = (x: string | undefined) => (x && !x.includes('*') ? x : undefined);
    return { service: 'sqs', name: sqs[4], region: known(sqs[1] ?? sqs[2]), account: known(sqs[3]), addresses: [], label: value };
  }
  return { service, name: value.replace(/^\//, ''), addresses: [], label: value };
}

/** Identity of a value in the infrastructure: a literal, an ARN pattern, or a reference to a resource. */
function infraIdentity(v: unknown, root: string, index: InfraIndex, service?: string): Identity | undefined {
  if (v === '*') return { any: true, addresses: [], label: '*' };
  if (typeof v === 'string') return fromString(v.replaceAll(UNKNOWN_PART, '*'), service);
  if (!isUnknown(v)) return undefined;
  if (v.pattern !== undefined && v.pattern.startsWith(UNKNOWN_PART) && v.refs.length) {
    const suffix = v.pattern.slice(UNKNOWN_PART.length);
    // Instance addresses: aws_sns_topic.t["a"] and aws_sns_topic.t["b"] are different topics.
    const addresses = [...v.refs];
    const name = addresses.map((a) => index.nameOf(root, a)).find(Boolean);
    const providers=addresses.map(a=>index.accountsOf(root,a));
    const accounts=[...new Set(providers.flat())];
    const account=service!=='s3'&&accounts.length===1&&providers.every(a=>a.length===1)?accounts[0]:undefined;
    return {
      service,
      name,
      ...(account ? {account} : {}),
      path: suffix.startsWith('/') ? suffix.slice(1) : undefined,
      addresses,
      root,
      // Only the bare reference is the resource itself; text after it may turn it into another type.
      ...(suffix ? { sfn: { type: 'unknown' as const } } : {}),
      label: (name ?? addresses.join(', ')) + suffix,
    };
  }
  if (v.pattern !== undefined && v.pattern.startsWith('arn:')) {
    const id = parseArn(v.pattern);
    if (id?.name && !id.name.includes(UNKNOWN_PART)) return { ...id, label: v.pattern.replaceAll(UNKNOWN_PART, '…') };
  }
  return undefined;
}

const S3_BUCKET_ACTIONS = /^s3:(ListBucket|ListBucketVersions|ListBucketMultipartUploads|GetBucket|PutBucket|DeleteBucket|GetLifecycle|PutLifecycle|GetEncryption|PutEncryption)/i;

type Match = 'yes' | 'no' | 'unknown';

/**
 * Whether two Terraform addresses name the same resource instance. Different keys of one resource are
 * different resources; a reference without a usable key (`t[*]`, or `t` for an expanded resource)
 * could be any of them.
 */
function sameInstance(a: string, b: string): Match {
  if (a === b) return 'yes';
  if (configAddress(a) !== configAddress(b)) return 'no';
  const keys = (x: string) => x.match(/\[[^\]]*\]/g) ?? [];
  const ka = keys(a);
  const kb = keys(b);
  if (ka.length !== kb.length || [...ka, ...kb].includes('[*]')) return 'unknown';
  return 'no';
}

/** Addresses compare only within one root; across roots only resolved names and ARNs can match. */
function sameAddresses(grant: Identity, need: Identity): Match | undefined {
  if (!grant.addresses.length || !need.addresses.length) return undefined;
  if (grant.root !== undefined && need.root !== undefined && grant.root !== need.root) return 'no';
  return addressesMatch(grant.addresses, need.addresses);
}

function addressesMatch(grant: string[], need: string[]): Match {
  let result: Match = 'no';
  for (const g of grant) {
    for (const n of need) {
      const m = sameInstance(g, n);
      if (m === 'yes') return 'yes';
      if (m === 'unknown') result = 'unknown';
    }
  }
  return result;
}

const iamService = (svc: string | undefined) => (svc === undefined ? undefined : IAM_PREFIX[svc] ?? svc);

function resourceMatch(grant: Identity | undefined, need: Identity, action: string): Match {
  if (!grant) return 'unknown';
  if (grant.any) return 'yes';
  if (grant.service && need.service && iamService(grant.service) !== iamService(need.service)) return 'no';
  for (const part of ['partition', 'account', 'region'] as const) {
    if (grant[part] && need[part] && !glob(grant[part]!).test(need[part]!)) return 'no';
  }
  if (action.startsWith('s3:')) {
    const objectAction = !S3_BUCKET_ACTIONS.test(action);
    // `arn:aws:s3:::*` or `arn:aws:s3:::exports-*` has no path, but IAM's `*` also matches the slash and
    // the key: compare the whole resource string `bucket/key`.
    if (objectAction && grant.path === undefined && grant.name?.includes('*')) {
      if (need.name === undefined) return 'unknown';
      const whole = `${need.name}/${need.path ?? '*'}`;
      if (covers(grant.name, whole)) return 'yes';
      return globsOverlap(grant.name, whole) ? 'unknown' : 'no';
    }
    if (objectAction !== (grant.path !== undefined)) return 'no';
    // The object key the code writes is not known: only a grant on every key proves access.
    if (objectAction && grant.path !== '*') {
      if (need.path === undefined) {
        const bucket = resourceMatch({ ...grant, path: '*' }, need, action);
        return bucket === 'yes' ? 'unknown' : bucket;
      }
      if (!covers(grant.path!, need.path)) {
        // Some keys of the code's pattern are granted and others are not: the bucket decides the rest.
        if (!need.path.includes('*') || !globsOverlap(grant.path!, need.path)) return 'no';
        const bucket = resourceMatch({ ...grant, path: '*' }, need, action);
        return bucket === 'no' ? 'no' : 'unknown';
      }
    }
  }
  if (action.startsWith('dynamodb:')) {
    // A table ARN covers the table; an index or stream needs `table/X/index/...`. IAM's `*` also matches `/`.
    const full = (id: Identity, name: string) => name + (id.path !== undefined ? `/${id.path}` : '');
    const needPath = need.path ?? '';
    const same = sameAddresses(grant, need) ?? 'no';
    if (same !== 'no') {
      const grantPath = grant.path ?? '';
      if (covers(grantPath, needPath)) return same;
      // An index pattern the grant covers only in part: which index runs is not known.
      return needPath.includes('*') && globsOverlap(grantPath, needPath) ? 'unknown' : 'no';
    }
    if (grant.name && need.name) {
      const n = full(need, need.name);
      const g = full(grant, grant.name);
      if (covers(g, n)) return 'yes';
      return n.includes('*') && globsOverlap(g, n) ? 'unknown' : 'no';
    }
  }
  if (action.startsWith('states:')) {
    const kind = sfnKind(grant, need, action);
    if (kind === 'no') return 'no';
    const name = nameMatch(grant, need);
    return kind === 'yes' ? name : name === 'no' ? 'no' : 'unknown';
  }
  return nameMatch(grant, need);
}

/**
 * A secret's name as IAM sees it: the full ARN ends in AWS's random six-character suffix, so a bare
 * name (`prod/db`, from code or a Terraform resource) stands for `prod/db-??????`.
 */
function secretForm(id: Identity): string {
  return id.secretArn ? id.name! : `${id.name}-??????`;
}

/**
 * The full ARN names a secret the code uses may stand for. Secrets Manager also accepts a partial ARN
 * without the suffix (`...:secret:prod/db`), which IAM authorizes as `prod/db-??????`. An ending of six
 * letters or digits (`-AbCdEf`, `-Config`) may be either AWS's random suffix or part of the name.
 */
function secretNeedForms(need: Identity): string[] {
  const n = need.name!;
  if (!need.secretArn) return [`${n}-??????`];
  if (/-(\?{6}|\*)$/.test(n) || need.secretFullArn) return [n];
  // `prod/db-AbCdEf` may be a full ARN or a partial one for a secret named so (`prod/App-Config`).
  if (/-[A-Za-z0-9]{6}$/.test(n)) return [n, `${n}-??????`];
  return [`${n}-??????`];
}

function nameMatch(grant: Identity, need: Identity): Match {
  const same = sameAddresses(grant, need);
  if (same === 'yes') return 'yes';
  if (grant.name && need.name) {
    if (iamService(grant.service) === 'secretsmanager' || iamService(need.service) === 'secretsmanager') {
      const g = secretForm(grant);
      // The code's secret may be read either way when its ARN ends in something like a suffix.
      const hits = secretNeedForms(need).map((n): Match => (covers(g, n) ? 'yes' : same !== 'no' && globsOverlap(g, n) ? 'unknown' : 'no'));
      // `prod/db-AbCdEf` and a bare `prod/db` overlap: whether AbCdEf is the real suffix is not known.
      return hits.every((h) => h === 'yes') ? 'yes' : hits.every((h) => h === 'no') ? 'no' : 'unknown';
    }
    if (covers(grant.name, need.name)) return 'yes';
    // Some values of the code's pattern are granted and others are not: which one runs is not known.
    return need.name.includes('*') && globsOverlap(grant.name, need.name) ? 'unknown' : 'no';
  }
  return same ?? 'unknown';
}

/** Step Functions actions authorized on an execution ARN; the others that take a resource take the state machine's. */
const SFN_EXECUTION_ACTIONS = new Set(['DescribeExecution', 'StopExecution', 'GetExecutionHistory', 'DescribeStateMachineForExecution', 'RedriveExecution']);

/**
 * Whether a grant's Step Functions resource type and execution name cover what the action needs. The
 * machine name is compared separately. A grant without a type (`*`, `arn:...:*`) covers any type; a
 * bare Terraform reference is the unqualified state machine itself; a reference with text after it
 * may be either type, so it cannot rule access in or out.
 */
function sfnKind(grant: Identity, need: Identity, action: string): Match {
  const onExecution = SFN_EXECUTION_ACTIONS.has(action.slice('states:'.length));
  const needType = need.sfn?.type ?? (onExecution ? 'execution' : 'stateMachine');
  const grantType = grant.sfn?.type ?? (grant.addresses.length ? 'stateMachine' : undefined);
  if (grantType === undefined) return 'yes';
  if (grantType === 'unknown' || needType === 'unknown') return 'unknown';
  if ((grantType === 'stateMachine') !== (needType === 'stateMachine')) return 'no';
  if (grantType === 'stateMachine') return qualifierMatch(grant, need);
  if (need.sfn && need.sfn.type !== grantType) return 'no';
  // An execution named only by its state machine is any execution of it.
  const g = grant.sfn?.execution ?? '*';
  const n = need.sfn?.execution ?? '*';
  if (covers(g, n)) return 'yes';
  return globsOverlap(g, n) ? 'unknown' : 'no';
}

/**
 * A state machine version or alias (`orders:live`) is a different ARN from `orders`: `stateMachine:orders`
 * does not cover it, `stateMachine:orders:*` covers it but not the unqualified machine. With literal
 * names the full `name:qualifier` strings are compared, so `stateMachine:orders*` covers both.
 */
function qualifierMatch(grant: Identity, need: Identity): Match {
  const gq = grant.sfn?.qualifier;
  const nq = need.sfn?.qualifier;
  if (gq === undefined && nq === undefined) return 'yes';
  if (grant.name && need.name && !grant.addresses.length) {
    const g = gq === undefined ? grant.name : `${grant.name}:${gq}`;
    const n = nq === undefined ? need.name : `${need.name}:${nq}`;
    if (covers(g, n)) return 'yes';
    return globsOverlap(g, n) ? 'unknown' : 'no';
  }
  if (gq === undefined || nq === undefined) return 'no';
  if (covers(gq, nq)) return 'yes';
  return globsOverlap(gq, nq) ? 'unknown' : 'no';
}

/** True when some string matches both globs (`*` any run, `?` one character). */
export function globsOverlap(a: string, b: string): boolean {
  const memo = new Map<number, boolean>();
  const go = (i: number, j: number): boolean => {
    const key = i * (b.length + 1) + j;
    const hit = memo.get(key);
    if (hit !== undefined) return hit;
    let r: boolean;
    if (i === a.length && j === b.length) r = true;
    else if (a[i] === '*') r = go(i + 1, j) || (j < b.length && go(i, j + 1));
    else if (b[j] === '*') r = go(i, j + 1) || (i < a.length && go(i + 1, j));
    else if (i === a.length || j === b.length) r = false;
    else r = (a[i] === '?' || b[j] === '?' || a[i] === b[j]) && go(i + 1, j + 1);
    memo.set(key, r);
    return r;
  };
  return go(0, 0);
}

function actionMatches(patterns: unknown[], action: string): boolean | undefined {
  let unknown = false;
  for (const p of patterns) {
    if (typeof p !== 'string') {
      unknown = true;
      continue;
    }
    if (actionGlob(p).test(action)) return true;
  }
  return unknown ? undefined : false;
}

/** Operations such as dynamodb:ListTables act on no resource: only a statement on Resource "*" covers them. */
function starOnly(st: RoleStatement): Match {
  const hit = (list: unknown[]): Match => (list.includes('*') ? 'yes' : list.some((r) => typeof r !== 'string') ? 'unknown' : 'no');
  if (st.notResources) {
    const h = hit(st.notResources);
    return h === 'yes' ? 'no' : h === 'unknown' ? 'unknown' : 'yes';
  }
  return hit(st.resources);
}

/** sts:GetCallerIdentity needs no permission and cannot be denied. */
const NO_PERMISSION_NEEDED: RoleStatement = { effect: 'Allow', actions: ['sts:GetCallerIdentity'], resources: ['*'], policy: 'needs no permission', source: { file: 'AWS', line: 0 }, style: 'json' };

function evaluate(statements: RoleStatement[], action: string, need: Identity | undefined, root: string, index: InfraIndex, service: string) {
  if (action === 'sts:GetCallerIdentity') return { result: 'yes' as Match, statement: NO_PERMISSION_NEEDED, denied: false };
  let allow: Match = 'no';
  let allowedBy: RoleStatement | undefined;
  let denyUnknown = false;
  for (const st of statements) {
    const listed = actionMatches(st.notActions ?? st.actions, action);
    // NotAction applies to every action it does not list; an unknown entry leaves that undecided.
    const matches = st.notActions ? (listed === undefined ? undefined : !listed) : listed;
    if (matches === false) continue;
    let m: Match = 'no';
    if (UNSCOPED_OPERATIONS.has(action)) m = starOnly(st);
    else if (!need) m = 'unknown';
    else if (st.notResources) {
      // NotResource: applies to everything except the listed resources.
      const hits = st.notResources.map((r) => resourceMatch(infraIdentity(r, st.root ?? root, index, service), need, action));
      m = hits.includes('yes') ? 'no' : hits.includes('unknown') ? 'unknown' : 'yes';
    } else {
      for (const r of st.resources) {
        const rm = resourceMatch(infraIdentity(r, st.root ?? root, index, service), need, action);
        if (rm === 'yes') {
          m = 'yes';
          break;
        }
        if (rm === 'unknown') m = 'unknown';
      }
    }
    if (matches === undefined && m === 'yes') m = 'unknown';
    // Conditions depend on the request (source VPC, tags, MFA...), which static analysis cannot see.
    if (st.conditional && m === 'yes') m = 'unknown';
    // A statement that may belong to a namesake role in another account cannot prove anything.
    if (st.uncertainAccount && m === 'yes') m = 'unknown';
    if (st.effect === 'Unknown') {
      // The effect is not known: the statement may allow or deny, so it neither grants nor can be ignored.
      if (m !== 'no') {
        denyUnknown = true;
        if (allow === 'no') allow = 'unknown';
      }
      continue;
    }
    if (st.effect === 'Deny') {
      if (m === 'yes') return { result: 'no' as Match, statement: st, denied: true };
      if (m === 'unknown') denyUnknown = true;
      continue;
    }
    if (m === 'yes' && allow !== 'yes') {
      allow = 'yes';
      allowedBy = st;
    } else if (m === 'unknown' && allow === 'no') allow = 'unknown';
  }
  if (allow === 'yes' && denyUnknown) return { result: 'unknown' as Match, statement: allowedBy, denied: false, mayDeny: true };
  return { result: allow, statement: allowedBy, denied: false, mayDeny: denyUnknown };
}

interface Target {
  root: string;
  role: Role;
  /** The env value the target's compute binds for the fact, when the fact names an env var. */
  envValue?: unknown;
  envName?: string;
}

function describeRef(r: ResourceRef): string {
  if (r.kind === 'literal') return r.value;
  if (r.kind === 'pattern') return r.glob;
  if (r.kind === 'env') return `$${r.name}${r.fallback !== undefined ? ` (default "${r.fallback}")` : ''}`;
  return r.text;
}

/** Merge facts from one call site that act on the same resource, so their actions are judged together. */
function groupFacts(facts: AccessFact[]): AccessFact[] {
  const groups = new Map<string, AccessFact>();
  for (const f of facts) {
    const k = JSON.stringify([f.file, f.line, f.service, f.resource, f.via, Boolean(f.possible), f.index]);
    const g = groups.get(k);
    if (g) g.actions = [...new Set([...g.actions, ...f.actions])];
    else groups.set(k, { ...f, actions: [...new Set(f.actions)] });
  }
  return [...groups.values()];
}

// Display text built from values: what a link prints about the resource, and the suggested statement.
const LINK_TEXT = new Set(['resource', 'access', 'detail', 'note', 'code']);

export function reconcile(facts: AccessFact[], envReads: EnvRead[], index: InfraIndex, opts: ReconcileOptions = {}): AppLink[] {
  const links: AppLink[] = [];
  const pairedEnv = new Set<string>();

  for (const fact of groupFacts(facts)) {
    let resource = fact.resource;
    let confidence: AppLink['confidence'] = 'proven';
    let note: string | undefined;
    // An unresolved resource next to an added env var that names the same kind of resource: pair them.
    if (resource.kind === 'unresolved' && opts.pairWithChangedEnv) {
      const unresolvedText = resource.text;
      const candidates = envReads.filter((e) => serviceHint({ kind: 'env', name: e.name }) === fact.service);
      const unique = [...new Set(candidates.map((c) => c.name))];
      if (unique.length === 1) {
        note = `paired with ${unique[0]}, read in the same change; ${unresolvedText} could not be followed`;
        resource = { kind: 'env', name: unique[0] };
        confidence = 'likely';
        pairedEnv.add(unique[0]);
      }
    }
    const base = {
      confidence,
      callsite: `${fact.file}:${fact.line}`,
      resource: describeRef(resource),
      via: fact.via,
      note,
    };
    const targets = findTargets(fact, resource, index, opts);
    if (!targets.length) {
      links.push(link(base, fact.actions, 'UNRESOLVED',
        resource.kind === 'env'
          ? `No Lambda or ECS task in the analyzed Terraform sets ${resource.name}, so the role running this code is unknown`
          : 'Cannot tell which Lambda or ECS task runs this code. Link the app to its role (--role or .terratrust.json)'));
      continue;
    }
    for (const t of targets) {
      const found = checkTarget(fact, resource, t, index, base);
      // A role matched by ARN in a root that targets several accounts may not be the deployed role.
      links.push(
        ...(t.role.accountUncertain
          ? found.map((l) =>
              l.status === 'GRANTED' || l.status === 'NOT_GRANTED'
                ? { ...l, status: 'UNRESOLVED' as const, detail: `${l.detail}. ${t.root} targets several AWS accounts, and which one created this role is not known statically`, suggestion: undefined }
                : l
            )
          : found)
      );
    }
  }

  const covered = new Set(facts.flatMap((f) => (f.resource.kind === 'env' ? [f.resource.name] : [])));
  for (const name of [...new Set(envReads.map((e) => e.name))]) {
    if (opts.externallyDefinedEnv?.has(name)) continue;
    if (envReads.filter((e) => e.name === name).every((e) => e.hasDefault)) continue;
    if (index.computesSetting(name).length) continue;
    if (!looksLikeInfraEnv(name) && !covered.has(name) && !pairedEnv.has(name)) continue;
    const read = envReads.find((e) => e.name === name)!;
    links.push({
      status: 'MISSING',
      confidence: 'proven',
      callsite: `${read.file}:${read.line}`,
      actions: [],
      resource: name,
      access: `reads ${name}`,
      detail: `No Lambda or ECS task in the analyzed Terraform sets ${name}`,
    });
  }
  // Matching reads sensitive values (env, policies); nothing written for the reader may contain one.
  return scrubDeep(links, index.sensitiveLeaves, LINK_TEXT);
}

type LinkBase = Pick<AppLink, 'confidence' | 'callsite' | 'resource' | 'via' | 'note'> & Partial<Pick<AppLink, 'root' | 'role'>>;

function link(base: LinkBase, actions: string[], status: LinkStatus, detail: string): AppLink {
  const access = `${actions.join(', ')} on ${base.resource}${base.via ? ` (via ${base.via})` : ''}${base.note ? ` (${base.note})` : ''}`;
  return { ...base, actions, status, detail, access };
}

/** Env vars that name AWS resources; others (feature flags, log levels) are not infrastructure's business. */
function looksLikeInfraEnv(name: string): boolean {
  return /(_ARN|_URL|_BUCKET|_BUCKET_NAME|_QUEUE|_TOPIC|_TABLE|_TABLE_NAME|_SECRET_NAME|_SECRET_ID|_STREAM|_SFN_NAME|_STATE_MACHINE|_PARAMETER)$/.test(name);
}

function findTargets(fact: AccessFact, resource: ResourceRef, index: InfraIndex, opts: ReconcileOptions): Target[] {
  const envName = resource.kind === 'env' ? resource.name : undefined;
  if (opts.roleNames?.length) {
    // The role is given; the env var's value still comes from a compute that runs as that role.
    return opts.roleNames.flatMap((n) =>
      index.rolesNamed(n).map((role) => {
        const setter = envName
          ? index.computesSetting(envName).find((c) => index.rolesFor(c).some((r) => r.root === role.root && r.instance === role.instance))
          : undefined;
        return { root: role.root, role, ...(setter && envName ? { envValue: setter.env[envName], envName } : {}) };
      })
    );
  }
  const fileEnv = opts.fileEnv?.get(fact.file) ?? [];
  // Candidates: computes that set the env var the call uses, or else (env unset, code has a fallback,
  // or no env var at all) the computes sharing env vars with the package.
  let candidates = envName ? index.computesSetting(envName) : [];
  if (!candidates.length && (!envName || (resource.kind === 'env' && resource.fallback !== undefined))) {
    candidates = index.computes.filter((c) => fileEnv.some((n) => n in c.env));
  }
  // Among those, keep the computes whose environment best matches what this package reads.
  if (fileEnv.length && candidates.length > 1) {
    const score = (c: (typeof candidates)[number]) => fileEnv.filter((n) => n in c.env).length;
    const best = Math.max(...candidates.map(score));
    candidates = candidates.filter((c) => score(c) === best);
  }
  const out: Target[] = [];
  for (const c of candidates) {
    for (const role of index.rolesFor(c)) {
      if (!out.some((o) => o.root === role.root && o.role.instance === role.instance)) {
        out.push({ root: c.root, role, envValue: envName && envName in c.env ? c.env[envName] : undefined, envName });
      }
    }
  }
  return out;
}

function needIdentity(resource: ResourceRef, t: Target, index: InfraIndex, service: string): Identity | undefined {
  const id = needIdentityOf(resource, t, index, service);
  // `...:secret:prod/db-a1B2c3` is a full ARN when Terraform declares the secret `prod/db` and no secret
  // named `prod/db-a1B2c3`; otherwise the tail may be part of the name (see secretNeedForms).
  if (id?.secretArn && id.name && /-[A-Za-z0-9]{6}$/.test(id.name)) {
    const types = SERVICE_TYPES.secretsmanager ?? ['aws_secretsmanager_secret'];
    const base = id.name.slice(0, -7);
    if (index.instancesByName(t.root, types, base,id.account).length && !index.instancesByName(t.root, types, id.name,id.account).length) return { ...id, secretFullArn: true };
  }
  return id;
}

function needIdentityOf(resource: ResourceRef, t: Target, index: InfraIndex, service: string): Identity | undefined {
  if (resource.kind === 'literal') return fromString(resource.value, service);
  if (resource.kind === 'pattern') {
    const arn = resource.glob.startsWith('arn:') ? parseArn(resource.glob) : undefined;
    // A `*` in the account or region of the code's ARN means not known, not every account.
    // A `*` the code's pattern puts in the partition, account or region means "not known", not "any".
    if (arn) return { ...arn, partition: arn.partition?.includes('*') ? undefined : arn.partition, account: arn.account?.includes('*') ? undefined : arn.account, region: arn.region?.includes('*') ? undefined : arn.region };
    return { service, name: resource.glob, addresses: [], label: resource.glob };
  }
  if (resource.kind === 'env') {
    if (t.envValue === undefined && resource.fallback !== undefined) return fromString(resource.fallback, service);
    // A sensitive value is matched on what it holds and never printed.
    if (isRedacted(t.envValue)) {
      const id = infraIdentity(reveal(t.envValue), t.root, index, service);
      return id && { ...id, label: '(sensitive)' };
    }
    return infraIdentity(t.envValue, t.root, index, service);
  }
  return undefined;
}

/** Check every action of one call against one role; actions with the same outcome share a link. */
function checkTarget(fact: AccessFact, resource: ResourceRef, t: Target, index: InfraIndex, b: LinkBase): AppLink[] {
  const roleLabel = t.role.name ? `role ${t.role.name}` : t.role.address;
  const base: LinkBase = { ...b, root: t.root, role: t.role.address };
  if (resource.kind === 'unresolved') {
    // Operations on no resource (ListTables, ListQueues) are checked anyway: they need Resource "*".
    const unscoped = fact.actions.filter((a) => UNSCOPED_OPERATIONS.has(a));
    const rest = fact.actions.filter((a) => !UNSCOPED_OPERATIONS.has(a));
    return [
      ...(unscoped.length ? checkTarget({ ...fact, actions: unscoped }, { kind: 'literal', value: '*' }, t, index, b) : []),
      ...(rest.length ? [link(base, rest, 'UNRESOLVED', `Runs as ${roleLabel}, but the resource (${resource.text}) cannot be followed statically`)] : []),
    ];
  }
  let need = needIdentity(resource, t, index, fact.service);
  // A table, queue or secret named without an ARN is in the account the role runs in, so a grant on
  // the same name in another account does not cover it. Only when the root targets one known account.
  const accounts = index.accountsOf(t.root,t.role.instance);
  if (need && !need.account && !need.any && !need.addresses.length && !need.label.startsWith('arn:') && accounts.length === 1) need = { ...need, account: accounts[0] };
  if (need && fact.service === 'dynamodb' && fact.index) need = { ...need, path: `index/${fact.index}`, label: `${need.label} index ${fact.index}` };
  const target = need?.label ?? describeRef(resource);
  const withTarget: LinkBase = { ...base, resource: resource.kind === 'env' ? `${describeRef(resource)} (${target})` : target };
  const grants = index.grants(t.role);
  const unknownManaged = grants.managedPolicies.filter((a) => !(managedPolicyName(a) in MANAGED_POLICY_ACTIONS));
  const statements: RoleStatement[] = [
    ...grants.statements,
    ...grants.managedPolicies
      .filter((a) => managedPolicyName(a) in MANAGED_POLICY_ACTIONS)
      .map((a) => ({ effect: 'Allow' as const, actions: MANAGED_POLICY_ACTIONS[managedPolicyName(a)], resources: ['*'], policy: `AWS managed ${managedPolicyName(a)}`, source: { file: 'AWS', line: 0 }, style: 'json' as const })),
    // From a root that may be another account: a catalogued policy can only make access undetermined.
    ...grants.uncertainManaged
      .filter((a) => managedPolicyName(a) in MANAGED_POLICY_ACTIONS)
      .map((a) => ({ effect: 'Allow' as const, actions: MANAGED_POLICY_ACTIONS[managedPolicyName(a)], resources: ['*'], policy: `AWS managed ${managedPolicyName(a)}`, source: { file: 'AWS', line: 0 }, style: 'json' as const, uncertainAccount: true })),
  ];
  const namesService = (action: string) => uncertainManagedCovers(grants.uncertainManaged, action);
  const granted: Array<{ action: string; st: RoleStatement }> = [];
  const missing: string[] = [];
  const denied: Array<{ action: string; st: RoleStatement }> = [];
  const unknown: string[] = [];
  for (const action of fact.actions) {
    const r = evaluate(statements, action, need, t.root, index, fact.service);
    // A policy that cannot be read (or an AWS managed one that is not catalogued) may hold a Deny,
    // so an Allow elsewhere does not prove access.
    if (r.result === 'yes' && (grants.opaque.length || unknownManaged.length) && action !== 'sts:GetCallerIdentity') unknown.push(action);
    else if (r.result === 'yes') granted.push({ action, st: r.statement! });
    else if (r.denied) denied.push({ action, st: r.statement! });
    else if (r.result === 'unknown' || unknownManaged.length || grants.opaque.length || namesService(action)) unknown.push(action);
    else missing.push(action);
  }
  // TransactWriteItems needs only the write actions its items use: a partial grant may be enough.
  if (ANY_OF.has(`${IAM_PREFIX[fact.service] ?? fact.service}:${fact.operation}`) && missing.length && (granted.length || unknown.length)) {
    unknown.push(...missing.splice(0));
  }
  // A permissions boundary caps the role: an action its policies allow must also be allowed there.
  if (grants.boundary && granted.length) {
    const b = grants.boundary;
    for (const g of [...granted]) {
      const r = b.opaque ? undefined : evaluate(b.statements, g.action, need, t.root, index, fact.service);
      if (r?.result === 'yes') continue;
      granted.splice(granted.indexOf(g), 1);
      if (r?.result === 'no') denied.push({ action: g.action, st: { ...g.st, policy: `${b.statements[0]?.policy ?? 'the permissions boundary'} (permissions boundary)` } });
      else unknown.push(g.action);
    }
  }
  const out: AppLink[] = [];
  if (granted.length) {
    const st = granted[0].st;
    const where = st.source.file === 'AWS' ? st.policy : `${st.policy}, ${st.source.file}:${st.source.line}`;
    out.push(link(withTarget, granted.map((g) => g.action), 'GRANTED', `${roleLabel} allows it (${where})`));
  }
  if (missing.length && fact.possible) {
    out.push(link(withTarget, missing, 'UNRESOLVED', `${roleLabel} does not allow ${missing.join(', ')} on ${target}. ${fact.via ?? 'The helper'} can make these calls, but this code may not use that path`));
  } else if (missing.length) {
    // Suggest a policy in the role's own root, never one that may belong to another account's namesake.
    const own = grants.statements.filter((st) => (st.root ?? t.root) === t.root && !st.uncertainAccount && st.effect !== 'Deny');
    const holder = own.find((st) => st.style === 'document') ?? own[0];
    const where = holder ? ` Add a statement to ${holder.policy} (${holder.source.file}:${holder.source.line}).` : '';
    const l = link(withTarget, missing, 'NOT_GRANTED', `${roleLabel} does not allow ${missing.join(', ')} on ${target}, so the call fails with AccessDenied when it runs under this role.${where}`);
    if (holder && need) {
      if (!need.addresses.length && need.name && !need.name.includes('*')) {
        const found = index.addressByName(t.root, SERVICE_TYPES[fact.service] ?? [], need.name);
        if (found) need.addresses = [found];
      }
      l.suggestion = { target: holder.policy, file: holder.source.file, line: holder.source.line, code: statementCode(holder, missing, resourceExpr(need, missing, fact.service, holder.module)) };
    }
    out.push(l);
  }
  if (denied.length) {
    const actions = denied.map((d) => d.action);
    const detail = `${roleLabel} explicitly denies ${actions.join(', ')} on ${target} (${denied[0].st.policy})`;
    // Like a missing allow: the helper can make the call, but this code may never take that path.
    out.push(
      fact.possible
        ? link(withTarget, actions, 'UNRESOLVED', `${detail}. ${fact.via ?? 'The helper'} can make these calls, but this code may not use that path`)
        : link(withTarget, actions, 'NOT_GRANTED', detail)
    );
  }
  if (granted.length && need) out.push(...kmsDependency(fact, granted.map((g) => g.action), need, t, index, statements, withTarget, roleLabel));
  if (unknown.length) {
    const why = [
      ...(unknownManaged.length ? [`AWS managed policies ${unknownManaged.map(managedPolicyName).join(', ')} are attached and not evaluated`] : []),
      ...(grants.opaque.length ? [`${grants.opaque.join(', ')} cannot be read statically`] : []),
      ...(grants.boundary?.opaque ? [`the permissions boundary ${grants.boundary.opaque} cannot be read statically`] : []),
      ...(grants.uncertainRoots.length
        ? [`policies in ${grants.uncertainRoots.join(', ')} name a role ${t.role.name ?? ''} too, but whether that root targets the same AWS account is not known statically`]
        : []),
    ].map((w) => `; ${w}`).join('');
    out.push(link(withTarget, unknown, 'UNRESOLVED', `Cannot tell whether ${roleLabel} allows ${unknown.join(', ')} on ${target}${why}`));
  }
  return out;
}

const SERVICE_TYPES: Record<string, string[]> = {
  sns: ['aws_sns_topic'],
  sqs: ['aws_sqs_queue'],
  dynamodb: ['aws_dynamodb_table'],
  s3: ['aws_s3_bucket'],
  secretsmanager: ['aws_secretsmanager_secret'],
  sfn: ['aws_sfn_state_machine'],
  ssm: ['aws_ssm_parameter'],
  lambda: ['aws_lambda_function'],
  kinesis: ['aws_kinesis_stream'],
};

const ARN_TEMPLATE: Record<string, (name: string) => string> = {
  sns: (n) => `arn:aws:sns:<region>:<account-id>:${n}`,
  sqs: (n) => `arn:aws:sqs:<region>:<account-id>:${n}`,
  dynamodb: (n) => `arn:aws:dynamodb:<region>:<account-id>:table/${n}`,
  secretsmanager: (n) => `arn:aws:secretsmanager:<region>:<account-id>:secret:${n}-??????`,
  sfn: (n) => `arn:aws:states:<region>:<account-id>:stateMachine:${n}`,
  ssm: (n) => `arn:aws:ssm:<region>:<account-id>:parameter/${n.replace(/^\//, '')}`,
  lambda: (n) => `arn:aws:lambda:<region>:<account-id>:function:${n}`,
  kinesis: (n) => `arn:aws:kinesis:<region>:<account-id>:stream/${n}`,
  s3: (n) => `arn:aws:s3:::${n}`,
};

/** A Terraform expression for the resource, relative to the module that holds the policy when possible. */
function resourceExpr(need: Identity, actions: string[], service: string, holderModule?: string): string {
  const objectLevel = service === 's3' && actions.some((a) => !S3_BUCKET_ACTIONS.test(a));
  const prefix = holderModule ? `${configAddress(holderModule)}.` : '';
  // Sub-resources the call needs: S3 objects, DynamoDB indexes.
  const suffix = objectLevel ? '/*' : service === 'dynamodb' && need.path ? `/${need.path}` : '';
  const local = need.addresses.find((a) => (prefix ? a.startsWith(prefix) : !a.startsWith('module.')));
  if (local) {
    const ref = `${local.slice(prefix.length)}.arn`;
    return suffix ? `"\${${ref}}${suffix}"` : ref;
  }
  if (need.label.startsWith('arn:')) return JSON.stringify(need.label);
  const arn = need.name ? ARN_TEMPLATE[service]?.(need.name) : undefined;
  return JSON.stringify(arn ? arn + suffix : need.label);
}

function statementCode(holder: RoleStatement, actions: string[], resource: string): string {
  const acts = `[${actions.map((a) => JSON.stringify(a)).join(', ')}]`;
  if (holder.style === 'document') {
    return `statement {\n  actions   = ${acts}\n  resources = [${resource}]\n}`;
  }
  return `{\n  Effect   = "Allow"\n  Action   = ${acts}\n  Resource = [${resource}]\n}`;
}

/** KMS actions a call needs when its target is encrypted with a customer managed key. */
const KMS_NEEDS: Record<string, string[]> = {
  'sqs:SendMessage': ['kms:GenerateDataKey', 'kms:Decrypt'],
  'sqs:ReceiveMessage': ['kms:Decrypt'],
  'sns:Publish': ['kms:GenerateDataKey', 'kms:Decrypt'],
  'secretsmanager:GetSecretValue': ['kms:Decrypt'],
  's3:PutObject': ['kms:GenerateDataKey'],
  's3:GetObject': ['kms:Decrypt'],
};

const KEY_ATTR: Record<string, string> = {
  aws_sqs_queue: 'kms_master_key_id',
  aws_sns_topic: 'kms_master_key_id',
  aws_secretsmanager_secret: 'kms_key_id',
};

/**
 * The customer managed key that encrypts a resource, as a Terraform instance address, when Terraform
 * manages both. `ambiguous` when the configuration names a key made with count or for_each without
 * saying which instance.
 */
function customerKeyOf(index: InfraIndex, root: string, address: string): string | 'ambiguous' | undefined {
  const inst = index.instance(root, address);
  if (!inst) return undefined;
  const instances = index.evaluations.find((e) => e.root === root)?.instances ?? [];
  // The exact instance an attribute value refers to (`aws_kms_key.k["b"].arn`), else the config
  // reference, which is only an instance when the resource has exactly one.
  const resolve = (value: unknown, refs: string[], type: string): string | 'ambiguous' | undefined => {
    const exact = unknownRefs(value).filter((r) => r.includes(`${type}.`) && r !== configAddress(r));
    if (exact.length) return exact[0];
    const cfg = refs.find((r) => r.includes(`${type}.`));
    if (!cfg) return undefined;
    const all = instances.filter((i) => i.configAddress === configAddress(cfg));
    return all.length === 1 ? all[0].address : all.length > 1 ? 'ambiguous' : undefined;
  };
  let value: unknown;
  let refs: string[] = [];
  if (KEY_ATTR[inst.type]) {
    value = inst.attrs[KEY_ATTR[inst.type]];
    refs = inst.references[KEY_ATTR[inst.type]] ?? [];
  }
  if (inst.type === 'aws_s3_bucket') {
    // The helper for this bucket instance: by the bucket's known name, else by an exact instance
    // reference, else by the config reference. Several left over means the key is not known.
    const helpers = instances.filter((i) => i.type === 'aws_s3_bucket_server_side_encryption_configuration');
    const name = inst.attrs.bucket;
    const byName = typeof name === 'string' ? helpers.filter((i) => i.attrs.bucket === name) : [];
    const byRef = helpers.filter((i) => {
      const exact = unknownRefs(i.attrs.bucket).filter((r) => r !== configAddress(r));
      if (exact.length) return exact.includes(inst.address);
      return typeof i.attrs.bucket !== 'string' && (i.references.bucket ?? []).includes(inst.configAddress);
    });
    const candidates = byName.length ? byName : byRef;
    if (candidates.length > 1) return 'ambiguous';
    value = candidates[0]?.attrs.rule;
    refs = candidates[0]?.references.rule ?? [];
  }
  const key = resolve(value, refs, 'aws_kms_key');
  if (key) return key;
  const alias = resolve(value, refs, 'aws_kms_alias');
  if (!alias || alias === 'ambiguous') return alias;
  const a = index.instance(root, alias);
  return a ? resolve(a.attrs.target_key_id, a.references.target_key_id ?? [], 'aws_kms_key') : undefined;
}

/** Resource addresses an attribute value was derived from, anywhere inside it. */
function unknownRefs(v: unknown): string[] {
  if (isUnknown(v)) return v.refs;
  if (Array.isArray(v)) return v.flatMap(unknownRefs);
  if (v && typeof v === 'object' && !isRedacted(v)) return Object.values(v).flatMap(unknownRefs);
  return [];
}

interface KeyPolicyVerdict {
  /** The key policy grants the role the action itself. */
  allow: Match;
  /** The key policy denies the role the action. */
  deny: Match;
  /** The key policy delegates to the account's IAM policies (the default key policy does). */
  delegates: Match;
}

/** The key's policy document: its own `policy` argument, or an aws_kms_key_policy whose key_id is this key. */
function keyPolicyValue(index: InfraIndex, root: string, keyAddress: string): unknown {
  const key = index.instance(root, keyAddress);
  if (key && key.attrs.policy !== undefined && key.attrs.policy !== null && key.attrs.policy !== '') return key.attrs.policy;
  const keyCfg = configAddress(keyAddress);
  const keyValues = new Set([key?.attrs.key_id, key?.attrs.arn, key?.attrs.id].filter((v): v is string => typeof v === 'string' && v !== ''));
  const separate = (index.evaluations.find((e) => e.root === root)?.instances ?? []).filter((i) => {
    if (i.type !== 'aws_kms_key_policy' || i.mode !== 'managed') return false;
    const v = i.attrs.key_id;
    // An exact instance reference (`aws_kms_key.k["a"].id`) decides; otherwise the config reference or the value.
    const exact = isUnknown(v) ? v.refs.filter((r) => configAddress(r) === keyCfg && r !== keyCfg) : [];
    if (exact.length) return key !== undefined && exact.some((r) => r === key.address || r.startsWith(`${key.address}.`));
    if ((i.references.key_id ?? []).some((r) => configAddress(r) === keyCfg)) return true;
    return typeof v === 'string' && keyValues.has(v);
  });
  return separate[0]?.attrs.policy;
}

/**
 * What a customer managed key's policy says about one action for one role. A key policy decides alone:
 * an identity-policy Allow only counts when the key policy delegates to the account root.
 */
function keyPolicy(index: InfraIndex, root: string, keyAddress: string, role: Role, action: string): KeyPolicyVerdict {
  // The policy is an argument of the key, or of a separate aws_kms_key_policy resource for it.
  const value = keyPolicyValue(index, root, keyAddress);
  // Without either, AWS applies the default key policy, which delegates to IAM.
  if (value === undefined || value === null || value === '') return { allow: 'no', deny: 'no', delegates: 'yes' };
  const parsed = parsePolicy(value);
  if (parsed.kind !== 'ok') return { allow: 'unknown', deny: 'unknown', delegates: 'unknown' };
  const accounts = index.accountsOf(role.root,role.instance);
  // A reference to `aws_iam_role.r["b"].arn` names that instance; a config-level reference to a role
  // made with count or for_each may or may not be this instance. A role ARN names this role only in
  // the root's account; when that account is not known statically, it may or may not.
  const principalMatch = (v: unknown): Match => {
    if (v === '*') return 'yes';
    if (typeof v === 'string') {
      if (role.name === undefined || !v.endsWith(`:role${role.path}${role.name}`)) return 'no';
      const acct = v.match(/^arn:aws[\w-]*:iam::(\d{12}):role\//)?.[1];
      if (!acct) return 'yes';
      return !accounts.length ? 'unknown' : accounts.includes(acct) ? 'yes' : 'no';
    }
    if (isUnknown(v)) {
      const refs = v.refs.filter((r) => configAddress(r) === role.address);
      if (!refs.length) return 'no';
      const exact = refs.filter((r) => r !== role.address);
      if (exact.length) return exact.some((r) => r === role.instance || r.startsWith(`${role.instance}.`)) ? 'yes' : 'no';
      return role.instance === role.address ? 'yes' : 'unknown';
    }
    const parts = Array.isArray(v) ? v : v !== null && typeof v === 'object' ? Object.values(v) : [];
    const hits = parts.map(principalMatch);
    return hits.includes('yes') ? 'yes' : hits.includes('unknown') ? 'unknown' : 'no';
  };
  // Delegation to IAM needs the key's own account root. A literal account counts unless the root's known
  // accounts exclude it (keys almost always delegate to their own account by number); an account from a
  // variable may be another one, so only `${data.aws_caller_identity.x.account_id}` counts for certain.
  const namesRoot = (v: unknown): Match => {
    if (typeof v === 'string') {
      const acct = v.match(/^arn:aws[\w-]*:iam::(\d{12}):root$/)?.[1] ?? v.match(/^(\d{12})$/)?.[1];
      if (acct) return !accounts.length || accounts.includes(acct) ? 'yes' : 'no';
      return 'no';
    }
    if (isUnknown(v)) {
      if (v.pattern === undefined) return 'unknown';
      if (!/:root$/.test(v.pattern)) return 'no';
      const callerIdentity = v.refs.some((r) => /(^|\.)data\.aws_caller_identity\./.test(r));
      return callerIdentity && accounts.length <= 1 ? 'yes' : 'unknown';
    }
    const parts = Array.isArray(v) ? v : v !== null && typeof v === 'object' ? Object.values(v) : [];
    const hits = parts.map(namesRoot);
    return hits.includes('yes') ? 'yes' : hits.includes('unknown') ? 'unknown' : 'no';
  };

  /**
   * Whether a NotPrincipal lists the role's own account. Unlike namesRoot (delegation), an account
   * counts only if it is the role's: when the root's account is not known statically, or the root
   * spans several accounts, a listed account may be another one.
   */
  const listsRoleAccount = (v: unknown): Match => {
    if (typeof v === 'string') {
      const acct = v.match(/^arn:aws[\w-]*:iam::(\d{12}):root$/)?.[1] ?? v.match(/^(\d{12})$/)?.[1];
      if (!acct) return 'no';
      if (accounts.length === 1) return accounts[0] === acct ? 'yes' : 'no';
      return accounts.length && !accounts.includes(acct) ? 'no' : 'unknown';
    }
    // `arn:aws:iam::${data.aws_caller_identity.current.account_id}:root` is this root's account; an
    // account from a variable or anything else may be another one.
    if (isUnknown(v)) {
      if (v.pattern === undefined) return 'unknown';
      if (!/:root$/.test(v.pattern)) return 'no';
      const callerIdentity = v.refs.some((r) => /(^|\.)data\.aws_caller_identity\./.test(r));
      return callerIdentity && accounts.length <= 1 ? 'yes' : 'unknown';
    }
    const parts = Array.isArray(v) ? v : v !== null && typeof v === 'object' ? Object.values(v) : [];
    const hits = parts.map(listsRoleAccount);
    return hits.includes('yes') ? 'yes' : hits.includes('unknown') ? 'unknown' : 'no';
  };
  let boundary: boolean | undefined;
  const bounded = () => (boundary ??= index.grants(role).boundary !== undefined);
  const verdict: KeyPolicyVerdict = { allow: 'no', deny: 'no', delegates: 'no' };
  const raise = (k: keyof KeyPolicyVerdict, m: Match) => {
    if (m === 'yes' || (m === 'unknown' && verdict[k] === 'no')) verdict[k] = m;
  };
  for (const st of parsed.statements) {
    const acts = actionMatches(Array.isArray(st.Action) ? st.Action : [st.Action], action);
    if (acts === false) continue;
    // A Condition depends on the request; it may or may not hold.
    const certain: Match = acts === true && !st.Condition ? 'yes' : 'unknown';
    // NotPrincipal applies the statement to everyone except the principals it lists. Per the IAM
    // documentation, a role is reliably excluded only when its account is listed too (AWS may check
    // the account, then the role, then the session). A Deny with NotPrincipal always applies to a
    // role with a permissions boundary; for an Allow (which AWS does not support with NotPrincipal)
    // a boundary only makes the exclusion uncertain.
    const listed = st.NotPrincipal !== undefined ? principalMatch(st.NotPrincipal) : undefined;
    const accountListed = st.NotPrincipal !== undefined ? listsRoleAccount(st.NotPrincipal) : 'no';
    const excluded: Match | undefined =
      listed !== 'yes'
        ? listed
        : bounded()
          ? st.Effect === 'Deny'
            ? 'no'
            : 'unknown'
          : accountListed;
    let principal: Match = excluded === undefined ? principalMatch(st.Principal) : excluded === 'yes' ? 'no' : excluded === 'no' ? 'yes' : 'unknown';
    // An Allow with NotPrincipal is not supported by AWS: it never proves access.
    if (excluded !== undefined && st.Effect !== 'Deny' && principal === 'yes') principal = 'unknown';
    if (isUnknown(st.Effect)) {
      // An effect not known statically may be either: it can neither grant nor be ruled out as a Deny.
      if (principal !== 'no' || isUnknown(st.Principal)) {
        raise('deny', 'unknown');
        raise('allow', 'unknown');
      }
      if (namesRoot(st.Principal) !== 'no') raise('delegates', 'unknown');
      continue;
    }
    if (st.Effect === 'Deny') {
      if (principal === 'yes') raise('deny', certain);
      else if (principal === 'unknown' || isUnknown(st.Principal)) raise('deny', 'unknown');
      continue;
    }
    if (st.Effect !== 'Allow') continue;
    if (principal !== 'no') raise('allow', principal === 'yes' ? certain : 'unknown');
    if (excluded !== undefined) continue;
    const delegation = namesRoot(st.Principal);
    if (delegation !== 'no') raise('delegates', delegation === 'yes' ? certain : 'unknown');
  }
  return verdict;
}

/** AWS managed policies that span services: their names say nothing about which. */
const BROAD_MANAGED = new Set(['AdministratorAccess', 'PowerUserAccess', 'ReadOnlyAccess', 'ViewOnlyAccess', 'SecurityAudit', 'SystemAdministrator', 'DatabaseAdministrator', 'DataScientist', 'NetworkAdministrator', 'SupportUser']);

/**
 * Whether an uncatalogued AWS managed policy attached in a root of unknown account may cover an action:
 * a broad one may cover anything, others the services their name names (AmazonDynamoDBReadOnlyAccess: dynamodb).
 */
function uncertainManagedCovers(arns: string[], action: string): boolean {
  const service = action.split(':')[0].toLowerCase();
  return arns.some((a) => {
    const name = managedPolicyName(a);
    if (name in MANAGED_POLICY_ACTIONS) return false;
    return BROAD_MANAGED.has(name.replace(/^job-function\//, '')) || name.toLowerCase().includes(service);
  });
}

const and = (a: Match, b: Match): Match => (a === 'no' || b === 'no' ? 'no' : a === 'yes' && b === 'yes' ? 'yes' : 'unknown');
const or = (a: Match, b: Match): Match => (a === 'yes' || b === 'yes' ? 'yes' : a === 'unknown' || b === 'unknown' ? 'unknown' : 'no');

/** Resources of the role's root that a literal name, URL or ARN names, when its account is this root's or not known. */
function namedInRoot(index: InfraIndex, t: Target, need: Identity, service: string): string[] {
  if (!need.name || /[*?]/.test(need.name)) return [];
  const accounts = index.accountsOf(t.root,t.role.instance);
  if (need.account && accounts.length && !accounts.includes(need.account)) return [];
  if (!need.secretArn) return index.instancesByName(t.root, SERVICE_TYPES[service] ?? [], need.name,need.account);
  // A secret ARN names the secret without its suffix in Terraform.
  const bare = need.name.replace(/-(\?{6}|\*|[A-Za-z0-9]{6})$/, '');
  return [...new Set([...index.instancesByName(t.root, SERVICE_TYPES[service] ?? [], need.name,need.account), ...index.instancesByName(t.root, SERVICE_TYPES[service] ?? [], bare,need.account)])];
}

function kmsDependency(
  fact: AccessFact,
  granted: string[],
  need: Identity,
  t: Target,
  index: InfraIndex,
  statements: RoleStatement[],
  base: LinkBase,
  roleLabel: string
): AppLink[] {
  const kmsActions = [...new Set(granted.flatMap((a) => KMS_NEEDS[a] ?? []))];
  if (!kmsActions.length) return [];
  // A literal URL, ARN or name has no Terraform address; it may still name a resource of this root.
  const addresses = need.addresses.length ? need.addresses : namedInRoot(index, t, need, fact.service);
  const keys = [...new Set(addresses.map((a) => customerKeyOf(index, t.root, a)))];
  if (addresses.length > 1 && keys.some(Boolean)) {
    // Several resources of this root carry the name, and at least one is encrypted with a customer key.
    return [link({ ...base, resource: need.label }, kmsActions, 'UNRESOLVED', `${need.label} names ${addresses.join(', ')}; which key protects it is not known`)];
  }
  if (keys.includes('ambiguous')) {
    return [link({ ...base, resource: need.label }, kmsActions, 'UNRESOLVED', `${need.label} is encrypted with a key made with count or for_each, and which instance is not known statically`)];
  }
  const key = keys.find(Boolean);
  if (!key) return [];
  const keyNeed: Identity = { service: 'kms', addresses: [key], label: key };
  const kmsBase: LinkBase = { ...base, resource: `${key}, the customer managed key of ${need.label}` };
  const grants = index.grants(t.role);
  const boundary = grants.boundary;
  // An explicit Deny in the role's policies, its permissions boundary or the key policy wins. Otherwise
  // the key policy grants the role directly, or delegates to IAM, where the identity policy (capped by
  // the boundary) decides.
  const results = new Map<string, Match | 'denied'>(
    kmsActions.map((a) => {
      const identity = evaluate(statements, a, keyNeed, t.root, index, 'kms');
      const capped = boundary ? (boundary.opaque ? undefined : evaluate(boundary.statements, a, keyNeed, t.root, index, 'kms')) : { result: 'yes' as Match, denied: false, mayDeny: false };
      const kp = keyPolicy(index, t.root, key, t.role, a);
      if (identity.denied || capped?.denied || kp.deny === 'yes') return [a, 'denied'];
      const bound: Match = capped ? capped.result : 'unknown';
      const viaIam = and(and(identity.result, bound), kp.delegates);
      // Whether a boundary limits a key-policy grant to the role depends on how the policy names it; stay undecided.
      const viaKey = boundary && bound !== 'yes' ? and(kp.allow, 'unknown') : kp.allow;
      const allowed = or(viaIam, viaKey);
      // A deny that may apply (in the key policy, the role's policies or its boundary) keeps a grant undecided.
      const mayDeny = kp.deny === 'unknown' || Boolean(identity.mayDeny) || Boolean(capped?.mayDeny);
      return [a, allowed === 'yes' && mayDeny ? 'unknown' : allowed];
    })
  );
  const cannotTell =
    grants.opaque.length > 0 ||
    grants.managedPolicies.some((a) => !(managedPolicyName(a) in MANAGED_POLICY_ACTIONS)) ||
    uncertainManagedCovers(grants.uncertainManaged, 'kms:Decrypt');
  const allowed = kmsActions.filter((a) => results.get(a) === 'yes');
  const undetermined = kmsActions.filter((a) => results.get(a) === 'unknown' || (results.get(a) === 'no' && cannotTell));
  const missing = kmsActions.filter((a) => results.get(a) === 'denied' || (results.get(a) === 'no' && !cannotTell));
  const out: AppLink[] = [];
  if (allowed.length) out.push(link(kmsBase, allowed, 'GRANTED', `${roleLabel} may use the key`));
  if (undetermined.length) out.push(link(kmsBase, undetermined, 'UNRESOLVED', `Cannot tell whether ${roleLabel} may use ${key} (conditional or unreadable grants)`));
  if (missing.length) {
    const holder = statements.find((st) => st.style === 'document') ?? statements.find((st) => st.source.file !== 'AWS');
    const l = link(
      kmsBase,
      missing,
      fact.possible ? 'UNRESOLVED' : 'NOT_GRANTED',
      `${need.label} is encrypted with ${key}, and ${roleLabel} may not use it, so ${granted.join(', ')} fails with AccessDenied.`
    );
    if (holder && !fact.possible) {
      l.suggestion = { target: holder.policy, file: holder.source.file, line: holder.source.line, code: statementCode(holder, missing, resourceExpr(keyNeed, missing, 'kms', holder.module)) };
    }
    out.push(l);
  }
  return out;
}
