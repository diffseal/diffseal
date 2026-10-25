import { isRedacted, isUnknown, reveal } from '../core/model.js';

export type IssueLevel = 'FAIL' | 'WARN' | 'UNKNOWN';

export interface PolicyIssue {
  level: IssueLevel;
  message: string;
}

export interface Statement {
  Sid?: unknown;
  Effect?: unknown;
  Action?: unknown;
  NotAction?: unknown;
  Resource?: unknown;
  NotResource?: unknown;
  Principal?: unknown;
  NotPrincipal?: unknown;
  Condition?: unknown;
}

export type ParsedPolicy =
  | { kind: 'ok'; statements: Statement[] }
  | { kind: 'unknown'; reason: string }
  | { kind: 'invalid'; reason: string };

/** Accepts a JSON string, an object, or an Unknown/Redacted marker. */
export function parsePolicy(value: unknown): ParsedPolicy {
  if (value === undefined || value === null || value === '') return { kind: 'unknown', reason: 'no policy document' };
  if (isUnknown(value)) return { kind: 'unknown', reason: value.reason };
  value = reveal(value);
  if (isRedacted(value)) return { kind: 'unknown', reason: 'policy is marked sensitive and its value is not available' };
  if (isUnknown(value)) return { kind: 'unknown', reason: value.reason };
  let doc: unknown = value;
  if (typeof value === 'string') {
    try {
      doc = JSON.parse(value);
    } catch {
      return { kind: 'invalid', reason: 'policy is not valid JSON' };
    }
  }
  if (!doc || typeof doc !== 'object') return { kind: 'invalid', reason: 'policy is not an object' };
  const raw = (doc as { Statement?: unknown }).Statement;
  if (isUnknown(raw)) return { kind: 'unknown', reason: raw.reason };
  const statements = (Array.isArray(raw) ? raw : raw ? [raw] : []).map((st) =>
    // A statement not known statically may allow or deny anything, for anyone.
    isUnknown(st) ? { Effect: st, Action: st, Resource: st, Principal: st } : st
  );
  return { kind: 'ok', statements: statements as Statement[] };
}

const list = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

/** Actions AWS only authorizes against `Resource: "*"`. Granting them on `*` is correct, not a finding. */
const STAR_ONLY_ACTIONS = new Set(
  [
    'ecr:GetAuthorizationToken',
    'sts:GetCallerIdentity',
    'xray:PutTraceSegments',
    'xray:PutTelemetryRecords',
    'xray:GetSamplingRules',
    'xray:GetSamplingTargets',
    'xray:GetSamplingStatisticSummaries',
    'cloudwatch:PutMetricData',
    'cloudwatch:GetMetricData',
    'cloudwatch:ListMetrics',
    'logs:DescribeLogGroups',
    'ec2:CreateNetworkInterface',
    'ec2:DescribeNetworkInterfaces',
    'ec2:DeleteNetworkInterface',
    'ec2:AssignPrivateIpAddresses',
    'ec2:UnassignPrivateIpAddresses',
    'ec2:DescribeInstances',
    'ec2:DescribeSubnets',
    'ec2:DescribeVpcs',
    'ec2:DescribeSecurityGroups',
    'ssm:DescribeParameters',
    'secretsmanager:ListSecrets',
    'secretsmanager:GetRandomPassword',
    'sns:ListTopics',
    'sqs:ListQueues',
    's3:ListAllMyBuckets',
    'kms:ListAliases',
    'kms:ListKeys',
    'iam:ListRoles',
    'iot:DescribeEndpoint',
    'route53:ListHostedZones',
    'tag:GetResources',
    'cognito-idp:ListUserPools',
    'states:ListStateMachines',
    'lambda:ListFunctions',
    'dynamodb:ListTables',
    'apigateway:GET',
    'bedrock:ListFoundationModels',
    'ssmmessages:CreateControlChannel',
    'ssmmessages:CreateDataChannel',
    'ssmmessages:OpenControlChannel',
    'ssmmessages:OpenDataChannel',
    'logs:CreateLogDelivery',
    'logs:GetLogDelivery',
    'logs:UpdateLogDelivery',
    'logs:DeleteLogDelivery',
    'logs:ListLogDeliveries',
    'logs:PutResourcePolicy',
    'logs:DescribeResourcePolicies',
  ].map((a) => a.toLowerCase())
);

/** Actions that let a principal grant itself more permissions. */
const ESCALATION_ACTIONS = new Set(
  [
    'iam:PassRole',
    'iam:CreatePolicyVersion',
    'iam:SetDefaultPolicyVersion',
    'iam:AttachRolePolicy',
    'iam:AttachUserPolicy',
    'iam:AttachGroupPolicy',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:PutGroupPolicy',
    'iam:CreateAccessKey',
    'iam:CreateLoginProfile',
    'iam:UpdateLoginProfile',
    'iam:UpdateAssumeRolePolicy',
    'iam:AddUserToGroup',
  ].map((a) => a.toLowerCase())
);

/** Services where a service-wide wildcard (`svc:*`) is admin-equivalent. */
const ADMIN_SERVICES = new Set(['iam', 'sts', 'organizations', 'kms']);

/** Analyze the Allow statements of an identity-based policy. */
export function analyzeIdentityPolicy(statements: Statement[]): PolicyIssue[] {
  const issues: PolicyIssue[] = [];
  for (const [i, st] of statements.entries()) {
    if (!mayAllow(st)) continue;
    // Labels come from content, not position, so inserting a statement does not make old issues look new.
    const label = typeof st.Sid === 'string' && st.Sid ? `Sid "${st.Sid}": ` : '';
    void i;

    if (st.NotAction !== undefined) {
      issues.push({ level: 'FAIL', message: `${label}Allow with NotAction [${list(st.NotAction).map(String).join(', ')}] grants every other action` });
      continue;
    }
    if (st.NotResource !== undefined) {
      issues.push({ level: 'WARN', message: `${label}Allow with NotResource grants every resource except those listed` });
    }

    const actions = list(st.Action);
    const resources = list(st.Resource);
    const knownActions = actions.filter((a): a is string => typeof a === 'string');
    if (knownActions.length < actions.length) {
      issues.push({ level: 'UNKNOWN', message: `${label}some actions are not known until apply` });
    }

    const resourceStar = resources.some((r) => r === '*');
    const unknownResources = resources.filter((r) => typeof r !== 'string' && resolveResourcePattern(r) === undefined).length;
    if (unknownResources) {
      issues.push({ level: 'UNKNOWN', message: `${label}${unknownResources} resource(s) not known until apply` });
    }

    for (const action of knownActions) {
      const a = action.toLowerCase();
      if (a === '*' || a === '*:*') {
        issues.push({ level: 'FAIL', message: `${label}Action "${action}" grants every AWS action (admin-equivalent)` });
        continue;
      }
      const [svc, op = ''] = a.split(':');
      if (op === '*') {
        const level: IssueLevel = ADMIN_SERVICES.has(svc) || resourceStar || resources.some(isServiceWideArn) ? 'FAIL' : 'WARN';
        issues.push({ level, message: `${label}Action "${action}" grants every ${svc} action` });
      }
      if (ESCALATION_ACTIONS.has(a)) {
        issues.push({
          level: resourceStar ? 'FAIL' : 'WARN',
          message: `${label}${action}${resourceStar ? ' on "*"' : ''} can be used to escalate privileges`,
        });
      }
    }

    if (resourceStar) {
      const needsScope = knownActions.filter((a) => !STAR_ONLY_ACTIONS.has(a.toLowerCase()) && !/^\*(:\*)?$/.test(a));
      if (needsScope.length) {
        issues.push({ level: 'FAIL', message: `${label}Resource "*" for ${needsScope.slice(0, 4).join(', ')}${needsScope.length > 4 ? ', ...' : ''}` });
      }
    }

    for (const r of resources) {
      const pattern = typeof r === 'string' ? r : resolveResourcePattern(r);
      if (pattern === undefined || pattern === '*' || pattern === SCOPED_TO_REFERENCE) continue;
      const verdict = classifyResourcePattern(pattern);
      if (verdict) issues.push({ level: verdict.level, message: `${label}${verdict.message}` });
    }
  }
  return dedupe(issues);
}

const SCOPED_TO_REFERENCE = '(attribute of a referenced resource)';

/**
 * A resource element that is only partly known (static analysis, or a template with a data source).
 * `aws_s3_bucket.b.arn` and `"${aws_s3_bucket.b.arn}/*"` are scoped to one referenced resource.
 * `arn:aws:secretsmanager:{?}:{?}:secret:provider/*` keeps its known text so its wildcard can be judged.
 */
function resolveResourcePattern(r: unknown): string | undefined {
  if (!isUnknown(r) || r.pattern === undefined) return undefined;
  // Anything that starts with a referenced resource's ARN stays inside that resource; a suffix only narrows it.
  if (r.pattern.startsWith('{?}') && (r.refs.length || /^\{\?\}(\/\*|:\*|\/index\/\*|\/stream\/\*|-\?{6})?$/.test(r.pattern))) return SCOPED_TO_REFERENCE;
  if (r.pattern.startsWith('arn:')) return r.pattern;
  return undefined;
}

function isServiceWideArn(r: unknown): boolean {
  if (typeof r !== 'string') return false;
  const id = arnResource(r);
  if (id === undefined) return false;
  // S3 ARNs have no resource-type prefix: `bucket/*` is objects of one bucket, `*` or `*/*` is every bucket.
  if (r.split(':')[2] === 's3') return id === '*' || id === '*/*';
  return /^(\*|[a-z-]+[:/]\*)$/i.test(id);
}

/** The resource part of an ARN (everything after the 5th colon), or undefined if not an ARN. */
function arnResource(arn: string): string | undefined {
  if (!arn.startsWith('arn:')) return undefined;
  const parts = arn.split(':');
  return parts.length >= 6 ? parts.slice(5).join(':') : undefined;
}

/**
 * Wildcards that only expand within one named resource are fine: S3 objects (`bucket/*`), the
 * Secrets Manager random suffix (`name-??????`), versions/streams after a concrete name (`name:*`),
 * DynamoDB indexes (`table/x/index/*`). A wildcard elsewhere spans resources and deserves review.
 */
export function classifyResourcePattern(display: string): { level: IssueLevel; message: string } | undefined {
  const arn = display.replaceAll('{?}', 'X');
  display = display.replaceAll('{?}', '…');
  if (!/[*?]/.test(arn)) return undefined;
  const id = arnResource(arn);
  if (id === undefined) return { level: 'WARN', message: `resource pattern "${display}" contains a wildcard` };
  if (isServiceWideArn(arn)) return { level: 'FAIL', message: `resource "${display}" matches every resource of the service` };

  const service = arn.split(':')[2];
  let rest = id;
  if (service === 's3') rest = rest.replace(/\/\*$/, '');
  if (service === 'secretsmanager') rest = rest.replace(/-\?{6}$/, '').replace(/-\*$/, '');
  if (service === 'dynamodb') rest = rest.replace(/\/(index|stream)\/\*$/, '');
  rest = rest.replace(/:\*$/, '');
  if (!/[*?]/.test(rest)) return undefined;
  return { level: 'WARN', message: `resource "${display}" uses a wildcard that spans multiple resources` };
}

const ADMIN_MANAGED_POLICIES: Record<string, IssueLevel> = {
  AdministratorAccess: 'FAIL',
  IAMFullAccess: 'FAIL',
  PowerUserAccess: 'FAIL',
  'AWSOrganizationsFullAccess': 'FAIL',
};

export function analyzeManagedPolicyArn(arn: unknown): PolicyIssue[] {
  if (isUnknown(arn)) return [{ level: 'UNKNOWN', message: 'policy ARN not known until apply' }];
  if (typeof arn !== 'string') return [];
  const m = arn.match(/^arn:aws[\w-]*:iam::aws:policy\/(?:.*\/)?([^/]+)$/);
  if (!m) return [];
  const name = m[1];
  if (ADMIN_MANAGED_POLICIES[name]) {
    return [{ level: ADMIN_MANAGED_POLICIES[name], message: `attaches AWS managed ${name}, which is admin-equivalent` }];
  }
  if (/FullAccess$/.test(name)) {
    return [{ level: 'WARN', message: `attaches AWS managed ${name}, which grants every action of the service` }];
  }
  return [];
}

const GITHUB_OIDC = 'token.actions.githubusercontent.com';

/** An Allow, or an effect that is not known and so may be an Allow. */
export const mayAllow = (st: Statement) => st.Effect === 'Allow' || isUnknown(st.Effect);

/**
 * Condition keys that narrow who or where a request comes from. `aws:SecureTransport` and the like
 * constrain the request, not the caller, so a statement limited only by them is still open to anyone.
 */
const NARROWING_KEY =
  /^(aws:(principalorgid|principalorgpaths|principalaccount|principalarn|sourceaccount|sourcearn|sourceorgid|sourceorgpaths|sourcevpce|sourcevpc|sourceip|vpcsourceip|calledvia)|kms:(calleraccount|viaservice))$/i;

/**
 * True when some allow-list condition on a key matching `keys` limits who matches. Each operator block
 * is ANDed with the others, so one narrowing block is enough; within a block the values are ORed, so
 * one value that admits everyone makes the block admit everyone.
 */
function narrows(condition: unknown, keys: RegExp): 'yes' | 'no' | 'unknown' {
  if (isUnknown(condition)) return 'unknown';
  if (!condition || typeof condition !== 'object') return 'no';
  let unknown = false;
  for (const [operator, block] of Object.entries(condition as Record<string, unknown>)) {
    if (NOT_ALLOW_LIST.test(operator)) continue;
    if (isUnknown(block)) {
      unknown = true;
      continue;
    }
    if (!block || typeof block !== 'object') continue;
    for (const [key, v] of Object.entries(block as Record<string, unknown>)) {
      const values = list(v);
      if (!keys.test(key) || !values.length) continue;
      if (values.every((x) => specific(operator, key, x))) return 'yes';
      // A value not known statically may be specific or may admit everyone.
      if (values.some(isUnknown) && values.every((x) => isUnknown(x) || specific(operator, key, x))) unknown = true;
    }
  }
  return unknown ? 'unknown' : 'no';
}

const NOT_ALLOW_LIST = /not|ifexists$|^forallvalues:|^null$/i;

/** Operators whose values may hold `*` and `?` wildcards. ArnEquals matches like ArnLike. */
const WILDCARD_OPERATOR = /(like|^(?:for(?:any|all)value:)?arnequals)$/i;

/** Whether one condition value admits only some callers. */
function specific(operator: string, key: string, value: unknown): boolean {
  // An exact-match value not known statically still matches one string; a pattern or CIDR could be anything.
  if (isUnknown(value)) return !WILDCARD_OPERATOR.test(operator) && !/sourceip$/i.test(key);
  if (typeof value !== 'string' || !value) return false;
  if (/sourceip$/i.test(key)) {
    // A prefix shorter than /8 (IPv4) or /16 (IPv6) is a large share of the internet.
    const m = value.match(/\/(\d+)$/);
    const bits = m ? Number(m[1]) : value.includes(':') ? 128 : 32;
    return bits >= (value.includes(':') ? 16 : 8);
  }
  // StringEquals "*" matches only the literal string; a Like pattern narrows only if it names an
  // account, organization or endpoint after its wildcards are removed.
  if (!WILDCARD_OPERATOR.test(operator)) return true;
  const fixed = value.replace(/[*?]+/g, ' ');
  return /\b\d{12}\b|o-[a-z0-9]{10,32}\b|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|vpce?-[0-9a-f]{8,17}\b/.test(fixed);
}

/** `Principal: "*"`, or `NotPrincipal`, which admits everyone except the principals it lists. */
const anyPrincipal = (st: Statement) => st.NotPrincipal !== undefined || principalValues(st.Principal).some((p) => p === '*');

/** True when a statement allows any AWS principal with no condition that narrows who can use it. */
export function openToAnyone(st: Statement): boolean {
  return mayAllow(st) && anyPrincipal(st) && narrows(st.Condition, NARROWING_KEY) === 'no';
}

/** True when a statement allows any AWS principal unless a condition not known statically narrows it. */
export function openUnlessUnknownCondition(st: Statement): boolean {
  return mayAllow(st) && anyPrincipal(st) && narrows(st.Condition, NARROWING_KEY) === 'unknown';
}

/** True when a statement may allow principals that are not known statically. */
export function principalUnknown(st: Statement): boolean {
  return mayAllow(st) && (principalValues(st.Principal).some(isUnknown) || isUnknown(st.NotPrincipal));
}

/** Analyze a role trust policy (assume_role_policy). */
export function analyzeTrustPolicy(statements: Statement[]): PolicyIssue[] {
  const issues: PolicyIssue[] = [];
  for (const [i, st] of statements.entries()) {
    if (!mayAllow(st)) continue;
    // Labels come from content, not position, so inserting a statement does not make old issues look new.
    const label = typeof st.Sid === 'string' && st.Sid ? `Sid "${st.Sid}": ` : '';
    void i;
    const principals = principalValues(st.Principal);
    const conditionKeys = conditionMap(st.Condition);

    if (principals.some(isUnknown) || isUnknown(st.NotPrincipal)) {
      issues.push({ level: 'UNKNOWN', message: `${label}who can assume this role is not known statically` });
    }
    if (anyPrincipal(st)) {
      const scoped = narrows(st.Condition, /^aws:(principalorgid|principalaccount|sourceaccount|sourcearn|principalarn)$/i);
      const who = st.NotPrincipal !== undefined ? 'any AWS principal except those in NotPrincipal' : 'any AWS principal';
      issues.push(
        scoped === 'unknown'
          ? { level: 'UNKNOWN', message: `${label}${who} can assume this role, limited by a condition not known statically` }
          : { level: scoped === 'yes' ? 'WARN' : 'FAIL', message: `${label}${who} can assume this role${scoped === 'yes' ? ' (limited by a condition)' : ''}` }
      );
    }

    if (principals.some((p) => typeof p === 'string' && p.includes(GITHUB_OIDC))) {
      const subValues = conditionKeys.get(`${GITHUB_OIDC}:sub`);
      if (!subValues) {
        issues.push({ level: 'FAIL', message: `${label}GitHub OIDC trust has no ${GITHUB_OIDC}:sub condition, so any GitHub repository can assume it` });
      } else {
        for (const v of subValues) {
          if (typeof v !== 'string') continue;
          if (v === '*' || /^repo:\*/.test(v)) {
            issues.push({ level: 'FAIL', message: `${label}GitHub OIDC sub "${v}" matches any repository` });
          } else if (/^repo:[^/]+\/\*/.test(v)) {
            issues.push({ level: 'WARN', message: `${label}GitHub OIDC sub "${v}" trusts every repository in the organization` });
          }
        }
      }
      if (!conditionKeys.get(`${GITHUB_OIDC}:aud`)) {
        issues.push({ level: 'WARN', message: `${label}GitHub OIDC trust does not pin aud to sts.amazonaws.com` });
      }
    }
  }
  return dedupe(issues);
}

export function principalValues(p: unknown): unknown[] {
  if (p === '*') return ['*'];
  if (isUnknown(p)) return [p];
  if (!p || typeof p !== 'object') return [];
  return Object.values(p as Record<string, unknown>).flatMap((v) => (isUnknown(v) ? [v] : list(v)));
}

/**
 * Condition keys that narrow who matches, lower-cased key -> values. Only allow-list operators count:
 * a negated operator (`StringNotEquals`) excludes some callers and admits everyone else, `...IfExists`
 * and `ForAllValues:` pass when the key is absent, and `Null` only tests presence.
 */
function conditionMap(c: unknown): Map<string, unknown[]> {
  const out = new Map<string, unknown[]>();
  if (!c || typeof c !== 'object' || isUnknown(c)) return out;
  for (const [operator, block] of Object.entries(c as Record<string, unknown>)) {
    if (/not|ifexists$|^forallvalues:|^null$/i.test(operator)) continue;
    if (!block || typeof block !== 'object' || isUnknown(block)) continue;
    for (const [k, v] of Object.entries(block as Record<string, unknown>)) {
      out.set(k.toLowerCase(), [...(out.get(k.toLowerCase()) ?? []), ...list(v)]);
    }
  }
  return out;
}

function dedupe(issues: PolicyIssue[]): PolicyIssue[] {
  const seen = new Set<string>();
  return issues.filter((i) => (seen.has(i.message) ? false : (seen.add(i.message), true)));
}

export function worstLevel(issues: PolicyIssue[]): IssueLevel | undefined {
  if (issues.some((i) => i.level === 'FAIL')) return 'FAIL';
  if (issues.some((i) => i.level === 'WARN')) return 'WARN';
  if (issues.some((i) => i.level === 'UNKNOWN')) return 'UNKNOWN';
  return undefined;
}
