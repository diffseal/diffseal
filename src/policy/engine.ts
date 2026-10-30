import {
  configAddress,
  instancesCompatible,
  isUnknown,
  reveal,
  scrub,
  sensitiveLeaves,
  type Attrs,
  type Finding,
  type FindingStatus,
  type PolicyConfig,
  type ResourceChange,
} from '../core/model.js';
import { RULES, resolvePolicyValue } from './rules.js';
import { stableKey } from '../hcl/eval.js';
import { grantsWithin } from './grants.js';
import { frameworksFor } from '../compliance/crosswalk.js';
import { typed } from './values.js';

export interface RuleResult {
  status: FindingStatus;
  detail: string;
  remediation?: string;
  /** Individual problems behind the status, so an update can be judged on what it introduced. */
  issues?: Array<{ level: 'FAIL' | 'WARN' | 'UNKNOWN'; message: string }>;
}

export interface Rule {
  id: string;
  title: string;
  controls: string[];
  types: string[];
  /** Change rules also judge deletes and are never compared against a prior configuration result. */
  scope?: 'change';
  /** Judge configured arguments, excluding provider defaults and computed plan attributes. */
  configurationOnly?: boolean;
  evaluate(values: Attrs, res: ResourceChange, ctx: RuleContext): RuleResult | undefined;
}

export const DEFAULT_POLICY: Required<PolicyConfig> = {
  requireCustomerManagedKeys: false,
  minBackupRetentionDays: 7,
  minLogRetentionDays: 0,
  blockOn: ['CRITICAL'],
  exceptions: [],
};

export class RuleContext {
  readonly byAddress = new Map<string, ResourceChange>();
  private readonly byConfigAddress = new Map<string, ResourceChange[]>();

  /**
   * @param side `before` reads every resource as it was before the change, so a rule judged on a
   *   resource's prior values also sees its helpers' prior values.
   */
  constructor(readonly all: ResourceChange[], readonly policy: Required<PolicyConfig>, readonly side: 'after' | 'before' = 'after') {
    for (const r of all) {
      this.byAddress.set(r.address, r);
      const key = configAddress(r.address);
      this.byConfigAddress.set(key, [...(this.byConfigAddress.get(key) ?? []), r]);
    }
  }

  /** Whether a resource exists on this side of the change. */
  private exists(r: ResourceChange): boolean {
    return this.side === 'after' ? r.action !== 'delete' : r.before !== null && r.action !== 'create' && r.action !== 'import';
  }

  /** Current values of a resource (after for live resources, before for ones being deleted), sensitive ones revealed. */
  values(r: ResourceChange): Attrs {
    if (this.side === 'before') return typed(reveal(r.before ?? {}) as Attrs, r.type);
    return typed(reveal((r.action === 'delete' ? r.before : r.after) ?? {}) as Attrs, r.type);
  }

  /** Only configured expressions count as encryption evidence; planned defaults/computed fields do not. */
  configuredValues(r: ResourceChange): Attrs {
    if (this.side === 'before' && r.configuredBefore) return typed(reveal(r.configuredBefore) as Attrs, r.type);
    if (this.side === 'after' && r.configuredAfter) return typed(reveal(r.configuredAfter) as Attrs, r.type);
    const values = this.values(r);
    if (!r.configuredPaths) return values;
    const paths = new Set(r.configuredPaths);
    const select = (value: unknown, path: string): unknown => {
      if (paths.has(path)) return value;
      if (path && !r.configuredPaths!.some((p) => p.startsWith(`${path}.`))) return undefined;
      if (Array.isArray(value)) return value.map((v, i) => select(v, path ? `${path}.${i}` : String(i)));
      if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
        return Object.fromEntries(Object.entries(value).flatMap(([key, v]) => {
          const selected = select(v, path ? `${path}.${key}` : key);
          return selected === undefined ? [] : [[key, selected]];
        }));
      }
      return value;
    };
    return select(values, '') as Attrs;
  }

  /** Resolve a rule's owner with the same instance-aware association used by listener evaluation. */
  listenerOwners(rule: ResourceChange): ResourceChange[] {
    if (rule.action === 'delete' && this.side === 'after') return new RuleContext(this.all, this.policy, 'before').listenerOwners(rule);
    return this.all.filter((r) => r.mode === 'managed' && r.type === 'aws_lb_listener' && this.exists(r)
      && this.referrers(r, 'aws_lb_listener_rule', 'listener_arn', ['arn']).includes(rule));
  }

  /** Resources by config address (instance keys stripped). */
  lookup(configAddr: string): ResourceChange[] {
    return this.byConfigAddress.get(configAddr) ?? [];
  }

  /**
   * Resources of `type` that point at `target` through `attr`, by config reference or, failing that,
   * by matching a known attribute value (e.g. bucket name). Deleted helpers are ignored.
   */
  referrers(target: ResourceChange, type: string, attr: string, targetValueAttrs: string[] = ['id', 'arn', 'bucket', 'name']): ResourceChange[] {
    const targetCfg = configAddress(target.address);
    const targetValues = new Set(
      targetValueAttrs.map((a) => this.values(target)[a]).filter((v): v is string => typeof v === 'string' && v !== '')
    );
    return this.all.filter((r) => {
      if (r.type !== type || !this.exists(r)) return false;
      const v = this.values(r)[attr];
      if (r.references[attr]?.includes(targetCfg)) {
        // The config reference names the resource block; the value says which instance.
        if (typeof v === 'string' && v !== '' && targetValues.size) return targetValues.has(v);
        const exact = isUnknown(v) ? v.refs.filter((ref) => configAddress(ref) === targetCfg && ref !== targetCfg) : [];
        if (exact.length) return exact.some((ref) => ref === target.address || ref.startsWith(`${target.address}.`));
        return instancesCompatible(r.address, target.address);
      }
      return typeof v === 'string' && targetValues.has(v);
    });
  }

  /** True when `attr` of `r` references a resource of one of `types`. */
  referencesType(r: ResourceChange, attr: string, types: string[]): boolean {
    return (r.references[attr] ?? []).some((a) => types.some((t) => a.split('.').includes(t)));
  }
}

function instanceKey(address: string): string | undefined {
  const m = address.match(/(\[[^\]]*\])$/);
  return m?.[1];
}

const EVALUATED_ACTIONS = new Set(['create', 'update', 'replace', 'import']);
const CHANGED_ACTIONS = new Set(['create', 'update', 'replace', 'import', 'delete']);

/** Resources configured through separate helper resources: a change to a helper changes what the owner's rules judge. */
const HELPERS: Record<string, { types: string[]; attr: string; targetAttrs?: string[] }> = {
  aws_s3_bucket: { attr: 'bucket', types: [
    'aws_s3_bucket_versioning',
    'aws_s3_bucket_server_side_encryption_configuration',
    'aws_s3_bucket_public_access_block',
    'aws_s3_bucket_lifecycle_configuration',
  ] },
  aws_lb_listener: { attr: 'listener_arn', targetAttrs: ['arn'], types: ['aws_lb_listener_rule'] },
};

export function evaluatePolicies(all: ResourceChange[], policy: PolicyConfig = {}): Finding[] {
  const ctx = new RuleContext(all, { ...DEFAULT_POLICY, ...policy });
  const ctxBefore = new RuleContext(all, { ...DEFAULT_POLICY, ...policy }, 'before');
  // Resources this change creates, replaces or deletes: a reference to one names a new principal.
  const recreated = all.filter((c) => c.action === 'replace' || c.action === 'create' || c.action === 'delete').map((c) => c.address);
  // An unchanged owner whose helper changed (versioning suspended) is judged too, against its helpers'
  // prior values, so only what the helper change introduced counts as new.
  const helperChanged = (res: ResourceChange) => {
    const helper = HELPERS[res.type];
    return helper?.types.some((type) =>
      [...ctx.referrers(res, type, helper.attr, helper.targetAttrs), ...ctxBefore.referrers(res, type, helper.attr, helper.targetAttrs)]
        .some((h) => CHANGED_ACTIONS.has(h.action))
    ) ?? false;
  };
  const findings: Finding[] = [];
  const byType = new Map<string, Rule[]>();
  for (const rule of RULES) for (const t of rule.types) byType.set(t, [...(byType.get(t) ?? []), rule]);

  // Rules judge sensitive values; nothing they print may contain one.
  const hidden = all.flatMap((r) => [...sensitiveLeaves(r.before), ...sensitiveLeaves(r.after), ...sensitiveLeaves(r.configuredAfter)]);
  const clean = (text: string) => scrub(text, hidden);

  for (const res of all) {
    if (res.mode !== 'managed' || (!res.after && res.action !== 'delete')) continue;
    const viaHelper = res.action === 'no-op' && helperChanged(res);
    if (!EVALUATED_ACTIONS.has(res.action) && !viaHelper && res.action !== 'delete') continue;
    const after = typed(reveal(res.after ?? {}) as Attrs, res.type);
    const before = res.before && typed(reveal(res.before) as Attrs, res.type);
    for (const rule of byType.get(res.type) ?? []) {
      if (res.action === 'delete' && rule.scope !== 'change') continue;
      const result = rule.evaluate(rule.configurationOnly ? ctx.configuredValues(res) : after, res, ctx);
      if (!result) continue;
      let preExisting: boolean | undefined;
      let status = result.status;
      let detail = result.detail;
      if (rule.scope !== 'change' && (res.action === 'update' || res.action === 'replace' || viaHelper) && res.before && result.status !== 'PASS') {
        const prior = rule.evaluate(rule.configurationOnly ? ctxBefore.configuredValues(res) : before!, res, ctxBefore);
        if (result.issues && prior?.issues) {
          const priorMessages = new Set(prior.issues.map((i) => i.message));
          const introduced = result.issues.filter((i) => !priorMessages.has(i.message));
          const kept = result.issues.filter((i) => i.level !== 'UNKNOWN' && priorMessages.has(i.message)).length;
          // A policy update that grants nothing new introduces nothing, whatever its statement ids say.
          if (!introduced.length || (rule.id === 'iam.least-privilege' && res.type !== 'aws_iam_role' && sameOwner(res.type, before!, after, recreated, res.references) && grantsWithin(resolvePolicyValue(before!.policy, res, 'policy', ctxBefore), resolvePolicyValue(after.policy, res, 'policy', ctx)))) {
            preExisting = true;
          } else if (kept) {
            status = (['FAIL', 'WARN', 'UNKNOWN'] as const).find((l) => introduced.some((i) => i.level === l))!;
            detail = `${capitalize(introduced.filter((i) => i.level === status).map((i) => i.message).join('; '))} (${kept} ${kept === 1 ? 'issue' : 'issues'} already present before this change)`;
          }
        } else {
          preExisting = prior !== undefined && prior.status === result.status && prior.detail === result.detail;
        }
      }
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        status,
        resource: res.address,
        controls: [...rule.controls, ...(frameworksFor(rule.id).frameworks.soc2_tsc ?? []).map((r) => `SOC2:${r.ref}`)],
        detail: clean(detail),
        remediation: result.remediation && clean(result.remediation),
        ...(preExisting ? { preExisting } : {}),
      });
    }
  }
  return findings;
}

/** An inline policy is narrower only for the same role, user or group; a managed policy has no owner here. */
function sameOwner(type: string, before: Attrs, after: Attrs, recreated: string[], references: Record<string, string[]>): boolean {
  const owner = { aws_iam_role_policy: 'role', aws_iam_user_policy: 'user', aws_iam_group_policy: 'group' }[type];
  if (!owner) return true;
  // An owner known only by reference (aws_iam_role.app.id) is the same when it names the same reference.
  const was = before[owner];
  const now = after[owner];
  if (was === undefined || was === null || stableKey(was) !== stableKey(now)) return false;
  const refs = [...(isUnknown(now) ? now.refs : []), ...(references[owner] ?? [])];
  return !refs.some((r) => recreated.some((a) => a === r || a.startsWith(r + '[') || a.startsWith(r + '.')));
}

export const capitalize = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);
