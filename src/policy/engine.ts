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
import { RULES } from './rules.js';
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
  evaluate(values: Attrs, res: ResourceChange, ctx: RuleContext): RuleResult | undefined;
}

export const DEFAULT_POLICY: Required<PolicyConfig> = {
  requireCustomerManagedKeys: false,
  minBackupRetentionDays: 7,
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
const HELPERS: Record<string, string[]> = {
  aws_s3_bucket: [
    'aws_s3_bucket_versioning',
    'aws_s3_bucket_server_side_encryption_configuration',
    'aws_s3_bucket_public_access_block',
    'aws_s3_bucket_lifecycle_configuration',
  ],
};

export function evaluatePolicies(all: ResourceChange[], policy: PolicyConfig = {}): Finding[] {
  const ctx = new RuleContext(all, { ...DEFAULT_POLICY, ...policy });
  const ctxBefore = new RuleContext(all, { ...DEFAULT_POLICY, ...policy }, 'before');
  // An unchanged owner whose helper changed (versioning suspended) is judged too, against its helpers'
  // prior values, so only what the helper change introduced counts as new.
  const helperChanged = (res: ResourceChange) =>
    (HELPERS[res.type] ?? []).some((type) =>
      [...ctx.referrers(res, type, 'bucket'), ...ctxBefore.referrers(res, type, 'bucket')].some((h) => CHANGED_ACTIONS.has(h.action))
    );
  const findings: Finding[] = [];
  const byType = new Map<string, Rule[]>();
  for (const rule of RULES) for (const t of rule.types) byType.set(t, [...(byType.get(t) ?? []), rule]);

  // Rules judge sensitive values; nothing they print may contain one.
  const hidden = all.flatMap((r) => [...sensitiveLeaves(r.before), ...sensitiveLeaves(r.after)]);
  const clean = (text: string) => scrub(text, hidden);

  for (const res of all) {
    if (res.mode !== 'managed' || !res.after) continue;
    const viaHelper = res.action === 'no-op' && helperChanged(res);
    if (!EVALUATED_ACTIONS.has(res.action) && !viaHelper) continue;
    const after = typed(reveal(res.after) as Attrs, res.type);
    const before = res.before && typed(reveal(res.before) as Attrs, res.type);
    for (const rule of byType.get(res.type) ?? []) {
      const result = rule.evaluate(after, res, ctx);
      if (!result) continue;
      let preExisting: boolean | undefined;
      let status = result.status;
      let detail = result.detail;
      if ((res.action === 'update' || res.action === 'replace' || viaHelper) && res.before && result.status !== 'PASS') {
        const prior = rule.evaluate(before!, res, ctxBefore);
        if (result.issues && prior?.issues) {
          const before = new Set(prior.issues.map((i) => i.message));
          const introduced = result.issues.filter((i) => !before.has(i.message));
          const kept = result.issues.filter((i) => i.level !== 'UNKNOWN' && before.has(i.message)).length;
          if (!introduced.length) {
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
        controls: rule.controls,
        detail: clean(detail),
        remediation: result.remediation && clean(result.remediation),
        ...(preExisting ? { preExisting } : {}),
      });
    }
  }
  return findings;
}

export const capitalize = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);
