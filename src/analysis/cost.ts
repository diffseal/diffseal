import { isUnknown, reveal, type Attrs, type CostItem, type CostSummary, type ResourceChange } from '../core/model.js';
import { typed } from '../policy/values.js';

/*
 * Diffseal does not try to be Infracost. It reports fixed monthly charges that appear or disappear,
 * changes to pricing dimensions (instance size, memory), and labels everything else usage-based.
 * Prices are approximate us-east-1 on-demand list prices; other regions differ by a few percent.
 */
const HOURS = 730;

const FIXED: Record<string, (v: Attrs) => { usd: number; note: string } | undefined> = {
  aws_nat_gateway: (v) => (v.connectivity_type === 'private' ? { usd: 0.045 * HOURS, note: 'private NAT gateway $0.045/h + $0.045/GB processed' } : { usd: 0.045 * HOURS, note: '$0.045/h + $0.045/GB processed' }),
  aws_kms_key: () => ({ usd: 1, note: '$1/month per key + $0.03 per 10k requests' }),
  aws_kms_replica_key: () => ({ usd: 1, note: '$1/month per key' }),
  aws_lb: (v) => ({ usd: 0.0225 * HOURS, note: `${v.load_balancer_type === 'network' ? 'NLB' : 'ALB'} $0.0225/h + capacity units` }),
  aws_alb: () => ({ usd: 0.0225 * HOURS, note: 'ALB $0.0225/h + capacity units' }),
  aws_eip: () => ({ usd: 0.005 * HOURS, note: 'public IPv4 address $0.005/h' }),
  aws_vpc_endpoint: (v) => {
    if (v.vpc_endpoint_type !== 'Interface') return undefined;
    const azs = Array.isArray(v.subnet_ids) ? Math.max(v.subnet_ids.length, 1) : 1;
    return { usd: 0.01 * HOURS * azs, note: `interface endpoint $0.01/h x ${azs} AZ + $0.01/GB` };
  },
  aws_secretsmanager_secret: () => ({ usd: 0.4, note: '$0.40/month per secret + $0.05 per 10k API calls' }),
  aws_route53_zone: () => ({ usd: 0.5, note: '$0.50/month per hosted zone' }),
  aws_cloudwatch_metric_alarm: () => ({ usd: 0.1, note: '$0.10/month per standard alarm' }),
  aws_db_instance: (v) => rdsMonthly(v),
  aws_rds_cluster_instance: (v) => rdsMonthly(v),
};

const USAGE_ONLY = new Set([
  'aws_sqs_queue',
  'aws_sns_topic',
  'aws_s3_bucket',
  'aws_lambda_function',
  'aws_cloudwatch_event_rule',
  'aws_cloudwatch_log_group',
  'aws_sfn_state_machine',
  'aws_api_gateway_rest_api',
  'aws_apigatewayv2_api',
]);

/** Approximate us-east-1 on-demand $/h for common RDS classes (single-AZ, PostgreSQL/MySQL). */
const RDS_HOURLY: Record<string, number> = {
  'db.t4g.micro': 0.016,
  'db.t4g.small': 0.032,
  'db.t4g.medium': 0.065,
  'db.t4g.large': 0.129,
  'db.t4g.xlarge': 0.258,
  'db.t3.micro': 0.017,
  'db.t3.small': 0.034,
  'db.t3.medium': 0.068,
  'db.t3.large': 0.136,
  'db.m6g.large': 0.152,
  'db.m6g.xlarge': 0.304,
  'db.m6g.2xlarge': 0.608,
  'db.m7g.large': 0.168,
  'db.r6g.large': 0.215,
  'db.r6g.xlarge': 0.43,
  'db.r6g.2xlarge': 0.86,
  'db.r6g.4xlarge': 1.72,
  'db.r7g.large': 0.239,
  'db.r7g.xlarge': 0.478,
};

function rdsMonthly(v: Attrs): { usd: number; note: string } | undefined {
  const cls = v.instance_class;
  if (typeof cls !== 'string' || !(cls in RDS_HOURLY)) return undefined;
  const multi = v.multi_az === true ? 2 : 1;
  return { usd: RDS_HOURLY[cls] * HOURS * multi, note: `${cls}${multi === 2 ? ' Multi-AZ' : ''} compute, storage extra` };
}

const round = (n: number) => Math.round(n * 100) / 100;

export function estimateCost(changes: ResourceChange[]): CostSummary {
  const items: CostItem[] = [];
  // Prices are decided on values as Terraform converts them (multi_az = "true" is true).
  const values = (a: Attrs | null, type: string) => a && (typed(reveal(a), type) as Attrs);
  for (const raw of changes) {
    const c = { ...raw, before: values(raw.before, raw.type), after: values(raw.after, raw.type) };
    if (c.mode !== 'managed') continue;
    const price = c.type in FIXED ? FIXED[c.type] : undefined;
    if (c.action === 'create' || c.action === 'delete') {
      const values = (c.action === 'create' ? c.after : c.before) ?? {};
      const p = price?.(values);
      if (p) {
        const sign = c.action === 'create' ? 1 : -1;
        items.push({ resource: c.address, type: c.type, kind: 'fixed', monthlyDeltaUsd: round(sign * p.usd), note: p.note });
      } else if (USAGE_ONLY.has(c.type) && c.action === 'create') {
        items.push({ resource: c.address, type: c.type, kind: 'usage', note: 'No fixed charge; billed by requests, storage or duration' });
      } else if (price && c.action === 'create') {
        items.push({ resource: c.address, type: c.type, kind: 'fixed', note: 'Fixed charge, size not known statically' });
      }
      continue;
    }
    if ((c.action === 'update' || c.action === 'replace') && c.before && c.after) {
      if (price) {
        const before = price(c.before);
        const after = price(c.after);
        if (before && after && round(after.usd - before.usd) !== 0) {
          items.push({ resource: c.address, type: c.type, kind: 'scaling', monthlyDeltaUsd: round(after.usd - before.usd), note: `${before.note} -> ${after.note}` });
        }
      }
      if (c.type === 'aws_lambda_function') {
        const m0 = c.before.memory_size;
        const m1 = c.after.memory_size;
        if (typeof m0 === 'number' && typeof m1 === 'number' && m0 !== m1) {
          const factor = m1 / m0;
          const shown = Number.isInteger(factor) ? `${factor}x` : `${factor.toFixed(2)}x`;
          items.push({
            resource: c.address,
            type: c.type,
            kind: 'scaling',
            note: `memory_size ${m0} -> ${m1} MB: compute cost per invocation-second ${shown} (shorter runtimes from the extra CPU offset part of it)`,
          });
        } else if (isUnknown(m1)) {
          items.push({ resource: c.address, type: c.type, kind: 'scaling', note: 'memory_size not known statically' });
        }
      }
    }
  }
  const fixed = items.reduce((s, i) => s + (i.kind !== 'usage' && i.monthlyDeltaUsd ? i.monthlyDeltaUsd : 0), 0);
  return {
    items,
    fixedMonthlyDeltaUsd: round(fixed),
    basis: 'Approximate us-east-1 on-demand list prices. Usage-based charges are listed, not estimated.',
  };
}
