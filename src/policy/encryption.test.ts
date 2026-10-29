import { expect, test } from 'bun:test';
import { analyze } from '../analysis/analyze.js';
import { Redacted, Unknown, type Attrs, type FindingStatus } from '../core/model.js';
import { readPlan } from '../plan/readPlan.js';
import { cfg, plan, rc } from '../testing/planFixtures.js';
import { evaluatePolicies } from './engine.js';
import { MemorySource } from '../terraform/source.js';
import { evaluateRoot } from '../terraform/expand.js';
import { compareEvaluations } from '../terraform/compare.js';
import { renderMarkdown } from '../report/markdown.js';
import { changeRecord } from '../evidence/changeRecord.js';

function check(rule: string, type: string, criterion: string, cases: Array<[string, Attrs, FindingStatus]>) {
  const address = (name: string) => `module.service["prod"].${type}.example[${JSON.stringify(name)}]`;
  const findings = evaluatePolicies(readPlan(plan(cases.map(([name, attrs]) => rc(address(name), type, ['create'], attrs)))))
    .filter((f) => f.ruleId === rule);
  expect(findings.map((f) => [f.resource, f.status, f.controls])).toEqual(cases.map(([name, _attrs, status]) => [
    address(name), status, ['ISO27001:A.8.24', `SOC2:${criterion}`],
  ]));
}

test('EBS default encryption warns only when disabled and respects the provider default', () => {
  check('ebs.default-encryption', 'aws_ebs_encryption_by_default', 'CC6.1', [
    ['off', { enabled: false }, 'WARN'],
    ['on', { enabled: 'true' }, 'PASS'],
    ['default', {}, 'PASS'],
    ['null', { enabled: null }, 'PASS'],
    ['unknown', { enabled: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { enabled: new Redacted() }, 'UNKNOWN'],
    ['invalid', { enabled: 'unrecognized' }, 'UNKNOWN'],
  ]);
});

test('EBS volumes warn only about explicitly disabled encryption and leave omitted encryption UNKNOWN', () => {
  check('ebs.encryption', 'aws_ebs_volume', 'CC6.1', [
    ['off', { encrypted: 'false' }, 'WARN'],
    ['on', { encrypted: true }, 'PASS'],
    ['unset', {}, 'UNKNOWN'],
    ['null', { encrypted: null }, 'UNKNOWN'],
    ['snapshot', { snapshot_id: 'snap-example' }, 'UNKNOWN'],
    ['unknown', { encrypted: new Unknown('computed') }, 'UNKNOWN'],
    ['redacted', { encrypted: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('EBS volumes with omitted encryption use a declared enabled regional default', () => {
  for (const [attrs, action, status] of [
    [{ enabled: true }, 'no-op', 'PASS'],
    [{}, 'create', 'PASS'],
    [{ enabled: false }, 'create', 'UNKNOWN'],
    [{ enabled: new Unknown('variable') }, 'create', 'UNKNOWN'],
    [{ enabled: true }, 'delete', 'UNKNOWN'],
    [{ enabled: true, region: 'us-west-2' }, 'create', 'UNKNOWN'],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_ebs_volume.example', 'aws_ebs_volume', ['create'], {}),
      rc('aws_ebs_encryption_by_default.example', 'aws_ebs_encryption_by_default', [action], action === 'delete' ? null : attrs, { before: attrs }),
    ]))).filter((f) => f.ruleId === 'ebs.encryption');
    expect(findings.map((f) => f.status)).toEqual([status]);
  }
});

test('EBS encryption defaults do not cross provider configurations or explicit regions', () => {
  const source = new MemorySource({ 'main.tf': `
    provider "aws" { alias = "encrypted" }
    provider "aws" { alias = "other" }
    resource "aws_ebs_encryption_by_default" "regional" {
      provider = aws.encrypted
      enabled = true
    }
    resource "aws_ebs_volume" "same" { provider = aws.encrypted }
    resource "aws_ebs_volume" "other" { provider = aws.other }
  ` });
  expect(evaluatePolicies(compareEvaluations(undefined, evaluateRoot(source, '.')))
    .filter((f) => f.ruleId === 'ebs.encryption').map((f) => [f.resource, f.status])).toEqual([
      ['aws_ebs_volume.same', 'PASS'],
      ['aws_ebs_volume.other', 'UNKNOWN'],
    ]);
  const changes = [
    rc('aws_ebs_encryption_by_default.regional', 'aws_ebs_encryption_by_default', ['create'], { enabled: true }),
    rc('aws_ebs_volume.same', 'aws_ebs_volume', ['create'], {}),
    rc('aws_ebs_volume.other', 'aws_ebs_volume', ['create'], {}),
    rc('aws_ebs_volume.region', 'aws_ebs_volume', ['create'], { region: 'us-west-2' }),
  ];
  const config = ['aws_ebs_encryption_by_default.regional', 'aws_ebs_volume.same', 'aws_ebs_volume.other', 'aws_ebs_volume.region']
    .map((address) => ({ address, provider_config_key: address === 'aws_ebs_volume.other' ? 'aws.other' : 'aws.encrypted' }));
  expect(evaluatePolicies(readPlan(plan(changes, config))).filter((f) => f.ruleId === 'ebs.encryption')
    .map((f) => [f.resource, f.status])).toEqual([
      ['aws_ebs_volume.same', 'PASS'],
      ['aws_ebs_volume.other', 'UNKNOWN'],
      ['aws_ebs_volume.region', 'UNKNOWN'],
    ]);
});

test('EFS encryption distinguishes configured, absent and unresolved values', () => {
  check('efs.encryption', 'aws_efs_file_system', 'CC6.1', [
    ['off', { encrypted: false }, 'WARN'],
    ['on', { encrypted: 'true' }, 'PASS'],
    ['unset', {}, 'WARN'],
    ['null', { encrypted: null }, 'WARN'],
    ['unknown', { encrypted: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { encrypted: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('ElastiCache encryption at rest respects Redis and Valkey defaults without guessing unknown engines', () => {
  check('elasticache.encryption', 'aws_elasticache_replication_group', 'CC6.1', [
    ['off', { at_rest_encryption_enabled: 'false', engine: 'valkey' }, 'WARN'],
    ['on', { at_rest_encryption_enabled: 'true' }, 'PASS'],
    ['unset', {}, 'WARN'],
    ['redis', { engine: 'redis' }, 'WARN'],
    ['valkey', { engine: 'valkey' }, 'PASS'],
    ['unknown_engine', { engine: new Unknown('variable') }, 'UNKNOWN'],
    ['unknown', { at_rest_encryption_enabled: new Unknown('computed'), engine: 'valkey' }, 'UNKNOWN'],
    ['redacted', { at_rest_encryption_enabled: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('OpenSearch and Elasticsearch encryption at rest handle block lists, objects and unresolved blocks', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.encryption', type, 'CC6.1', [
      ['off', { encrypt_at_rest: [{ enabled: false }] }, 'WARN'],
      ['on', { encrypt_at_rest: [{ enabled: 'true' }] }, 'PASS'],
      ['object', { encrypt_at_rest: { enabled: true } }, 'PASS'],
      ['unset', {}, 'WARN'],
      ['empty', { encrypt_at_rest: [] }, 'WARN'],
      ['unknown', { encrypt_at_rest: [{ enabled: new Unknown('computed') }] }, 'UNKNOWN'],
      ['block', { encrypt_at_rest: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { encrypt_at_rest: [new Unknown('dynamic block collection')] }, 'UNKNOWN'],
      ['redacted', { encrypt_at_rest: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('ElastiCache transit encryption flags false and unset and leaves unresolved values unknown', () => {
  check('elasticache.transit-encryption', 'aws_elasticache_replication_group', 'CC6.7', [
    ['off', { transit_encryption_enabled: 'false' }, 'WARN'],
    ['on', { transit_encryption_enabled: 'true' }, 'PASS'],
    ['unset', {}, 'WARN'],
    ['null', { transit_encryption_enabled: null }, 'WARN'],
    ['unknown', { transit_encryption_enabled: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { transit_encryption_enabled: new Redacted() }, 'UNKNOWN'],
  ]);
});

test('ElastiCache global secondaries leave inherited encryption UNKNOWN without forbidden remediation', () => {
  const cases: Attrs[] = [
    { global_replication_group_id: 'global-cache' },
    { global_replication_group_id: 'global-cache', engine: 'valkey' },
    { global_replication_group_id: 'global-cache', at_rest_encryption_enabled: false, transit_encryption_enabled: false },
    { global_replication_group_id: new Unknown('primary global group') },
    { global_replication_group_id: new Redacted() },
  ];
  const findings = evaluatePolicies(readPlan(plan(cases.map((attrs, i) =>
    rc(`aws_elasticache_replication_group.secondary[${i}]`, 'aws_elasticache_replication_group', ['create'], attrs)
  )))).filter((f) => f.ruleId === 'elasticache.encryption' || f.ruleId === 'elasticache.transit-encryption');
  expect(findings.map((f) => [f.status, f.remediation])).toEqual(Array.from({ length: 10 }, () => ['UNKNOWN', undefined]));
});

test('ElastiCache Memcached transit encryption checks supported versions in a VPC and preserves uncertainty', () => {
  const supported = { engine: 'memcached', engine_version: '1.6.12', subnet_group_name: 'cache-vpc' };
  check('elasticache.transit-encryption', 'aws_elasticache_cluster', 'CC6.7', [
    ['off', { ...supported, transit_encryption_enabled: false }, 'WARN'],
    ['on', { ...supported, transit_encryption_enabled: 'true' }, 'PASS'],
    ['unset', supported, 'WARN'],
    ['null', { ...supported, transit_encryption_enabled: null }, 'WARN'],
    ['later', { ...supported, engine_version: '1.6.100', transit_encryption_enabled: true }, 'PASS'],
    ['old_patch', { ...supported, engine_version: '1.6.9' }, 'UNKNOWN'],
    ['old_minor', { ...supported, engine_version: '1.5.16' }, 'UNKNOWN'],
    ['partial_version', { ...supported, engine_version: '1.6' }, 'UNKNOWN'],
    ['unknown_version', { ...supported, engine_version: new Unknown('version') }, 'UNKNOWN'],
    ['omitted_version', { ...supported, engine_version: null }, 'UNKNOWN'],
    ['unknown_vpc', { ...supported, subnet_group_name: new Unknown('subnet') }, 'UNKNOWN'],
    ['omitted_vpc', { ...supported, subnet_group_name: null }, 'UNKNOWN'],
    ['unknown_flag', { ...supported, transit_encryption_enabled: new Unknown('flag') }, 'UNKNOWN'],
    ['redacted_flag', { ...supported, transit_encryption_enabled: new Redacted() }, 'UNKNOWN'],
    ['unknown_engine', { ...supported, engine: new Unknown('engine') }, 'UNKNOWN'],
  ]);
});

test('ElastiCache Redis and Valkey cluster members are checked only at their replication group', () => {
  const findings = evaluatePolicies(readPlan(plan([
    rc('aws_elasticache_replication_group.primary', 'aws_elasticache_replication_group', ['create'], { transit_encryption_enabled: false }),
    ...['redis', 'valkey', undefined].map((engine, i) =>
      rc(`aws_elasticache_cluster.member[${i}]`, 'aws_elasticache_cluster', ['create'], { engine, replication_group_id: 'primary' })
    ),
    rc('aws_elasticache_cluster.pending', 'aws_elasticache_cluster', ['create'], { replication_group_id: new Unknown('group') }),
  ]))).filter((f) => f.ruleId === 'elasticache.transit-encryption');
  expect(findings.map((f) => [f.resource, f.status])).toEqual([['aws_elasticache_replication_group.primary', 'WARN']]);
});

test('OpenSearch and Elasticsearch node encryption warns on absent blocks and preserves block uncertainty', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.node-to-node-encryption', type, 'CC6.7', [
      ['off', { node_to_node_encryption: [{ enabled: 'false' }] }, 'WARN'],
      ['on', { node_to_node_encryption: { enabled: 'true' } }, 'PASS'],
      ['unset', {}, 'WARN'],
      ['empty', { node_to_node_encryption: [] }, 'WARN'],
      ['unknown', { node_to_node_encryption: [{ enabled: new Unknown('variable') }] }, 'UNKNOWN'],
      ['block', { node_to_node_encryption: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { node_to_node_encryption: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
      ['redacted', { node_to_node_encryption: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('OpenSearch and Elasticsearch HTTPS enforcement respects the option default without assuming an omitted block', () => {
  for (const type of ['aws_opensearch_domain', 'aws_elasticsearch_domain']) {
    check('opensearch.https', type, 'CC6.7', [
      ['off', { domain_endpoint_options: [{ enforce_https: 'false' }] }, 'WARN'],
      ['on', { domain_endpoint_options: { enforce_https: 'true' } }, 'PASS'],
      ['option_default', { domain_endpoint_options: [{}] }, 'PASS'],
      ['unset', {}, 'UNKNOWN'],
      ['empty', { domain_endpoint_options: [] }, 'UNKNOWN'],
      ['unknown', { domain_endpoint_options: [{ enforce_https: new Unknown('variable') }] }, 'UNKNOWN'],
      ['block', { domain_endpoint_options: new Unknown('computed') }, 'UNKNOWN'],
      ['dynamic', { domain_endpoint_options: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
      ['redacted', { domain_endpoint_options: new Redacted() }, 'UNKNOWN'],
    ]);
  }
});

test('HTTP listeners warn unless their default action redirects to HTTPS, preserving unknown actions', () => {
  check('elb.https', 'aws_lb_listener', 'CC6.7', [
    ['forward', { protocol: 'HTTP', default_action: [{ type: 'forward' }] }, 'WARN'],
    ['redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }] }, 'PASS'],
    ['object', { protocol: 'HTTP', default_action: { type: 'redirect', redirect: { protocol: 'HTTPS' } } }, 'PASS'],
    ['http_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: 'HTTP' }] }] }, 'WARN'],
    ['inherited_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{}] }] }, 'WARN'],
    ['unset_action', { protocol: 'HTTP' }, 'WARN'],
    ['unknown_action', { protocol: 'HTTP', default_action: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic_action', { protocol: 'HTTP', default_action: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['unknown_type', { protocol: 'HTTP', default_action: [{ type: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_redirect', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: new Unknown('computed') }] }, 'UNKNOWN'],
    ['unknown_target', { protocol: 'HTTP', default_action: [{ type: 'redirect', redirect: [{ protocol: new Unknown('variable') }] }] }, 'UNKNOWN'],
    ['https', { protocol: 'HTTPS' }, 'PASS'],
    ['unknown_protocol', { protocol: new Unknown('variable') }, 'UNKNOWN'],
    ['missing_protocol', {}, 'UNKNOWN'],
  ]);
  expect(evaluatePolicies(readPlan(plan([rc('aws_lb_listener.tcp', 'aws_lb_listener', ['create'], { protocol: 'TCP' })])))).toEqual([]);
});

test('HTTP listener HTTPS redirects account for catch-all rule conditions, association and priority', () => {
  const redirect = [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }];
  const forward = [{ type: 'forward' }];
  const catchAll = [{ path_pattern: [{ values: ['/*'] }] }];
  const partial = [{ path_pattern: [{ values: ['/admin/*'] }] }];
  const rule = (attrs: Attrs): Attrs => ({ listener_arn: 'listener-http', priority: 10, condition: catchAll, action: redirect, ...attrs });
  const cases: Array<[string, Attrs[], FindingStatus]> = [
    ['catch_all', [rule({ priority: 1 })], 'PASS'],
    ['star', [rule({ condition: { path_pattern: { values: ['*'] } } })], 'PASS'],
    ['later_forward', [rule({}), rule({ priority: 20, condition: partial, action: forward })], 'PASS'],
    ['earlier_redirect', [rule({}), rule({ priority: 1, condition: partial })], 'PASS'],
    ['earlier_forward', [rule({}), rule({ priority: 1, condition: partial, action: forward })], 'WARN'],
    ['unknown_priority', [rule({ priority: new Unknown('priority') })], 'UNKNOWN'],
    ['unknown_earlier_priority', [rule({}), rule({ priority: new Unknown('priority'), action: forward })], 'UNKNOWN'],
    ['unknown_condition', [rule({ condition: new Unknown('dynamic condition') })], 'UNKNOWN'],
    ['unknown_matching_path', [rule({ condition: [{ path_pattern: [{ values: new Unknown('paths') }] }], action: forward })], 'UNKNOWN'],
    ['unknown_action', [rule({ action: new Unknown('action') })], 'UNKNOWN'],
    ['unrecognized_action', [rule({ action: [{ type: 'unrecognized' }] })], 'UNKNOWN'],
    ['unknown_listener', [rule({ listener_arn: new Unknown('listener') })], 'UNKNOWN'],
    ['conditional', [rule({ condition: partial })], 'UNKNOWN'],
    ['additional_condition', [rule({ condition: [...catchAll, { host_header: [{ values: ['example.com'] }] }] })], 'UNKNOWN'],
    ['different_listener', [rule({ listener_arn: 'listener-other' })], 'WARN'],
  ];
  for (const [name, rules, status] of cases) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { arn: 'listener-http', protocol: 'HTTP', default_action: forward }),
      ...rules.map((attrs, i) => rc(`aws_lb_listener_rule.rule[${i}]`, 'aws_lb_listener_rule', ['create'], attrs)),
    ]))).filter((f) => f.ruleId === 'elb.https');
    expect([name, findings.map((f) => f.status)]).toEqual([name, [status]]);
  }
});

test('HTTP listener rule references preserve unresolved listener association', () => {
  for (const [listenerArn, ruleArn, refs, status] of [
    [new Unknown('listener ARN'), new Unknown('listener ARN'), ['aws_lb_listener.http.arn'], 'PASS'],
    ['listener-http', new Unknown('conditional listener ARN'), ['aws_lb_listener.http.arn', 'aws_lb_listener.other.arn'], 'UNKNOWN'],
    [new Unknown('listener ARN'), 'listener-rule-target', [], 'UNKNOWN'],
    ['listener-http', new Unknown('module output'), ['module.external.listener_arn'], 'UNKNOWN'],
  ] as const) {
    const findings = evaluatePolicies(readPlan(plan([
      rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { arn: listenerArn, protocol: 'HTTP', default_action: [{ type: 'forward' }] }),
      rc('aws_lb_listener_rule.redirect', 'aws_lb_listener_rule', ['create'], {
        listener_arn: ruleArn, priority: 1,
        condition: [{ path_pattern: [{ values: ['/*'] }] }],
        action: [{ type: 'redirect', redirect: [{ protocol: 'HTTPS' }] }],
      }),
    ], [cfg('aws_lb_listener_rule.redirect', { listener_arn: [...refs] })])))
      .filter((f) => f.ruleId === 'elb.https');
    expect(findings.map((f) => f.status)).toEqual([status]);
  }
});

test('HTTPS listener policies require a TLS 1.2 floor rather than a recent policy date', () => {
  check('elb.tls-policy', 'aws_lb_listener', 'CC6.7', [
    ['legacy', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' }, 'WARN'],
    ['tls11', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS-1-1-2017-01' }, 'WARN'],
    ['modern_but_weak', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-0-2021-06' }, 'WARN'],
    ['tls12', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS-1-2-2017-01' }, 'PASS'],
    ['tls13', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' }, 'PASS'],
    ['tls13_only', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-3-2021-06' }, 'PASS'],
    ['forward_secrecy', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-FS-1-2-Res-2020-10' }, 'PASS'],
    ['post_quantum', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' }, 'PASS'],
    ['default', { protocol: 'HTTPS' }, 'WARN'],
    ['unknown', { protocol: 'HTTPS', ssl_policy: new Unknown('variable') }, 'UNKNOWN'],
    ['redacted', { protocol: 'HTTPS', ssl_policy: new Redacted() }, 'UNKNOWN'],
    ['unrecognized', { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-future' }, 'UNKNOWN'],
  ]);
  expect(evaluatePolicies(readPlan(plan([rc('aws_lb_listener.http', 'aws_lb_listener', ['create'], { protocol: 'HTTP' })])))
    .filter((f) => f.ruleId === 'elb.tls-policy')).toEqual([]);
});

test('CloudFront HTTPS checks default and every ordered behavior and retains unresolved behavior uncertainty', () => {
  check('cloudfront.https', 'aws_cloudfront_distribution', 'CC6.7', [
    ['http', { default_cache_behavior: [{ viewer_protocol_policy: 'allow-all' }] }, 'WARN'],
    ['https', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }] }, 'PASS'],
    ['redirect', { default_cache_behavior: { viewer_protocol_policy: 'redirect-to-https' } }, 'PASS'],
    ['ordered_http', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }], ordered_cache_behavior: [
      { path_pattern: '/safe/*', viewer_protocol_policy: 'redirect-to-https' },
      { path_pattern: '/unsafe/*', viewer_protocol_policy: 'allow-all' },
    ] }, 'WARN'],
    ['unset', {}, 'UNKNOWN'],
    ['unknown_policy', { default_cache_behavior: [{ viewer_protocol_policy: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_default', { default_cache_behavior: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic_ordered', { default_cache_behavior: [{ viewer_protocol_policy: 'https-only' }], ordered_cache_behavior: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['redacted', { default_cache_behavior: new Redacted() }, 'UNKNOWN'],
    ['invalid', { default_cache_behavior: [{ viewer_protocol_policy: 'unrecognized' }] }, 'UNKNOWN'],
  ]);
});

test('CloudFront TLS versions distinguish TLS 1.2 policies from legacy and unresolved certificate settings', () => {
  check('cloudfront.tls-policy', 'aws_cloudfront_distribution', 'CC6.7', [
    ['ssl3', { viewer_certificate: [{ minimum_protocol_version: 'SSLv3' }] }, 'WARN'],
    ['tls1', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1' }] }, 'WARN'],
    ['tls1_2016', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1_2016' }] }, 'WARN'],
    ['tls11', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.1_2016' }] }, 'WARN'],
    ['tls12', { viewer_certificate: { minimum_protocol_version: 'TLSv1.2_2018' } }, 'PASS'],
    ['tls12_2021', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.2_2021' }] }, 'PASS'],
    ['tls13', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.3_2025' }] }, 'PASS'],
    ['custom_default', { viewer_certificate: [{ acm_certificate_arn: 'arn:aws:acm:eu-west-1:123456789012:certificate/example' }] }, 'WARN'],
    ['cloudfront_default', { viewer_certificate: [{ cloudfront_default_certificate: true, minimum_protocol_version: 'TLSv1.2_2021' }] }, 'WARN'],
    ['unset', {}, 'UNKNOWN'],
    ['unknown', { viewer_certificate: [{ minimum_protocol_version: new Unknown('variable') }] }, 'UNKNOWN'],
    ['unknown_block', { viewer_certificate: new Unknown('computed') }, 'UNKNOWN'],
    ['dynamic', { viewer_certificate: [new Unknown('dynamic collection')] }, 'UNKNOWN'],
    ['redacted', { viewer_certificate: new Redacted() }, 'UNKNOWN'],
    ['unknown_default', { viewer_certificate: [{ cloudfront_default_certificate: new Unknown('variable'), minimum_protocol_version: 'TLSv1.2_2021' }] }, 'UNKNOWN'],
    ['unrecognized', { viewer_certificate: [{ minimum_protocol_version: 'TLSv1.2_future' }] }, 'UNKNOWN'],
  ]);
});

const moduleSource = new MemorySource({
  'main.tf': `
    variable "environments" { type = map(bool) }
    module "service" {
      source = "./service"
      for_each = var.environments
      secure = each.value
    }
  `,
  'service/main.tf': `
    variable "secure" { type = bool }
    resource "aws_ebs_encryption_by_default" "default" {
      count = 2
      enabled = var.secure
    }
    resource "aws_ebs_volume" "volume" {
      count = 2
      encrypted = var.secure
    }
    resource "aws_efs_file_system" "fs" {
      count = 2
      encrypted = var.secure
    }
    resource "aws_elasticache_replication_group" "cache" {
      count = 2
      at_rest_encryption_enabled = var.secure
      transit_encryption_enabled = var.secure
    }
    resource "aws_opensearch_domain" "search" {
      count = 2
      encrypt_at_rest { enabled = var.secure }
      node_to_node_encryption { enabled = var.secure }
      domain_endpoint_options { enforce_https = var.secure }
    }
    resource "aws_elasticsearch_domain" "legacy" {
      count = 2
      encrypt_at_rest { enabled = var.secure }
      node_to_node_encryption { enabled = var.secure }
      domain_endpoint_options { enforce_https = var.secure }
    }
    resource "aws_lb_listener" "http" {
      count = 2
      protocol = "HTTP"
      default_action {
        type = "redirect"
        redirect {
          protocol = var.secure ? "HTTPS" : "HTTP"
          status_code = "HTTP_301"
        }
      }
    }
    resource "aws_lb_listener" "tls" {
      count = 2
      protocol = "HTTPS"
      ssl_policy = var.secure ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : "ELBSecurityPolicy-2016-08"
    }
    resource "aws_cloudfront_distribution" "cdn" {
      count = 2
      default_cache_behavior { viewer_protocol_policy = "https-only" }
      ordered_cache_behavior { viewer_protocol_policy = var.secure ? "https-only" : "allow-all" }
      viewer_certificate { minimum_protocol_version = var.secure ? "TLSv1.2_2021" : "TLSv1" }
    }
  `,
});

const moduleRules = [
  ['ebs.default-encryption', 'aws_ebs_encryption_by_default.default'],
  ['ebs.encryption', 'aws_ebs_volume.volume'],
  ['efs.encryption', 'aws_efs_file_system.fs'],
  ['elasticache.encryption', 'aws_elasticache_replication_group.cache'],
  ['elasticache.transit-encryption', 'aws_elasticache_replication_group.cache'],
  ['opensearch.encryption', 'aws_opensearch_domain.search'],
  ['opensearch.node-to-node-encryption', 'aws_opensearch_domain.search'],
  ['opensearch.https', 'aws_opensearch_domain.search'],
  ['opensearch.encryption', 'aws_elasticsearch_domain.legacy'],
  ['opensearch.node-to-node-encryption', 'aws_elasticsearch_domain.legacy'],
  ['opensearch.https', 'aws_elasticsearch_domain.legacy'],
  ['elb.https', 'aws_lb_listener.http'],
  ['elb.tls-policy', 'aws_lb_listener.tls'],
  ['cloudfront.https', 'aws_cloudfront_distribution.cdn'],
  ['cloudfront.tls-policy', 'aws_cloudfront_distribution.cdn'],
];

test('encryption checks resolve Terraform listener and subnet references with counted resources', () => {
  const source = new MemorySource({ 'main.tf': `
    resource "aws_ebs_encryption_by_default" "regional" { enabled = true }
    resource "aws_ebs_volume" "volume" { availability_zone = "eu-west-1a" }
    resource "aws_lb_listener" "http" {
      count = 2
      protocol = "HTTP"
      default_action { type = "forward" }
    }
    resource "aws_lb_listener_rule" "redirect" {
      count = 2
      listener_arn = aws_lb_listener.http[count.index].arn
      priority = 1
      action {
        type = "redirect"
        redirect {
          protocol = "HTTPS"
          status_code = "HTTP_301"
        }
      }
      condition { path_pattern { values = ["/*"] } }
    }
    resource "aws_elasticache_replication_group" "secondary" { global_replication_group_id = "global-cache" }
    resource "aws_elasticache_subnet_group" "cache" {
      name_prefix = "cache-"
      subnet_ids = ["subnet-vpc"]
    }
    resource "aws_elasticache_cluster" "memcached" {
      count = 2
      engine = "memcached"
      engine_version = "1.6.12"
      subnet_group_name = aws_elasticache_subnet_group.cache.name
      transit_encryption_enabled = count.index == 0
    }
    resource "aws_elasticache_cluster" "replica" { replication_group_id = aws_elasticache_replication_group.secondary.id }
  ` });
  const evaluated = evaluateRoot(source, '.');
  expect(evaluated.diagnostics).toEqual([]);
  const findings = evaluatePolicies(compareEvaluations(undefined, evaluated)).filter((f) =>
    ['ebs.encryption', 'elb.https', 'elasticache.encryption', 'elasticache.transit-encryption'].includes(f.ruleId));
  expect(findings.map((f) => [f.resource, f.ruleId, f.status])).toEqual([
    ['aws_ebs_volume.volume', 'ebs.encryption', 'PASS'],
    ['aws_lb_listener.http[0]', 'elb.https', 'PASS'],
    ['aws_lb_listener.http[1]', 'elb.https', 'PASS'],
    ['aws_elasticache_replication_group.secondary', 'elasticache.encryption', 'UNKNOWN'],
    ['aws_elasticache_replication_group.secondary', 'elasticache.transit-encryption', 'UNKNOWN'],
    ['aws_elasticache_cluster.memcached[0]', 'elasticache.transit-encryption', 'PASS'],
    ['aws_elasticache_cluster.memcached[1]', 'elasticache.transit-encryption', 'WARN'],
  ]);
});

test('all encryption rules evaluate separate count instances inside for_each modules through static HCL', () => {
  const evaluation = evaluateRoot(moduleSource, '.', { environments: { secure: true, insecure: false } });
  expect(evaluation.diagnostics).toEqual([]);
  const result = analyze(compareEvaluations(undefined, evaluation));
  for (const [rule, resource] of moduleRules) {
    for (const [env, status] of [['secure', 'PASS'], ['insecure', 'WARN']]) {
      const addresses = [0, 1].map((i) => `module.service["${env}"].${resource}[${i}]`);
      expect(result.findings.filter((f) => f.ruleId === rule && addresses.includes(f.resource)).map((f) => [f.resource, f.status]))
        .toEqual(addresses.map((address) => [address, status]));
    }
  }
  expect(result.findings.some((f) => f.status === 'FAIL')).toBe(false);
  expect(result.gate).toEqual({ result: 'pass', items: [], reasons: [] });
});

test('symbolic for_each modules keep unresolved encryption values UNKNOWN', () => {
  const evaluation = evaluateRoot(moduleSource, '.');
  expect(evaluation.diagnostics).toEqual([]);
  const findings = evaluatePolicies(compareEvaluations(undefined, evaluation));
  for (const [rule, resource] of moduleRules) {
    const addresses = [0, 1].map((i) => `module.service[*].${resource}[${i}]`);
    expect(findings.filter((f) => f.ruleId === rule && addresses.includes(f.resource)).map((f) => [f.resource, f.status]))
      .toEqual(addresses.map((address) => [address, 'UNKNOWN']));
  }
});

test('encryption findings preserve pre-existing detection, exceptions, Markdown and v1 change records', () => {
  const changes = readPlan(plan([
    rc('aws_ebs_volume.preexisting', 'aws_ebs_volume', ['update'], { encrypted: false, tags: { team: 'new' } }, { before: { encrypted: false } }),
    rc('aws_lb_listener.downgrade', 'aws_lb_listener', ['update'], { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-2016-08' }, { before: { protocol: 'HTTPS', ssl_policy: 'ELBSecurityPolicy-TLS13-1-2-2021-06' } }),
    rc('aws_efs_file_system.pending', 'aws_efs_file_system', ['create'], {}, { afterUnknown: { encrypted: true } }),
    rc('aws_ebs_volume.deleted', 'aws_ebs_volume', ['delete'], null, { before: { encrypted: false } }),
    rc('aws_ebs_volume.unchanged', 'aws_ebs_volume', ['no-op'], { encrypted: false }),
    rc('aws_ebs_volume.data', 'aws_ebs_volume', ['create'], { encrypted: false }, { mode: 'data' }),
  ]));
  const result = analyze(changes, {
    now: new Date('2026-10-29T00:00:00Z'),
    policy: { exceptions: [{ rule: 'elb.tls-policy', resource: '*', reason: 'Legacy client migration', expires: '2026-12-31' }] },
  });
  expect(result.findings.map((f) => [f.resource, f.ruleId, f.status, f.preExisting, f.accepted?.reason])).toEqual([
    ['aws_ebs_volume.preexisting', 'ebs.encryption', 'WARN', true, undefined],
    ['aws_lb_listener.downgrade', 'elb.https', 'PASS', undefined, undefined],
    ['aws_lb_listener.downgrade', 'elb.tls-policy', 'WARN', undefined, 'Legacy client migration'],
    ['aws_efs_file_system.pending', 'efs.encryption', 'UNKNOWN', undefined, undefined],
  ]);
  // The volume deletion still blocks through the existing blast-radius check, not encryption.
  expect(result.gate.result).toBe('block');
  expect(result.gate.items.map((item) => [item.rule, item.level])).toEqual([['blast-radius', 'block']]);
  const markdown = renderMarkdown(JSON.parse(JSON.stringify(result)), {});
  expect(markdown).toContain('A.8.24, SOC 2 CC6.7');
  expect(markdown).toContain('A.8.24, SOC 2 CC6.1');
  const record = changeRecord({
    commit: { sha: 'a'.repeat(40), parents: ['b'.repeat(40)], subject: 'encryption settings', author: 'Dev', date: '2026-10-29T00:00:00Z' },
    base: 'b'.repeat(40), roots: [], result, appLinks: [], engine: { version: 'test', replaceCatalog: 'test' },
  });
  expect(record.schema).toBe('diffseal.change-record/v1');
  expect(record.controls).toHaveLength(4);
  expect(record.controls.map((c) => [c.control, c.category, c.frameworks.soc2_tsc])).toEqual([
    ['ISO27001:A.8.24', 'encryption-at-rest', [{ ref: 'CC6.1', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-in-transit', [{ ref: 'CC6.7', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-in-transit', [{ ref: 'CC6.7', fit: 'direct' }]],
    ['ISO27001:A.8.24', 'encryption-at-rest', [{ ref: 'CC6.1', fit: 'direct' }]],
  ]);
});
