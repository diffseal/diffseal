/** Builders for `terraform show -json` documents used by tests. */

export interface RcOptions {
  before?: Record<string, unknown> | null;
  afterUnknown?: Record<string, unknown>;
  afterSensitive?: Record<string, unknown>;
  replacePaths?: string[][];
  actionReason?: string;
  mode?: 'managed' | 'data';
}

export function rc(
  address: string,
  type: string,
  actions: string[],
  after: Record<string, unknown> | null,
  opts: RcOptions = {}
) {
  const last = address.replace(/\[[^\]]*\]$/, '').split('.').pop()!;
  const moduleAddress = address.startsWith('module.')
    ? address.slice(0, address.indexOf(`.${type}.`))
    : undefined;
  return {
    address,
    ...(moduleAddress ? { module_address: moduleAddress } : {}),
    mode: opts.mode ?? 'managed',
    type,
    name: last,
    provider_name: 'registry.terraform.io/hashicorp/aws',
    change: {
      actions,
      before: opts.before ?? (actions.includes('create') && !actions.includes('delete') ? null : {}),
      after,
      after_unknown: opts.afterUnknown ?? {},
      before_sensitive: false,
      after_sensitive: opts.afterSensitive ?? {},
      ...(opts.replacePaths ? { replace_paths: opts.replacePaths } : {}),
    },
    ...(opts.actionReason ? { action_reason: opts.actionReason } : {}),
  };
}

/** A root-module resource config entry whose attributes reference other resources. */
export function cfg(address: string, refs: Record<string, string[]>) {
  const [type, name] = address.split('.');
  return {
    address,
    mode: 'managed',
    type,
    name,
    expressions: Object.fromEntries(
      Object.entries(refs).map(([attr, targets]) => [attr, { references: targets }])
    ),
  };
}

export function plan(resourceChanges: unknown[], configResources: unknown[] = [], extra: Record<string, unknown> = {}) {
  // Fixture values represent configured arguments unless a test supplies an exact configuration.
  const supplied = configResources as Array<{ address: string; expressions?: Record<string, unknown> }>;
  const generated = new Map<string, { address: string; provider_config_key?: string; expressions: Record<string, unknown> }>();
  for (const change of resourceChanges as ReturnType<typeof rc>[]) {
    const address = change.address.replace(/\[[^\]]*\]/g, '');
    const config = supplied.find((r) => r.address === address);
    const expressions = Object.fromEntries(Object.entries({ ...change.change.after, ...change.change.after_unknown })
      .map(([key, value]) => [key, value === null ? { constant_value: null } : { references: ['var.fixture'] }]));
    generated.set(address, { address, provider_config_key: 'aws', ...config, expressions: { ...generated.get(address)?.expressions, ...expressions, ...config?.expressions } });
  }
  const resources = [...generated.values()];
  return {
    format_version: '1.2',
    terraform_version: '1.9.5',
    resource_changes: resourceChanges,
    configuration: { root_module: { resources: [...resources, ...supplied.filter((r) => !resources.some((c) => c.address === r.address))] } },
    ...extra,
    variables: { fixture: { value: true }, ...(extra.variables as Record<string, unknown> | undefined) },
  };
}
