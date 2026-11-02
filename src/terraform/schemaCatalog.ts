import generated from './aws-schema.json' with { type: 'json' };
export { argumentFacts, type ArgumentFacts } from './replaceCatalog.js';

export interface RawResourceSchema {
  bool?: string[];
  number?: string[];
  computed?: string[];
  sensitive?: string[];
  write_only?: string[];
  blocks?: Record<string, string>;
}

interface RawSchemaSnapshot {
  source: string;
  version: string;
  lock: { h1: string };
  terraform: string;
  format_version: string;
  schema_sha256: string;
  max_depth: number;
  resources: Record<string, RawResourceSchema>;
}

const snapshot = generated as RawSchemaSnapshot;

export interface ResourceSchema {
  bool: Set<string>;
  number: Set<string>;
  computed: Set<string>;
  sensitive: Set<string>;
  writeOnly: Set<string>;
  blocks: Record<string, string>;
}

const cache = new Map<string, ResourceSchema>();

export function resourceSchema(type: string): ResourceSchema | undefined {
  const hit = cache.get(type);
  if (hit) return hit;
  const raw = snapshot.resources[type];
  if (!raw) return undefined;
  const entry: ResourceSchema = {
    bool: new Set(raw.bool ?? []),
    number: new Set(raw.number ?? []),
    computed: new Set(raw.computed ?? []),
    sensitive: new Set(raw.sensitive ?? []),
    writeOnly: new Set(raw.write_only ?? []),
    blocks: raw.blocks ?? {},
  };
  cache.set(type, entry);
  return entry;
}

export const PROVIDER_SCHEMA_SOURCE = `${snapshot.source.replace(/^registry\.terraform\.io\//, '')}@${snapshot.version}`;
export const PROVIDER_SCHEMA_VERSION = snapshot.version;
export const PROVIDER_SCHEMA_FORMAT_VERSION = snapshot.format_version;
export const PROVIDER_SCHEMA_SHA256 = snapshot.schema_sha256;
export const PROVIDER_SCHEMA_MAX_DEPTH = snapshot.max_depth;
export const PROVIDER_SCHEMA_LOCK_H1 = snapshot.lock.h1;
export const PROVIDER_SCHEMA_RESOURCE_COUNT = Object.keys(snapshot.resources).length;

/**
 * Whether the provider leaves the object in AWS when Terraform destroys it: `skip_destroy = true`, read
 * from the last applied values, on a type whose schema has that argument (the provider's delete then
 * only removes it from state). Not for a value that is unknown or sensitive.
 */
export function retainedOnDestroy(type: string, before: Record<string, unknown> | null | undefined): boolean {
  if (!resourceSchema(type)?.bool.has('skip_destroy')) return false;
  const v = before?.skip_destroy;
  return v === true || v === 'true';
}
