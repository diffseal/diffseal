import { isUnknown, type Attrs } from '../core/model.js';
import { PROVIDER_SCHEMA_MAX_DEPTH, resourceSchema } from '../terraform/schemaCatalog.js';

/** First element of a nested block list (plan JSON represents blocks as lists), or the object itself. */
export function block(v: unknown): Attrs | undefined {
  if (Array.isArray(v)) return v.length && v[0] && typeof v[0] === 'object' && !isUnknown(v[0]) ? (v[0] as Attrs) : undefined;
  if (v && typeof v === 'object' && !isUnknown(v)) return v as Attrs;
  return undefined;
}

/** A nested block written as a dynamic block over a collection not known statically. */
export function unknownBlock(v: unknown): boolean {
  // Only a dynamic block over a collection not known statically. In a plan, a computed block nobody
  // configured is "known after apply" too, and is judged as absent (its default), as before.
  const dynamic = (x: unknown) => isUnknown(x) && x.reason.startsWith('dynamic ');
  return dynamic(v) || (Array.isArray(v) && v.some(dynamic));
}

export function blocks(v: unknown): Attrs[] {
  if (Array.isArray(v)) return v.filter((x): x is Attrs => Boolean(x) && typeof x === 'object' && !isUnknown(x));
  const b = block(v);
  return b ? [b] : [];
}

/** AWS provider arguments that are booleans in the schema: Terraform converts "true"/"false" to them. */
const BOOL_ATTRS = new Set([
  'force_destroy',
  'deletion_protection',
  'deletion_protection_enabled',
  'skip_final_snapshot',
  'apply_immediately',
  'block_public_acls',
  'block_public_policy',
  'ignore_public_acls',
  'restrict_public_buckets',
  'enabled',
  'sqs_managed_sse_enabled',
  'enable_key_rotation',
  'storage_encrypted',
  'publicly_accessible',
  'multi_az',
  'encrypted',
  'is_enabled',
  'bucket_key_enabled',
  'object_lock_enabled',
]);

/** AWS provider arguments that are numbers in the schema: Terraform converts numeric strings to them. */
const NUMBER_ATTRS = new Set([
  'from_port',
  'to_port',
  'recovery_window_in_days',
  'deletion_window_in_days',
  'memory_size',
  'backup_retention_period',
  'days',
  'noncurrent_days',
  'retention_in_days',
  'message_retention_seconds',
  'allocated_storage',
]);

/** Maps of free-form values (tags, env vars): their entries are strings, whatever their keys. */
const FREE_FORM = new Set(['tags', 'tags_all', 'variables', 'environment_variables']);

/**
 * Attribute values in their schema types, as Terraform converts them: `force_destroy = "true"` is
 * true, `from_port = "443"` is 443. Rules and risk decisions compare with === true and typeof number.
 * Uses the provider schema snapshot (`aws-schema.json`) when the resource type is known and the path
 * is within the snapshot's depth cap, falling back to the attribute-name lists otherwise.
 */
export function typed<T>(v: T, resourceType?: string): T {
  const schema = resourceType ? resourceSchema(resourceType) : undefined;
  const go = (x: unknown, path?: string, key?: string): unknown => {
    if (Array.isArray(x)) return x.map((y) => go(y, path, key));
    if (x && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype) {
      if (key && FREE_FORM.has(key)) return x;
      return Object.fromEntries(
        Object.entries(x).map(([k, y]) => [k, go(y, path ? `${path}.${k}` : k, k)])
      );
    }
    if (typeof x === 'string' && path && key) {
      const depth = path.split('.').length;
      if (schema && depth <= PROVIDER_SCHEMA_MAX_DEPTH) {
        if (schema.bool.has(path) && (x === 'true' || x === 'false')) return x === 'true';
        if (schema.number.has(path) && /^-?\d+(\.\d+)?$/.test(x)) return Number(x);
        return x;
      }
      if (BOOL_ATTRS.has(key) && (x === 'true' || x === 'false')) return x === 'true';
      if (NUMBER_ATTRS.has(key) && /^-?\d+(\.\d+)?$/.test(x)) return Number(x);
    }
    return x;
  };
  return go(v) as T;
}

