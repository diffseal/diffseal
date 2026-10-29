import { isRedacted, isUnknown } from './model.js';

/** Evidence must stay known and non-null throughout resolution, including function operands. */
export function knownConfiguration(value: unknown): boolean {
  if (value == null || isUnknown(value)) return false;
  if (isRedacted(value)) return value.revealed !== undefined && knownConfiguration(value.revealed.value);
  if (Array.isArray(value)) return value.every(knownConfiguration);
  if (typeof value === 'object') {
    return Object.getPrototypeOf(value) === Object.prototype && Object.values(value).every(knownConfiguration);
  }
  return true;
}
