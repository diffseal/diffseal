import { describe, expect, test } from 'bun:test';
import { parseModuleLock, readModuleLock } from './moduleCache.js';

const entry = { source: 'terraform-aws-modules/s3-bucket/aws', constraint: '4.1.0', version: '4.1.0', subdir: '', sha256: 'a'.repeat(64) };
const legacy = JSON.stringify({ format: 'terratrust.modules/v1', modules: [entry] });
const current = JSON.stringify({ format: 'diffseal.modules/v1', modules: [] });

describe('module locks written before the rename to Diffseal', () => {
  test('a lock with the TerraTrust format id is read and comes back with the Diffseal id', () => {
    const lock = parseModuleLock(legacy);
    expect(lock.format).toBe('diffseal.modules/v1');
    expect(lock.modules).toEqual([entry]);
  });

  test('a commit that only has terratrust.modules.lock.json reads that lock', () => {
    expect(readModuleLock({ readFile: (p: string) => (p === 'terratrust.modules.lock.json' ? legacy : undefined) })).toBe(legacy);
  });

  test('diffseal.modules.lock.json wins when both exist', () => {
    const files: Record<string, string> = { 'terratrust.modules.lock.json': legacy, 'diffseal.modules.lock.json': current };
    expect(readModuleLock({ readFile: (p: string) => files[p] })).toBe(current);
  });
});
