import { expect, test } from 'bun:test';
import { ExtractionCache } from './cache.js';

test('a bounded extraction cache reuses blobs, protects stored facts, and evicts least-recently-used entries', () => {
  const cache = new ExtractionCache({ maxEntries: 2, maxBytes: 4096 });
  let builds = 0;
  const read = (id: string) =>
    cache.memo('facts', id, { language: 'go' }, () => {
      builds++;
      return { actions: ['s3:GetObject'] };
    });
  const first = read('blob-a');
  first.actions.push('s3:PutObject');
  expect(read('blob-a')).toEqual({ actions: ['s3:GetObject'] });
  read('blob-b');
  read('blob-a');
  read('blob-c');
  read('blob-b');
  expect(builds).toBe(4);
  expect(cache.stats()).toMatchObject({ entries: 2, hits: 2, misses: 4, evictions: 2 });
  expect(cache.stats().bytes).toBeLessThanOrEqual(4096);
});

test('the byte budget rejects oversized summaries and contexts cannot share facts', () => {
  const cache = new ExtractionCache({ maxBytes: 1024 });
  let builds = 0;
  for (let i = 0; i < 2; i++)
    cache.memo('facts', 'large', null, () => {
      builds++;
      return 'x'.repeat(2048);
    });
  expect(cache.stats().entries).toBe(0);
  expect(builds).toBe(2);
  const old = cache.memo('facts', 'same-blob', { module: 'one' }, () => ['one']);
  const changed = cache.memo('facts', 'same-blob', { module: 'two' }, () => ['two']);
  expect(old).toEqual(['one']);
  expect(changed).toEqual(['two']);
  expect(cache.stats().bytes).toBeLessThanOrEqual(1024);
});
