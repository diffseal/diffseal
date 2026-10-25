import { expect, test } from 'bun:test';
import { globCovers } from './reconcile.js';

test('a grant covers a pattern only if every expansion of it matches (round 7)', () => {
  expect(globCovers('topic-????', 'topic-*')).toBe(false);
  expect(globCovers('topic-*', 'topic-*')).toBe(true);
  expect(globCovers('*', 'a*b?c')).toBe(true);
  expect(globCovers('provider/*/creds', 'provider/*/creds')).toBe(true);
  expect(globCovers('provider/x*/creds', 'provider/*/creds')).toBe(false);
  expect(globCovers('a*', 'a*b')).toBe(true);
  expect(globCovers('a?c', 'a?c')).toBe(true);
  expect(globCovers('a?c', 'a*c')).toBe(false);
  expect(globCovers('abc', 'abc')).toBe(true);
  expect(globCovers('ab', 'abc')).toBe(false);
});
