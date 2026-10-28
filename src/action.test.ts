import { describe, expect, test } from 'bun:test';
import { upsertComment } from './action/comment.js';

type Call = { url: string; method: string; body?: string };

function fakeGitHub(comments: Array<{ id: number; body: string; user: { login: string } }>, failPatch = false) {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init?: { method?: string; body?: string }) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: init?.body });
    if (method === 'GET') {
      const page = Number(new URL(url).searchParams.get('page') ?? '1');
      const slice = comments.slice((page - 1) * 100, page * 100);
      return new Response(JSON.stringify(slice), { status: 200 });
    }
    if (method === 'PATCH' && failPatch) return new Response('{}', { status: 403 });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  return { calls, fetchFn };
}

const ctx = { api: 'https://api.github.com', repo: 'o/r', pr: 7, token: 't', author: 'github-actions[bot]' };
const MARKER = '<!-- diffseal-report -->';

describe('upsertComment', () => {
  test('ignores a marker comment written by someone else and posts its own', async () => {
    const gh = fakeGitHub([{ id: 1, body: `${MARKER} gate: PASS`, user: { login: 'pr-author' } }]);
    await upsertComment('report', { ...ctx, fetchFn: gh.fetchFn });
    expect(gh.calls.map((c) => c.method)).toEqual(['GET', 'POST']);
  });

  test('updates its own comment, found on a later page', async () => {
    const many = Array.from({ length: 150 }, (_, i) => ({ id: i, body: 'x', user: { login: 'someone' } }));
    many[140] = { id: 140, body: `${MARKER} old`, user: { login: 'github-actions[bot]' } };
    const gh = fakeGitHub(many);
    await upsertComment('report', { ...ctx, fetchFn: gh.fetchFn });
    expect(gh.calls.filter((c) => c.method !== 'GET').map((c) => [c.method, c.url.endsWith('/comments/140')])).toEqual([['PATCH', true]]);
  });

  test('posts a new comment when updating fails', async () => {
    const gh = fakeGitHub([{ id: 3, body: `${MARKER} old`, user: { login: 'github-actions[bot]' } }], true);
    await upsertComment('report', { ...ctx, fetchFn: gh.fetchFn });
    expect(gh.calls.filter((c) => c.method !== 'GET').map((c) => c.method)).toEqual(['PATCH', 'POST']);
  });

  test('sends a User-Agent, which the GitHub API requires (round 2 gemini)', async () => {
    const seen: Array<Record<string, string>> = [];
    const fetchFn = (async (_url: string, init?: { headers?: Record<string, string> }) => {
      seen.push(init?.headers ?? {});
      return new Response('[]', { status: 200 });
    }) as unknown as typeof fetch;
    await upsertComment('r', { ...ctx, fetchFn });
    expect(seen.every((h) => typeof h['user-agent'] === 'string' && h['user-agent'].length > 0)).toBe(true);
  });

  test('when nothing changed (onlyUpdate), skips posting a new comment but updates an existing one', async () => {
    const empty = fakeGitHub([]);
    await upsertComment('quiet', { ...ctx, onlyUpdate: true, fetchFn: empty.fetchFn });
    expect(empty.calls.map((c) => c.method)).toEqual(['GET']);

    const prior = fakeGitHub([{ id: 9, body: `${MARKER} earlier finding`, user: { login: 'github-actions[bot]' } }]);
    await upsertComment('cleared', { ...ctx, onlyUpdate: true, fetchFn: prior.fetchFn });
    expect(prior.calls.map((c) => c.method)).toEqual(['GET', 'PATCH']);
  });
});
