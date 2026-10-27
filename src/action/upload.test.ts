import { expect, test } from 'bun:test';
import { uploadRun, uploadComment, type UploadOptions, type RunUpload } from './upload.js';
import { actionExitCode } from './inputs.js';
import { combineRoots } from '../replay/replay.js';
import type { ReplayResult } from '../replay/replay.js';

function setup(statuses = [200]) {
  const calls: Array<{ url: string; init?: RequestInit }> = [], warnings: string[] = [], logs: string[] = [];
  const replay = { commit: { sha: 'merge', parents: ['base'], subject: 'subject', author: 'author', date: '2026-10-27' }, base: 'base', roots: [], combined: combineRoots([]), appLinks: [] } as unknown as ReplayResult;
  const options: UploadOptions = { upload: 'true', mode: 'pr', eventName: 'pull_request', event: { number: 7, pull_request: { head: { sha: 'head' }, base: { sha: 'base' } } }, advisory: true, replay, env: { ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example/token?other=1', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token', GITHUB_REF: 'refs/pull/7/merge', GITHUB_SHA: 'merge' }, warn: (m) => warnings.push(m), log: (m) => logs.push(m), fetchFn: (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    if (!init?.method) return Response.json({ value: 'oidc-token' });
    const status = statuses.shift() ?? 200;
    if (status === 0) throw new Error('network');
    return Response.json({ id: 'run-1', pageUrl: 'https://api.terratrust.dev/a/org/runs/run-1', exceptionUrl: 'https://api.terratrust.dev/a/org/exceptions/new' }, { status });
  }) as typeof fetch };
  return { options, calls, warnings, logs };
}

test('upload defaults off and unsupported modes and events never fetch', async () => {
  for (const override of [{ upload: undefined }, { mode: 'plan' }, { mode: 'app' }, { eventName: 'merge_group' }]) {
    const s = setup(); await uploadRun({ ...s.options, ...override }); expect(s.calls).toHaveLength(0); expect(s.logs).toHaveLength(1);
  }
});
test('OIDC audience and authorization, merge commit body and push body match the contract', async () => {
  for (const eventName of ['pull_request', 'push']) {
    const s = setup(); const response = await uploadRun({ ...s.options, eventName });
    expect(response?.id).toBe('run-1');
    expect(s.calls[0].url).toBe('https://token.example/token?other=1&audience=terratrust');
    expect(s.calls[0].init?.headers).toEqual({ authorization: 'Bearer request-token' });
    expect(s.calls[1].url).toBe('https://api.terratrust.dev/v1/runs');
    expect(s.calls[1].init?.signal).toBeInstanceOf(AbortSignal);
    expect(s.calls[1].init?.headers).toEqual({ authorization: 'Bearer oidc-token', 'content-type': 'application/json' });
    const body = JSON.parse(String(s.calls[1].init?.body)) as RunUpload;
    expect(body).toMatchObject({ schema: 'terratrust.run/v1', event: eventName, commit: 'merge', action: { mode: 'pr', advisory: true }, record: { change: { commit: 'merge' }, approvals: null, gate: { items: [], reasons: [], result: 'pass' } } });
    expect(body.record.notes.some((n) => n.startsWith('No approvals'))).toBe(false);
    expect(body.pullRequest).toEqual(eventName === 'pull_request' ? { number: 7, headSha: 'head', baseSha: 'base' } : undefined);
  }
});
test('fork pull requests without OIDC variables warn without fetching', async () => {
  const s = setup(); await uploadRun({ ...s.options, env: {} }); expect(s.calls).toHaveLength(0);
  expect(s.warnings).toEqual(['Upload skipped: give the job `permissions: id-token: write`. Pull requests from forks cannot upload.']);
});
test('a head checkout cannot upload', async () => {
  const s = setup(); s.options.replay!.commit.sha = 'head'; await uploadRun(s.options); expect(s.calls).toHaveLength(0); expect(s.logs[0]).toContain('pull request head');
});
test('ref and SHA must match the merge checkout', async () => {
  const s = setup(); await uploadRun({ ...s.options, env: { ...s.options.env, GITHUB_SHA: 'other' } }); expect(s.calls).toHaveLength(0); expect(s.logs[0]).toContain('merge checkout');
});
test('insecure URLs are refused, localhost URLs are accepted', async () => {
  for (const url of ['http://example.com', 'ftp://localhost', 'https://user:pass@example.com']) { const s = setup(); await uploadRun({ ...s.options, url }); expect(s.calls).toHaveLength(0); expect(s.warnings[0]).toContain('HTTPS'); }
  for (const url of ['http://localhost:4321', 'http://127.0.0.1:4321']) { const s = setup(); await uploadRun({ ...s.options, url }); expect(s.calls).toHaveLength(2); }
});
test('network errors and 5xx retry once, 4xx do not retry; failures keep the passing exit code', async () => {
  for (const status of [0, 503, 400, 403]) {
    const s = setup([status, status]); expect(await uploadRun(s.options)).toBeUndefined();
    expect(s.calls).toHaveLength(status === 0 || status === 503 ? 3 : 2); expect(s.warnings).toHaveLength(1);
    expect(actionExitCode('pass', { advisory: false, strict: false })).toBe(0);
  }
  const s = setup([503, 200]); expect((await uploadRun(s.options))?.id).toBe('run-1');
});
test('another host exception URL is ignored', async () => {
  const s = setup(); const original = s.options.fetchFn!;
  s.options.fetchFn = (async (...args: Parameters<typeof fetch>) => { const r = await original(...args); return args[1]?.method ? Response.json({ ...await r.json() as object, exceptionUrl: 'https://evil.example/exception' }) : r; }) as typeof fetch;
  const response = await uploadRun(s.options); expect(response?.exceptionUrl).toBeUndefined(); expect(uploadComment('report\n---\nfooter', 'block', response)).not.toContain('Request an exception');
});
test('exception comment is inserted before the footer only on BLOCK', async () => {
  const s = setup(); const response = await uploadRun(s.options); const md = 'report\n\n---\nfooter';
  expect(uploadComment(md, 'pass', response)).toBe(md); expect(uploadComment(md, 'review', response)).toBe(md);
  const blocked = uploadComment(md, 'block', response); expect(blocked).toContain('An approver can accept these risks for this pull request: [Request an exception](https://api.terratrust.dev/a/org/exceptions/new).'); expect(blocked.indexOf('Request an exception')).toBeLessThan(blocked.indexOf('---'));
});
