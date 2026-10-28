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
    return Response.json({ id: 'run-1', pageUrl: 'https://api.diffseal.com/a/org/runs/run-1', exceptionUrl: 'https://api.diffseal.com/a/org/exceptions/new' }, { status });
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
    expect(s.calls[0].url).toBe('https://token.example/token?other=1&audience=diffseal');
    expect(s.calls[0].init?.headers).toEqual({ authorization: 'Bearer request-token' });
    expect(s.calls[1].url).toBe('https://api.diffseal.com/v1/runs');
    expect(s.calls[1].init?.signal).toBeInstanceOf(AbortSignal);
    expect(s.calls[1].init?.headers).toEqual({ authorization: 'Bearer oidc-token', 'content-type': 'application/json' });
    const body = JSON.parse(String(s.calls[1].init?.body)) as RunUpload;
    expect(body).toMatchObject({ schema: 'diffseal.run/v1', event: eventName, commit: 'merge', action: { mode: 'pr', advisory: true }, record: { change: { commit: 'merge' }, approvals: null, gate: { items: [], reasons: [], result: 'pass' } } });
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
    expect(s.calls).toHaveLength(status === 0 || status === 503 ? 4 : 2); expect(s.warnings).toHaveLength(1);
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
  const blocked = uploadComment(md, 'block', response); expect(blocked).toContain('An approver can accept these risks for this pull request: [Request an exception](https://api.diffseal.com/a/org/exceptions/new).'); expect(blocked.indexOf('Request an exception')).toBeLessThan(blocked.indexOf('---'));
});

test('the Action job keeps its passing exit code when upload fails', async () => {
  const fs = await import('node:fs'), path = await import('node:path'), os = await import('node:os');
  const { spawnSync } = await import('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-upload-job-'));
  try {
    const git = (...args: string[]) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' });
      if (r.status) throw new Error(r.stderr);
    };
    git('init', '-q'); git('commit', '--allow-empty', '-qm', 'base'); git('commit', '--allow-empty', '-qm', 'head');
    fs.writeFileSync(path.join(dir, 'event.json'), '{}');
    const r = spawnSync('node', ['--import', 'data:text/javascript,globalThis.fetch=async(url,init)=>{if(!init.method)return Response.json({value:"oidc"});throw new Error("offline upload failure")}', path.resolve(import.meta.dirname, '../../dist/action.js')], { cwd: dir, encoding: 'utf8', env: { ...process.env, INPUT_MODE: 'pr', INPUT_UPLOAD: 'true', INPUT_COMMENT: 'false', GITHUB_WORKSPACE: dir, GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_EVENT_NAME: 'push', GITHUB_OUTPUT: path.join(dir, 'outputs'), ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example/token', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token' } });
    expect(r.status).toBe(0); expect(r.stderr).toContain('upload network request failed');
    expect(fs.readFileSync(path.join(dir, 'outputs'), 'utf8')).toBe('gate=pass\n');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

for (const firstFailure of ['500', 'network']) {
  test(`upload retries ${firstFailure} with a fresh single-use token and identical body bytes`, async () => {
    const s = setup();
    const consumed = new Set<string>(), bodies: string[] = [], tokens: string[] = [];
    let issued = 0;
    s.options.fetchFn = (async (_url, init) => {
      if (!init?.method) return Response.json({ value: `single-use-${++issued}` });
      const token = new Headers(init.headers).get('authorization')!;
      bodies.push(String(init.body)); tokens.push(token);
      if (consumed.has(token)) return Response.json({ error: 'token already used' }, { status: 401 });
      consumed.add(token);
      if (bodies.length === 1) {
        if (firstFailure === 'network') throw new Error('response lost after token consumption');
        return Response.json({ error: 'temporary server error' }, { status: 500 });
      }
      return Response.json({ id: 'retried-run', pageUrl: 'https://api.diffseal.com/retried-run' }, { status: 201 });
    }) as typeof fetch;
    const response = await uploadRun(s.options);
    expect(response?.id).toBe('retried-run');
    expect(issued).toBe(2); expect(new Set(tokens).size).toBe(2);
    expect(bodies).toHaveLength(2); expect(bodies[1] === bodies[0]).toBe(true);
    expect(s.warnings).toHaveLength(0);
  });
}
test('a rejected upload shows the service reason on one short line', async () => {
  const bodies: Array<[BodyInit, string]> = [
    [JSON.stringify({ error: 'Invalid field', path: 'pullRequest.headSha' }), 'Upload skipped: upload failed (400): Invalid field (pullRequest.headSha)'],
    [JSON.stringify({ error: `line one\nline two ${'x'.repeat(300)}` }), 'Upload skipped: upload failed (400): line one line two '],
    ['not json', 'Upload skipped: upload failed (400)'],
    [JSON.stringify({ error: '##[set-output name=upload-id;]x ::add-mask::y', path: '::stop-commands::z' }), 'Upload skipped: upload failed (400): set-output name upload-id x add-mask y (stop-commands z)'],
  ];
  for (const [body, expected] of bodies) {
    const s = setup(); const original = s.options.fetchFn!;
    s.options.fetchFn = (async (...args: Parameters<typeof fetch>) => args[1]?.method ? new Response(body, { status: 400 }) : original(...args)) as typeof fetch;
    expect(await uploadRun(s.options)).toBeUndefined();
    expect(s.warnings[0]!.startsWith(expected)).toBe(true);
    expect(s.warnings[0]).not.toContain('\n');
    expect(s.warnings[0]).not.toMatch(/##|::|\[/);
    expect(s.warnings[0]!.length).toBeLessThanOrEqual(260);
  }
});
test('a stale upload says how to refresh and offers no exception link', async () => {
  const s = setup(); const original = s.options.fetchFn!;
  s.options.fetchFn = (async (...args: Parameters<typeof fetch>) => { const r = await original(...args); return args[1]?.method ? Response.json({ ...await r.json() as object, stale: true }, { status: 201 }) : r; }) as typeof fetch;
  const response = await uploadRun(s.options);
  expect(response?.stale).toBe(true);
  expect(response?.exceptionUrl).toBeUndefined();
  expect(s.warnings).toEqual(['Diffseal stored this record as stale: the pull request or its base branch changed after this run started, so the Diffseal evidence check was not updated. Push a commit to refresh it. Re-running this job does not help, because GitHub reuses the original event.']);
});
