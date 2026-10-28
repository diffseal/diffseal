import { changeRecord, type ChangeRecord } from '../evidence/changeRecord.js';
import type { ReplayResult } from '../replay/replay.js';
import { VERSION } from '../replay/render.js';
import { REPLACE_CATALOG_SOURCE } from '../terraform/replaceCatalog.js';

/** Contract v1, section 2. Only the scrubbed change record leaves CI. */
export interface RunUpload {
  schema: 'terratrust.run/v1';
  event: 'pull_request' | 'push';
  commit: string;
  pullRequest?: { number: number; headSha: string; baseSha: string };
  action: { version: string; mode: 'pr'; advisory: boolean };
  record: ChangeRecord;
}
export interface RunUploadResponse { id: string; pageUrl: string; exceptionUrl?: string; stale?: boolean }
export interface UploadOptions {
  upload?: string;
  mode: string;
  eventName?: string;
  event?: unknown;
  url?: string;
  advisory: boolean;
  replay?: ReplayResult;
  env?: NodeJS.ProcessEnv;
  fetchFn?: typeof fetch;
  log?: (message: string) => void;
  warn?: (message: string) => void;
}

function uploadUrl(text: string): URL {
  const url = new URL(text);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) || url.username || url.password || url.search || url.hash) {
    throw new Error('upload-url must use HTTPS (HTTP is allowed only for localhost tests), without credentials, query or fragment');
  }
  return url;
}

/** All failures are advisory. Injectable fetch keeps tests offline. */
export async function uploadRun(o: UploadOptions): Promise<RunUploadResponse | undefined> {
  const log = o.log ?? console.log, warn = o.warn ?? console.warn;
  if (o.upload !== 'true') { log('Upload skipped: upload is not true.'); return; }
  if (o.mode !== 'pr') { log('Upload skipped: only pr mode can upload.'); return; }
  if (o.eventName !== 'pull_request' && o.eventName !== 'push') { log(`Upload skipped: event ${o.eventName ?? '(unknown)'} is not pull_request or push.`); return; }
  try {
    const endpoint = uploadUrl(o.url ?? 'https://api.terratrust.dev');
    const env = o.env ?? process.env;
    if (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
      warn('Upload skipped: give the job `permissions: id-token: write`. Pull requests from forks cannot upload.'); return;
    }
    const r = o.replay;
    if (!r) throw new Error('replay result is unavailable');
    const payload = o.event as { number?: number; pull_request?: { number?: number; head?: { sha?: string }; base?: { sha?: string } } };
    let pullRequest: RunUpload['pullRequest'];
    if (o.eventName === 'pull_request') {
      const pr = payload?.pull_request;
      const number = payload?.number ?? pr?.number;
      if (!number || !pr?.head?.sha || !pr.base?.sha) throw new Error('pull request payload is missing number, head.sha or base.sha');
      if (r.commit.sha === pr.head.sha) { log('Upload skipped: HEAD is the pull request head. Use the default refs/pull/N/merge checkout.'); return; }
      if (env.GITHUB_REF !== `refs/pull/${number}/merge` || (env.GITHUB_SHA && env.GITHUB_SHA !== r.commit.sha)) {
        log('Upload skipped: HEAD must match the default pull request merge checkout and GITHUB_SHA.'); return;
      }
      pullRequest = { number, headSha: pr.head.sha, baseSha: pr.base.sha };
    }
    const record = changeRecord({ commit: r.commit, base: r.base, roots: r.roots.map((root) => root.root), result: r.combined, appLinks: r.appLinks, engine: { version: VERSION, replaceCatalog: REPLACE_CATALOG_SOURCE }, diagnostics: r.roots.flatMap((root) => root.diagnostics) });
    record.notes = record.notes.filter((note) => !note.startsWith('No approvals were supplied'));
    const body: RunUpload = { schema: 'terratrust.run/v1', event: o.eventName, commit: r.commit.sha, ...(pullRequest ? { pullRequest } : {}), action: { version: VERSION, mode: 'pr', advisory: o.advisory }, record };
    const serialized = JSON.stringify(body);
    if (Buffer.byteLength(serialized) > 1024 * 1024) throw new Error('change record exceeds the 1 MiB upload limit');
    const f = o.fetchFn ?? fetch;
    const tokenUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
    tokenUrl.searchParams.set('audience', 'terratrust');
    for (let attempt = 0; attempt < 2; attempt++) {
      // The service consumes each OIDC jti before idempotency, even if a response is lost.
      const tokenResponse = await f(tokenUrl.toString(), { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }, signal: AbortSignal.timeout(15_000) });
      if (!tokenResponse.ok) throw new Error(`OIDC token request failed (${tokenResponse.status})`);
      const token = await tokenResponse.json() as { value?: string };
      if (typeof token.value !== 'string' || !token.value) throw new Error('OIDC token response has no token');
      let response: Response;
      try {
        response = await f(new URL('v1/runs', endpoint.href.endsWith('/') ? endpoint : `${endpoint.href}/`).toString(), { method: 'POST', headers: { authorization: `Bearer ${token.value}`, 'content-type': 'application/json' }, body: serialized, signal: AbortSignal.timeout(15_000), redirect: 'error' });
      } catch {
        if (attempt === 0) continue;
        throw new Error('upload network request failed or timed out');
      }
      if (response.status >= 500 && attempt === 0) continue;
      if (!response.ok) throw new Error(`upload failed (${response.status})${await serviceReason(response)}`);
      const result = await response.json() as RunUploadResponse;
      if (!result || typeof result.id !== 'string' || !result.id || /[\r\n]/.test(result.id) || typeof result.pageUrl !== 'string' || (result.exceptionUrl !== undefined && typeof result.exceptionUrl !== 'string')) throw new Error('invalid upload response');
      if (result.stale === true) {
        delete result.exceptionUrl;
        warn('TerraTrust stored this record as stale: the pull request or its base branch changed after this run started, so the TerraTrust evidence check was not updated. Push a commit to refresh it. Re-running this job does not help, because GitHub reuses the original event.');
      } else delete result.stale;
      if (result.exceptionUrl) {
        try {
          const exception = new URL(result.exceptionUrl);
          if (exception.host !== endpoint.host || exception.protocol !== endpoint.protocol || exception.username || exception.password) delete result.exceptionUrl;
          else result.exceptionUrl = exception.href;
        } catch { delete result.exceptionUrl; }
      }
      return result;
    }
  } catch (e) { warn(`Upload skipped: ${(e as Error).message}`); }
}

/** The service's error and field path as one short line, or nothing when the body is not the documented error shape. */
async function serviceReason(response: Response): Promise<string> {
  try {
    const body = await response.json() as { error?: unknown; path?: unknown };
    if (typeof body?.error !== 'string') return '';
    const reason = `${body.error}${typeof body.path === 'string' ? ` (${body.path})` : ''}`.replace(/[\x00-\x1f\x7f]+/g, ' ');
    return `: ${reason.slice(0, 200)}`;
  } catch { return ''; }
}

export function uploadComment(markdown: string, gate: string, response?: RunUploadResponse): string {
  if (gate !== 'block' || !response?.exceptionUrl) return markdown;
  const url = response.exceptionUrl.replace(/\(/g, '%28').replace(/\)/g, '%29');
  const line = `An approver can accept these risks for this pull request: [Request an exception](${url}).`;
  const footer = markdown.lastIndexOf('\n---');
  return footer < 0 ? `${markdown}\n\n${line}\n` : `${markdown.slice(0, footer)}\n${line}\n${markdown.slice(footer)}`;
}
