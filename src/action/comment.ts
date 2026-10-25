/** The single PR comment the Action keeps up to date. */

export const MARKER = '<!-- terratrust-report -->';

export interface CommentTarget {
  api: string;
  repo: string;
  pr: number;
  token: string;
  /** Only a comment by this login is updated; anyone can write the marker into their own comment. */
  author: string;
  /** When true, update an existing report comment if one is present, and do not post a new one. */
  onlyUpdate?: boolean;
  fetchFn?: typeof fetch;
}

export async function upsertComment(body: string, t: CommentTarget): Promise<void> {
  const f = t.fetchFn ?? fetch;
  const headers = {
    authorization: `Bearer ${t.token}`,
    accept: 'application/vnd.github+json',
    'content-type': 'application/json',
    'user-agent': 'terratrust-action',
  };
  let existing: { id: number } | undefined;
  for (let page = 1; page <= 50 && !existing; page++) {
    const res = await f(`${t.api}/repos/${t.repo}/issues/${t.pr}/comments?per_page=100&page=${page}`, { headers });
    if (!res.ok) throw new Error(`listing PR comments failed: ${res.status}`);
    const batch = (await res.json()) as Array<{ id: number; body?: string; user?: { login?: string } }>;
    existing = batch.find((c) => c.body?.includes(MARKER) && c.user?.login === t.author);
    if (batch.length < 100) break;
  }
  const payload = JSON.stringify({ body: `${MARKER}\n${body}` });
  if (existing) {
    const res = await f(`${t.api}/repos/${t.repo}/issues/comments/${existing.id}`, { method: 'PATCH', headers, body: payload });
    if (res.ok) return;
  }
  if (t.onlyUpdate) return;
  const res = await f(`${t.api}/repos/${t.repo}/issues/${t.pr}/comments`, { method: 'POST', headers, body: payload });
  if (!res.ok) throw new Error(`writing the PR comment failed: ${res.status}`);
}
