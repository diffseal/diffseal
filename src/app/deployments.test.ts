import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { LinkStatus } from '../reconcile/reconcile.js';
import { checkApp } from './checkApp.js';
const cases = JSON.parse(
  fs.readFileSync(path.resolve(import.meta.dirname, '../../fixtures/compute/deployments.fixture'), 'utf8'),
).cases as Array<{
  name: string;
  files: Record<string, string>;
  expect: { statuses: LinkStatus[]; role?: string; notes?: string; entries?: string[] };
}>;
for (const c of cases)
  test(c.name, async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-deploy-'));
    try {
      for (const [file, text] of Object.entries(c.files)) {
        const p = path.join(repo, file);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, text);
      }
      const r = await checkApp({ app: repo, worktree: true, entries: c.expect.entries });
      expect(r.links.map((l) => l.status)).toEqual(c.expect.statuses);
      if (c.expect.role) expect(r.links[0].role).toBe(c.expect.role);
      if (c.expect.notes) expect(r.notes.join('\n')).toContain(c.expect.notes);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

test('PR replay uses the same Pod Identity deployment binding', async () => {
  const { spawnSync } = await import('node:child_process');
  const { replayCommit } = await import('../replay/replay.js');
  const c = cases[1];
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-deploy-replay-'));
  const git = (args: string[]) => {
    const r = spawnSync(
      'git',
      [
        '-C',
        repo,
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'user.name=Test',
        '-c',
        'user.email=test@example.invalid',
        ...args,
      ],
      { encoding: 'utf8' },
    );
    if (r.status) throw new Error(r.stderr);
  };
  try {
    git(['init', '-q']);
    for (const [file, text] of Object.entries(c.files)) {
      const p = path.join(repo, file);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, text);
    }
    fs.writeFileSync(path.join(repo, 'cmd/orders/main.go'), 'package main\nfunc main() {}\n');
    git(['add', '.']);
    git(['commit', '-qm', 'base']);
    fs.writeFileSync(path.join(repo, 'cmd/orders/main.go'), c.files['cmd/orders/main.go']);
    git(['add', '.']);
    git(['commit', '-qm', 'call']);
    expect((await replayCommit({ repo, head: 'HEAD' })).appLinks.map((l) => l.status)).toEqual(['GRANTED']);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});
