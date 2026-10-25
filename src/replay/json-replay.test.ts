import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { replayCommit } from './replay.js';
for (const broken of [false, true])
  test(`JSON-only configuration edits are ${broken ? 'reviewed when malformed' : 'evaluated without an uncovered-file warning'}`, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-json-replay-'));
    const git = (args: string[]) => {
      const r = spawnSync(
        'git',
        [
          '-C',
          dir,
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
    const value = (input: number) => JSON.stringify({ resource: { terraform_data: { example: { input } } } });
    try {
      git(['init', '-q']);
      fs.writeFileSync(path.join(dir, 'main.tf.json'), value(1));
      git(['add', '.']);
      git(['commit', '-qm', 'base']);
      fs.writeFileSync(path.join(dir, 'main.tf.json'), broken ? '{"resource": {' : value(2));
      git(['add', '.']);
      git(['commit', '-qm', 'head']);
      const result = replayCommit({ repo: dir, head: 'HEAD' });
      expect(result.combined.gate.result).toBe(broken ? 'review' : 'pass');
      if (!broken) {
        expect(result.combined.changes).toHaveLength(1);
        expect(result.roots[0].root).toBe('.');
      } else expect(result.roots[0].diagnostics.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
