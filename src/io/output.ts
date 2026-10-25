import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Real path of the deepest existing ancestor, so symlinks cannot smuggle a write into a protected tree. */
function realAncestor(p: string): string {
  let cur = path.resolve(p);
  const rest: string[] = [];
  while (!fs.existsSync(cur)) {
    rest.unshift(path.basename(cur));
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  // The native realpath returns the on-disk case, so `Repo` and `repo` compare equal where the
  // file system treats them as the same directory.
  return path.join(fs.realpathSync.native(cur), ...rest);
}

/** The given paths plus the git work tree each belongs to: git reads the whole repository. */
export function protectedRoots(paths: string[]): string[] {
  const out = new Set(paths.map((p) => path.resolve(p)));
  for (const p of paths) {
    const r = spawnSync('git', ['-C', p, 'rev-parse', '--show-toplevel'], { encoding: 'utf8', env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' } });
    if (r.status === 0 && r.stdout.trim()) out.add(r.stdout.trim());
  }
  return [...out];
}

/**
 * Refuse to write inside a repository being analyzed. Replay promises the target is never modified,
 * so this is enforced on every write rather than left to the caller.
 */
export function assertOutsideRepo(target: string, protectedRoots: string[]): void {
  const t = realAncestor(target);
  for (const root of protectedRoots) {
    const r = realAncestor(root);
    if (t === r || t.startsWith(r + path.sep)) {
      throw new Error(`Refusing to write ${target}: it is inside ${root}, which TerraTrust only reads.`);
    }
  }
}

export function writeOutput(target: string, content: string, protectedRoots: string[] = []): void {
  assertOutsideRepo(target, protectedRoots);
  fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
}
