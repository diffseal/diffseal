import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Read-only view of a repository at one point in time. Paths are POSIX, relative to the repository root.
 */
export interface FileSource {
  readonly label: string;
  /** Immutable object identity, available without reading its contents. */
  blobId?(relPath: string): string | undefined;
  readFile(relPath: string): string | undefined;
  /** File names (not paths) directly inside a directory. */
  listFiles(relDir: string): string[];
  /** Every file path in the snapshot. */
  allFiles(): string[];
}

export const normalize = (p: string) => path.posix.normalize(p).replace(/^\.\//, '').replace(/\/$/, '') || '.';

export class MemorySource implements FileSource {
  constructor(private readonly files: Record<string, string>, readonly label = 'memory') {}
  readFile(p: string) {
    return this.files[normalize(p)];
  }
  listFiles(dir: string) {
    const d = normalize(dir);
    return Object.keys(this.files)
      .filter((f) => path.posix.dirname(f) === d || (d === '.' && !f.includes('/')))
      .map((f) => path.posix.basename(f));
  }
  allFiles() {
    return Object.keys(this.files);
  }
}

const SKIP_DIRS = new Set(['.git', 'node_modules', '.terraform', '.claude', '.worktrees', 'vendor', '.venv', 'venv', 'dist', 'build']);

/** The working tree. Used by `terratrust scan` and local checks, never by historical replay. */
export class FsSource implements FileSource {
  readonly label: string;
  constructor(private readonly root: string) {
    this.label = root;
  }
  /** Reads regular files inside the root only: no `..`, no symlinks out, nothing huge or special. */
  readFile(p: string) {
    try {
      const rootReal = fs.realpathSync.native(this.root);
      const real = fs.realpathSync.native(path.resolve(this.root, p));
      if (real !== rootReal && !real.startsWith(rootReal + path.sep)) return undefined;
      const st = fs.statSync(real);
      if (!st.isFile() || st.size > 10 * 1024 * 1024) return undefined;
      return fs.readFileSync(real, 'utf8');
    } catch {
      return undefined;
    }
  }
  listFiles(dir: string) {
    try {
      return fs.readdirSync(path.join(this.root, dir), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name);
    } catch {
      return [];
    }
  }
  allFiles() {
    const out: string[] = [];
    const walk = (rel: string) => {
      for (const e of fs.readdirSync(path.join(this.root, rel), { withFileTypes: true })) {
        if (e.isDirectory()) {
          if (!SKIP_DIRS.has(e.name)) walk(rel === '.' ? e.name : `${rel}/${e.name}`);
        } else if (e.isFile()) out.push(rel === '.' ? e.name : `${rel}/${e.name}`);
      }
    };
    walk('.');
    return out;
  }
}

/**
 * A commit, read through git plumbing only: `rev-parse`, `ls-tree`, `cat-file --batch`, `diff`, `log`.
 * Nothing is checked out, no index or lock files are written, hooks and fsmonitor are disabled.
 */
export class GitSource implements FileSource {
  readonly label: string;
  readonly sha: string;
  private readonly blobs = new Map<string, string>();
  private readonly contents = new Map<string, string>();
  private readonly dirs = new Map<string, string[]>();

  constructor(private readonly repo: string, rev: string) {
    this.sha = resolveCommit(repo, rev);
    this.label = `${rev}@${this.sha.slice(0, 9)}`;
    const out = git(repo, ['ls-tree', '-r', '-z', '--full-tree', this.sha]);
    for (const entry of out.split('\0')) {
      if (!entry) continue;
      const tab = entry.indexOf('\t');
      const [, type, sha] = entry.slice(0, tab).split(' ');
      if (type !== 'blob') continue;
      const p = entry.slice(tab + 1);
      this.blobs.set(p, sha);
      const d = path.posix.dirname(p);
      const list = this.dirs.get(d) ?? [];
      list.push(path.posix.basename(p));
      this.dirs.set(d, list);
    }
  }

  blobId(p: string): string | undefined {
    return this.blobs.get(normalize(p));
  }

  readFile(p: string) {
    const key = normalize(p);
    if (this.contents.has(key)) return this.contents.get(key);
    if (!this.blobs.has(key)) return undefined;
    this.prefetch([key]);
    return this.contents.get(key);
  }

  /** Read many blobs in one `git cat-file --batch` call. */
  prefetch(paths: string[]) {
    const wanted = paths.map(normalize).filter((p) => this.blobs.has(p) && !this.contents.has(p));
    if (!wanted.length) return;
    const input = wanted.map((p) => this.blobs.get(p)).join('\n') + '\n';
    const res = spawnSync('git', ['-C', this.repo, ...SAFE_CONFIG, 'cat-file', '--batch'], {
      input,
      env: SAFE_ENV,
      maxBuffer: 1 << 30,
    });
    if (res.status !== 0) throw new Error(`git cat-file failed: ${res.stderr.toString()}`);
    const buf = res.stdout;
    let offset = 0;
    for (const p of wanted) {
      const nl = buf.indexOf(10, offset);
      const header = buf.subarray(offset, nl).toString();
      if (header.endsWith(' missing')) {
        offset = nl + 1;
        continue;
      }
      const size = Number(header.split(' ')[2]);
      this.contents.set(p, buf.subarray(nl + 1, nl + 1 + size).toString('utf8'));
      offset = nl + 1 + size + 1;
    }
  }

  listFiles(dir: string) {
    return this.dirs.get(normalize(dir)) ?? [];
  }

  allFiles() {
    return [...this.blobs.keys()];
  }
}

const SAFE_CONFIG = [
  '-c', 'core.fsmonitor=false',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'diff.external=',
  '-c', 'core.quotePath=false',
  '-c', 'log.showSignature=false',
  '-c', 'diff.noprefix=false',
  '--no-pager',
];
// GIT_NO_LAZY_FETCH: in a partial clone, never fetch missing objects from the remote (no network).
const SAFE_ENV = { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_NO_LAZY_FETCH: '1' };

export function git(repo: string, args: string[]): string {
  const res = spawnSync('git', ['-C', repo, ...SAFE_CONFIG, ...args], { env: SAFE_ENV, maxBuffer: 1 << 30, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`git ${args[0]} failed: ${res.stderr.trim()}`);
  return res.stdout;
}

export function resolveCommit(repo: string, rev: string): string {
  if (!rev || rev.startsWith('-')) throw new Error(`Refusing revision "${rev}"`);
  return git(repo, ['rev-parse', '--verify', '--end-of-options', `${rev}^{commit}`]).trim();
}

export interface ChangedPath {
  status: 'A' | 'M' | 'D' | 'R' | 'C' | 'T';
  path: string;
  oldPath?: string;
}

/** `git diff --name-status -M -z base head`, without external diff drivers or textconv. */
export function changedPaths(repo: string, base: string, head: string): ChangedPath[] {
  const out = git(repo, ['diff', '--name-status', '-M', '-z', '--no-ext-diff', '--no-textconv', base, head, '--']);
  const parts = out.split('\0').filter((x) => x !== '');
  const result: ChangedPath[] = [];
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++][0] as ChangedPath['status'];
    if (status === 'R' || status === 'C') {
      const oldPath = parts[i++];
      result.push({ status, oldPath, path: parts[i++] });
    } else {
      result.push({ status, path: parts[i++] });
    }
  }
  return result;
}

/** Unified diff of selected paths, used to scope app-code extraction to changed lines. */
export function unifiedDiff(repo: string, base: string, head: string, paths: string[]): string {
  if (!paths.length) return '';
  return git(repo, ['diff', '--no-ext-diff', '--no-textconv', '--no-color', '--src-prefix=a/', '--dst-prefix=b/', '-U0', base, head, '--', ...paths]);
}

/** Files changed between a commit and the working tree, plus untracked files (not ignored). */
export function worktreeChanges(repo: string, base: string): { changed: ChangedPath[]; untracked: string[] } {
  // --relative: paths relative to `repo`, which may be a subdirectory of the work tree (as FsSource reads it).
  const out = git(repo, ['diff', '--relative', '--name-status', '-M', '-z', '--no-ext-diff', '--no-textconv', base, '--']);
  const parts = out.split('\0').filter((x) => x !== '');
  const changed: ChangedPath[] = [];
  for (let i = 0; i < parts.length; ) {
    const status = parts[i++][0] as ChangedPath['status'];
    if (status === 'R' || status === 'C') {
      const oldPath = parts[i++];
      changed.push({ status, oldPath, path: parts[i++] });
    } else changed.push({ status, path: parts[i++] });
  }
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean);
  return { changed, untracked };
}

/** Unified diff of selected paths between a commit and the working tree. */
export function worktreeDiff(repo: string, base: string, paths: string[]): string {
  if (!paths.length) return '';
  return git(repo, ['diff', '--relative', '--no-ext-diff', '--no-textconv', '--no-color', '--src-prefix=a/', '--dst-prefix=b/', '-U0', base, '--', ...paths]);
}

export interface CommitInfo {
  sha: string;
  parents: string[];
  subject: string;
  author: string;
  date: string;
}

export function commitInfo(repo: string, rev: string): CommitInfo {
  const out = git(repo, ['log', '-1', '--no-show-signature', '--format=%H%x00%P%x00%s%x00%an%x00%aI', resolveCommit(repo, rev)]);
  const [sha, parents, subject, author, date] = out.trim().split('\0');
  return { sha, parents: parents ? parents.split(' ') : [], subject, author, date };
}
