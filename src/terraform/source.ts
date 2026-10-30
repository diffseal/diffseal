import { OfflineModules } from './moduleCache.js';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Read-only view of a repository at one point in time. Paths are POSIX, relative to the repository root.
 */
export interface FileSource {
  readonly label: string;
  allowsModulePath?(parent: string, child: string): boolean;
  resolveModule?(source: string, constraint?: string): string | undefined;
  /** Immutable object identity, available without reading its contents. */
  blobId?(relPath: string): string | undefined;
  readFile(relPath: string): string | undefined;
  /** File names (not paths) directly inside a directory. */
  listFiles(relDir: string): string[];
  /** Every file path in the snapshot. */
  allFiles(): string[];
  /** Why a path that exists cannot be read (a symbolic link Diffseal does not follow). */
  linkProblem?(relPath: string): string | undefined;
  /** Paths of symbolic links (or files reached through a linked directory) that resolve to this path. */
  linksTo?(relPath: string): string[];
  /** The repository path a symbolic link (or a file reached through a linked directory) resolves to. */
  linkTarget?(relPath: string): string | undefined;
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

/** The working tree. Used by `diffseal scan` and local checks, never by historical replay. */
export class FsSource implements FileSource {
  readonly label: string;
  private modules?: OfflineModules;
  allowsModulePath(parent: string, child: string): boolean { return this.modules?.allowsLocal(parent, child) ?? true; }
  resolveModule(source: string, constraint?: string): string | undefined {
    if (!this.moduleCache) return;
    return (this.modules ??= new OfflineModules(this, this.moduleCache)).resolve(source, constraint);
  }
  constructor(private readonly root: string, private readonly moduleCache?: string) {
    this.label = root;
  }
  /** Reads regular files inside the root only: no `..`, no symlinks out, nothing huge or special. */
  readFile(p: string) {
    if (this.modules?.owns(normalize(p))) return this.modules?.readFile(normalize(p));
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
    if (this.modules?.owns(normalize(dir))) return this.modules?.listFiles(normalize(dir)) ?? [];
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

  private modules?: OfflineModules;
  allowsModulePath(parent: string, child: string): boolean { return this.modules?.allowsLocal(parent, child) ?? true; }
  resolveModule(source: string, constraint?: string): string | undefined {
    if (!this.moduleCache) return;
    return (this.modules ??= new OfflineModules(this, this.moduleCache)).resolve(source, constraint);
  }
  constructor(private readonly repo: string, rev: string, private readonly moduleCache?: string) {
    this.sha = resolveCommit(repo, rev);
    this.label = `${rev}@${this.sha.slice(0, 9)}`;
    const out = git(repo, ['ls-tree', '-r', '-z', '--full-tree', this.sha]);
    const links = new Map<string, string>();
    for (const entry of out.split('\0')) {
      if (!entry) continue;
      const tab = entry.indexOf('\t');
      const [mode, type, sha] = entry.slice(0, tab).split(' ');
      if (type !== 'blob') continue;
      const p = entry.slice(tab + 1);
      if (mode === '120000') links.set(p, sha);
      else this.blobs.set(p, sha);
    }
    this.resolveLinks(links);
    for (const p of [...this.blobs.keys(), ...this.refused.keys()]) {
      const d = path.posix.dirname(p);
      const list = this.dirs.get(d) ?? [];
      list.push(path.posix.basename(p));
      this.dirs.set(d, list);
    }
  }

  /** Link path (or a path under a linked directory) -> the repository path it resolves to. */
  private readonly linkTargets = new Map<string, string>();
  /** Links that are not followed -> why. */
  private readonly refused = new Map<string, string>();

  /**
   * Symbolic links (git mode 120000) are followed the way a checkout would follow them, but only inside
   * the repository: the target path is resolved against the link's directory, through further links,
   * and must name a file or directory of the same commit. A file link reads its target's blob; a
   * directory link lists the target's files under the link's path. A link that leaves the repository,
   * or whose target is missing, is listed but not read, and says why.
   */
  private resolveLinks(links: Map<string, string>) {
    if (!links.size) return;
    const paths = [...links.keys()];
    const texts = this.catBlobs(paths.map((p) => links.get(p)!));
    const text = new Map(paths.map((p, i) => [p, texts[i] ?? '']));
    const files = [...this.blobs.keys()];
    const isDir = (d: string) => files.some((f) => f.startsWith(d + '/'));
    // Resolve a path whose components may pass through links, following at most 16 links in all.
    const resolve = (p: string): { path?: string; problem?: string } => {
      let cur = p;
      for (let hops = 0; hops <= 16; hops++) {
        const parts = cur.split('/');
        let hit: { at: number; target: string } | undefined;
        for (let i = 1; i <= parts.length; i++) {
          const prefix = parts.slice(0, i).join('/');
          if (text.has(prefix)) {
            hit = { at: i, target: text.get(prefix)! };
            break;
          }
        }
        if (!hit) return { path: cur };
        const linkDir = path.posix.dirname(parts.slice(0, hit.at).join('/'));
        const joined = path.posix.normalize(path.posix.join(linkDir, hit.target));
        if (hit.target.startsWith('/') || joined === '..' || joined.startsWith('../')) return { problem: 'it leaves the repository' };
        cur = [joined, ...parts.slice(hit.at)].filter((x) => x !== '' && x !== '.').join('/') || '.';
      }
      return { problem: 'it is a chain of more than 16 links' };
    };
    let added = 0;
    for (const link of paths) {
      const label = `symbolic link to ${text.get(link)} is not followed`;
      const r = resolve(link);
      if (!r.path) {
        this.refused.set(link, `${label}: ${r.problem}`);
        continue;
      }
      const sha = this.blobs.get(r.path);
      if (sha) {
        this.blobs.set(link, sha);
        this.linkTargets.set(link, r.path);
        continue;
      }
      if (r.path !== '.' && isDir(r.path)) {
        for (const f of files) {
          if (!f.startsWith(r.path + '/') || added >= 20_000) continue;
          const alias = link + f.slice(r.path.length);
          if (this.blobs.has(alias)) continue;
          this.blobs.set(alias, this.blobs.get(f)!);
          this.linkTargets.set(alias, f);
          added++;
        }
        continue;
      }
      this.refused.set(link, `${label}: its target is not in the repository at this commit`);
    }
  }

  linkProblem(p: string): string | undefined {
    return this.refused.get(normalize(p));
  }

  linkTarget(p: string): string | undefined {
    return this.linkTargets.get(normalize(p));
  }

  linksTo(p: string): string[] {
    const target = normalize(p);
    return [...this.linkTargets].filter(([, t]) => t === target).map(([l]) => l);
  }

  /** Contents of blobs by id, in order, with one `git cat-file --batch` call. */
  private catBlobs(shas: string[]): Array<string | undefined> {
    const res = spawnSync('git', ['-C', this.repo, ...SAFE_CONFIG, 'cat-file', '--batch'], { input: shas.join('\n') + '\n', env: SAFE_ENV, maxBuffer: 1 << 30 });
    if (res.status !== 0) throw new Error(`git cat-file failed: ${res.stderr.toString()}`);
    const buf = res.stdout;
    const out: Array<string | undefined> = [];
    let offset = 0;
    for (let i = 0; i < shas.length; i++) {
      const nl = buf.indexOf(10, offset);
      const header = buf.subarray(offset, nl).toString();
      if (header.endsWith(' missing')) {
        out.push(undefined);
        offset = nl + 1;
        continue;
      }
      const size = Number(header.split(' ')[2]);
      out.push(buf.subarray(nl + 1, nl + 1 + size).toString('utf8'));
      offset = nl + 1 + size + 1;
    }
    return out;
  }

  blobId(p: string): string | undefined {
    return this.blobs.get(normalize(p));
  }

  readFile(p: string) {
    const key = normalize(p);
    if (this.modules?.owns(key)) return this.modules?.readFile(key);
    if (this.contents.has(key)) return this.contents.get(key);
    if (!this.blobs.has(key)) return undefined;
    this.prefetch([key]);
    return this.contents.get(key);
  }

  /** Read many blobs in one `git cat-file --batch` call. */
  prefetch(paths: string[]) {
    const wanted = paths.map(normalize).filter((p) => this.blobs.has(p) && !this.contents.has(p));
    if (!wanted.length) return;
    const texts = this.catBlobs(wanted.map((p) => this.blobs.get(p)!));
    wanted.forEach((p, i) => {
      if (texts[i] !== undefined) this.contents.set(p, texts[i]!);
    });
  }

  listFiles(dir: string) {
    if (this.modules?.owns(normalize(dir))) return this.modules?.listFiles(normalize(dir)) ?? [];
    return this.dirs.get(normalize(dir)) ?? [];
  }

  allFiles() {
    return [...this.blobs.keys(), ...this.refused.keys()];
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
