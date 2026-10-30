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
  /** The directory a path reaches through a linked directory, when it passes through one. */
  linkedDir?(relDir: string): string | undefined;
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
  /** Link path (or a path under a linked directory) -> the links its resolution passes through. */
  private readonly linkVia = new Map<string, string[]>();
  private readonly bySha = new Map<string, string>();
  /** Path a link resolves to, or a link on the way -> the link paths (and aliases) reading it. */
  private readers?: Map<string, string[]>;
  /** Directory link -> the directory it resolves to. */
  private readonly dirLinks = new Map<string, string>();
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
    // A directory may hold only links.
    const isDir = (d: string) => files.some((f) => f.startsWith(d + '/')) || paths.some((l) => l.startsWith(d + '/'));
    // Resolve a path one component at a time, as the operating system does: a link is followed where it
    // is met, before any later `..` applies. At most 16 links in all.
    const resolve = (p: string): { path?: string; problem?: string; via: string[] } => {
      const via: string[] = [];
      const stack: string[] = [];
      const queue = p.split('/');
      let hops = 0;
      while (queue.length) {
        const c = queue.shift()!;
        if (c === '' || c === '.') continue;
        if (c === '..') {
          if (!stack.length) return { problem: 'it leaves the repository', via };
          stack.pop();
          continue;
        }
        stack.push(c);
        const target = text.get(stack.join('/'));
        if (target === undefined) continue;
        via.push(stack.join('/'));
        if (++hops > 16) return { problem: 'it is a chain of more than 16 links', via };
        if (target.startsWith('/')) return { problem: 'it leaves the repository', via };
        stack.pop();
        queue.unshift(...target.split('/'));
      }
      return { path: stack.join('/') || '.', via };
    };
    // File links first, so a linked directory also shows the file links inside it.
    const resolved = new Map(paths.map((link) => [link, resolve(link)]));
    const dirLinks: Array<[string, string]> = [];
    for (const link of paths) {
      const label = `symbolic link to ${text.get(link)} is not followed`;
      const r = resolved.get(link)!;
      if (!r.path) {
        this.refused.set(link, `${label}: ${r.problem}`);
        continue;
      }
      const sha = this.blobs.get(r.path);
      if (sha) {
        this.blobs.set(link, sha);
        this.linkTargets.set(link, this.linkTargets.get(r.path) ?? r.path);
        this.linkVia.set(link, r.via);
        continue;
      }
      if (r.path === '.') this.refused.set(link, `${label}: it points at the repository root`);
      else if (isDir(r.path)) dirLinks.push([link, r.path]);
      else this.refused.set(link, `${label}: its target is not in the repository at this commit`);
    }
    // Directory links, in passes, so a directory link inside a linked directory is expanded under the
    // outer link too. Bounded: at most 20,000 files and 2,000 directory aliases in all, and 4 passes.
    let added = 0;
    let aliasDirs = 0;
    const done = new Set<string>();
    // Each entry: alias path, the directory it shows, and the links its resolution passes through.
    let pending: Array<[string, string, string[]]> = dirLinks.map(([link, dir]) => [link, dir, resolved.get(link)?.via ?? [link]]);
    for (let pass = 0; pass < 4 && pending.length; pass++) {
      const all = [...this.blobs.keys()];
      const allRefused = [...this.refused];
      const next: Array<[string, string, string[]]> = [];
      for (const [link, dir, via] of pending) {
        if (done.has(link)) continue;
        done.add(link);
        // A link inside the directory it points at would show itself without end.
        if (link.startsWith(dir + '/')) {
          this.refused.set(link, `symbolic link to ${text.get(link) ?? dir} is not followed: it points at a directory that contains it`);
          continue;
        }
        const under = all.filter((f) => f.startsWith(dir + '/'));
        if (added + under.length > 20_000 || ++aliasDirs > 2_000) {
          this.refused.set(link, `symbolic link to ${text.get(link) ?? dir} is not followed: its directory holds too many files`);
          continue;
        }
        this.dirLinks.set(link, dir);
        // A link inside the target that is not followed is not followed under the alias either.
        for (const [f, why] of allRefused) if (f.startsWith(dir + '/') && !this.refused.has(link + f.slice(dir.length))) this.refused.set(link + f.slice(dir.length), why);
        for (const f of under) {
          const alias = link + f.slice(dir.length);
          if (this.blobs.has(alias)) continue;
          this.blobs.set(alias, this.blobs.get(f)!);
          this.linkTargets.set(alias, this.linkTargets.get(f) ?? f);
          this.linkVia.set(alias, [...via, ...(this.linkVia.get(f) ?? [])]);
          added++;
        }
        // Directory links inside this target appear under the alias in the next pass.
        for (const [inner, innerDir] of dirLinks) {
          if (inner.startsWith(dir + '/')) next.push([link + inner.slice(dir.length), innerDir, [...via, ...(resolved.get(inner)?.via ?? [inner])]]);
        }
      }
      pending = next;
    }
  }

  linkProblem(p: string): string | undefined {
    return this.refused.get(normalize(p));
  }

  linkedDir(dir: string): string | undefined {
    const d = normalize(dir);
    // The deepest link wins: `alias/inner` reaches what `alias/inner` links to, not `tree/inner`.
    let best: [string, string] | undefined;
    for (const [link, target] of this.dirLinks) if ((d === link || d.startsWith(link + '/')) && (!best || link.length > best[0].length)) best = [link, target];
    return best ? best[1] + d.slice(best[0].length) : undefined;
  }

  linkTarget(p: string): string | undefined {
    return this.linkTargets.get(normalize(p));
  }

  linksTo(p: string): string[] {
    const target = normalize(p);
    // A path reads `target` when it resolves to it, or when its resolution passes through the link `target`.
    if (!this.readers) {
      this.readers = new Map();
      for (const [l, t] of this.linkTargets) {
        for (const k of new Set([t, ...(this.linkVia.get(l) ?? [])])) {
          const list = this.readers.get(k) ?? [];
          list.push(l);
          this.readers.set(k, list);
        }
      }
    }
    return this.readers.get(target) ?? [];
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
    // Contents are kept by blob id too, so a file seen through several links is read from git once.
    const wanted = paths.map(normalize).filter((p) => this.blobs.has(p) && !this.contents.has(p));
    for (const p of wanted) {
      const known = this.bySha.get(this.blobs.get(p)!);
      if (known !== undefined) this.contents.set(p, known);
    }
    const missing = [...new Set(wanted.filter((p) => !this.contents.has(p)).map((p) => this.blobs.get(p)!))];
    if (!missing.length) return;
    const texts = this.catBlobs(missing);
    missing.forEach((sha, i) => {
      if (texts[i] !== undefined) this.bySha.set(sha, texts[i]!);
    });
    for (const p of wanted) {
      const text = this.bySha.get(this.blobs.get(p)!);
      if (text !== undefined) this.contents.set(p, text);
    }
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
