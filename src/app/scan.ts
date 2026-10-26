import { extractManaged, envReadsManaged } from './managed.js';
import { ExtractionCache, extractionCache, fileIdentity } from './cache.js';
import { languageForFile, prepareLanguages } from './parser.js';
import { clearSyntax } from './syntax.js';
import * as path from 'node:path';
import type { FileSource } from '../terraform/source.js';
import type { AccessFact, AddedLines, AppScan, EnvRead } from './facts.js';
import { GoIndex, envReadsGo, extractGo, parseImports, type SourceFile } from './go.js';
import { envReadsPython, extractPython } from './python.js';
import { envReadsTs, extractTs } from './typescript.js';

const SKIP =
  /(^|\/)(\.git|\.claude|\.worktrees|node_modules|vendor|testdata|gen|dist|build|\.venv|venv|__pycache__|site-packages|\.terraform|coverage)\//;
const TEST = /(_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|(^|\/)test_[^/]*\.py|_test\.py)$/;

export function isAppFile(p: string): boolean {
  if (/\.(java|kt|cs)$/.test(p) && (/(^|\/)(test|tests|target|bin|obj)\//.test(p) || /(?:Tests?|Spec)\.(java|kt|cs)$/.test(p))) return false;
  return /\.(go|ts|tsx|js|mjs|cjs|py|java|kt|cs)$/.test(p) && !SKIP.test(p) && !TEST.test(p) && !p.endsWith('.d.ts');
}

export interface ScanResult extends AppScan {
  /** Env vars read anywhere in each scanned file's directory (package), for finding the compute. */
  fileEnv: Map<string, string[]>;
}

/**
 * Extract AWS access facts and env reads from an application snapshot. With `addedLines`, only calls
 * and reads on added lines count; the whole snapshot is still read to resolve helpers and packages.
 */
export async function scanApp(
  source: FileSource,
  opts: { addedLines?: AddedLines; entries?: string[]; cache?: ExtractionCache } = {},
): Promise<ScanResult> {
  const cache = opts.cache ?? extractionCache;
  const read = (p: string, asPath = p): SourceFile => ({
    path: asPath,
    blobId: source.blobId?.(p),
    get content() {
      return source.readFile(p) ?? '';
    },
  });
  const identities = new Map<string, string>();
  const identity = (p: string): string => {
    let id = identities.get(p);
    if (!id) {
      id = fileIdentity(read(p));
      identities.set(p, id);
    }
    return id;
  };
  const prefetch = (paths: string[]) => {
    if ('prefetch' in source && typeof source.prefetch === 'function') source.prefetch(paths);
  };
  const lineKey = (p: string) => (opts.addedLines ? [...(opts.addedLines.get(p) ?? [])].sort((a, b) => a - b) : null);
  const all = source.allFiles().filter(isAppFile);
  let wanted = opts.addedLines ? all.filter((p) => opts.addedLines!.has(p)) : all;
  if (opts.entries?.length) {
    await prepareLanguages(all.some((p) => p.endsWith('.go') && opts.entries!.some((entry) => path.posix.dirname(p) === path.posix.normalize(entry))) ? ['go'] : []);
    const closure = entryClosure(source, all, opts.entries, cache);
    wanted = wanted.filter(
      (p) =>
        closure.has(path.posix.dirname(p)) ||
        opts.entries!.some((e) => p.startsWith(e.replace(/\/$/, '') + '/') && !p.endsWith('.go')),
    );
  }
  await prepareLanguages(wanted.map(languageForFile));
  const goAll = all.filter((p) => p.endsWith('.go'));
  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];

  // Go: one helper index per module (nearest go.mod).
  const modules = source
    .allFiles()
    .filter((p) => p === 'go.mod' || p.endsWith('/go.mod'))
    .map((p) => path.posix.dirname(p));
  const moduleOf = (p: string) =>
    modules.filter((m) => m === '.' || p.startsWith(m + '/')).sort((a, b) => b.length - a.length)[0];
  for (const modDir of modules) {
    const inModule = goAll.filter((p) => moduleOf(p) === modDir);
    const targets = inModule.filter((p) => wanted.includes(p));
    if (!targets.length) continue;
    const modulePath = (source.readFile(modDir === '.' ? 'go.mod' : `${modDir}/go.mod`) ?? '').match(
      /^module\s+(\S+)/m,
    )?.[1];
    if (!modulePath) continue;
    const rel = (p: string) => (modDir === '.' ? p : p.slice(modDir.length + 1));
    const pkg = (p: string) =>
      path.posix.dirname(rel(p)) === '.' ? modulePath : modulePath + '/' + path.posix.dirname(rel(p));
    prefetch(inModule.filter((p) => !cache.has('go-index', identity(p), [modulePath, pkg(p)])));
    const index = new GoIndex(
      modulePath,
      inModule.map((p) => read(p, rel(p))),
      cache,
    );
    const context = (p: string) => [p, modDir, index.cacheKey, lineKey(p)];
    prefetch(targets.filter((p) => !cache.has('go-facts', identity(p), context(p))));
    const scans = targets.map((p) =>
      cache.memo('go-facts', identity(p), context(p), () =>
        extractGo([read(p)], { index, addedLines: opts.addedLines, moduleDir: modDir }),
      ),
    );
    const r = { facts: scans.flatMap((s) => s.facts), envReads: scans.flatMap((s) => s.envReads) };
    // A helper's own call on its parameter is redundant when its callers were scanned: they name the resource.
    const helperPackages = new Set(r.facts.flatMap((f) => (f.viaPackage ? [f.viaPackage] : [])));
    facts.push(...r.facts.filter((f) => !(f.internal && helperPackages.has(index.packageOf(rel(f.file))))));
    envReads.push(...r.envReads);
  }

  for (const p of [
    ...wanted.filter((p) => !p.endsWith('.go') && !p.endsWith('.py')),
    ...wanted.filter((p) => p.endsWith('.py')),
  ]) {
    const kind = p.endsWith('.py') ? 'python' : /\.(java|kt|cs)$/.test(p) ? 'managed' : 'typescript',
      context = [p, lineKey(p)];
    const r = cache.memo(kind + '-facts', identity(p), context, () =>
      kind === 'managed'
        ? extractManaged([read(p)], { addedLines: opts.addedLines })
        : kind === 'python'
        ? extractPython([read(p)], { addedLines: opts.addedLines })
        : extractTs([read(p)], { addedLines: opts.addedLines }),
    );
    facts.push(...r.facts);
    envReads.push(...r.envReads);
  }

  // Env vars read in the same directory as each file with facts, at this snapshot.
  const fileEnv = new Map<string, string[]>();
  for (const f of new Set(facts.map((x) => x.file))) {
    const dir = path.posix.dirname(f);
    const names = new Set<string>();
    const siblings = all.filter((x) => path.posix.dirname(x) === dir);
    await prepareLanguages(siblings.map(languageForFile));
    for (const p of siblings) {
      const reads = cache.memo('env', identity(p), [p], () => {
        const content = source.readFile(p) ?? '';
        try {
          return p.endsWith('.go')
            ? envReadsGo(content, p)
            : /\.(java|kt|cs)$/.test(p)
              ? envReadsManaged(content,p)
              : p.endsWith('.py')
              ? envReadsPython(content, p)
              : envReadsTs(content, p);
        } finally {
          clearSyntax();
        }
      });
      for (const e of reads) names.add(e.name);
    }
    fileEnv.set(f, [...names]);
  }

  return { facts, envReads, fileEnv };
}

/**
 * Directories reachable from Go main packages through imports within the same module: the code one
 * binary can run. Non-Go entries contribute their own directory only.
 */
export function entryClosure(
  source: FileSource,
  appFiles: string[],
  entries: string[],
  cache: ExtractionCache = extractionCache,
): Set<string> {
  const goFiles = appFiles.filter((p) => p.endsWith('.go'));
  const modules = source
    .allFiles()
    .filter((p) => p === 'go.mod' || p.endsWith('/go.mod'))
    .map((p) => path.posix.dirname(p));
  const modulePaths = modules.map((m) => ({
    dir: m,
    path: (source.readFile(m === '.' ? 'go.mod' : `${m}/go.mod`) ?? '').match(/^module\s+(\S+)/m)?.[1],
  }));
  const dirOfImport = (imp: string): string | undefined => {
    for (const m of modulePaths) {
      if (!m.path) continue;
      if (imp === m.path) return m.dir;
      if (imp.startsWith(m.path + '/')) return (m.dir === '.' ? '' : m.dir + '/') + imp.slice(m.path.length + 1);
    }
    return undefined;
  };
  const seen = new Set<string>();
  const queue = entries.map((e) => path.posix.normalize(e));
  while (queue.length) {
    const dir = queue.pop()!;
    if (seen.has(dir)) continue;
    seen.add(dir);
    for (const f of goFiles.filter((p) => path.posix.dirname(p) === dir)) {
      const file: SourceFile = {
        path: f,
        blobId: source.blobId?.(f),
        get content() {
          return source.readFile(f) ?? '';
        },
      };
      const imports = cache.memo('go-imports', fileIdentity(file), null, () => {
        try {
          return [...parseImports(file.content)];
        } finally {
          clearSyntax();
        }
      });
      for (const [, imp] of imports) {
        const d = dirOfImport(imp);
        if (d !== undefined && !seen.has(d)) queue.push(d);
      }
    }
  }
  return seen;
}
