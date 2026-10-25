import * as path from 'node:path';
import type { FileSource } from '../terraform/source.js';
import type { AccessFact, AddedLines, AppScan, EnvRead } from './facts.js';
import { GoIndex, envReadsGo, extractGo, parseImports, withoutGoComments, type SourceFile } from './go.js';
import { envReadsPython, extractPython, pythonCode } from './python.js';
import { envCode, envReadsTs, extractTs } from './typescript.js';

const SKIP = /(^|\/)(\.git|\.claude|\.worktrees|node_modules|vendor|testdata|gen|dist|build|\.venv|venv|__pycache__|site-packages|\.terraform|coverage)\//;
const TEST = /(_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|(^|\/)test_[^/]*\.py|_test\.py)$/;

export function isAppFile(p: string): boolean {
  return /\.(go|ts|tsx|js|mjs|cjs|py)$/.test(p) && !SKIP.test(p) && !TEST.test(p) && !p.endsWith('.d.ts');
}

export interface ScanResult extends AppScan {
  /** Env vars read anywhere in each scanned file's directory (package), for finding the compute. */
  fileEnv: Map<string, string[]>;
}

/**
 * Extract AWS access facts and env reads from an application snapshot. With `addedLines`, only calls
 * and reads on added lines count; the whole snapshot is still read to resolve helpers and packages.
 */
export function scanApp(source: FileSource, opts: { addedLines?: AddedLines; entries?: string[] } = {}): ScanResult {
  const all = source.allFiles().filter(isAppFile);
  let wanted = opts.addedLines ? all.filter((p) => opts.addedLines!.has(p)) : all;
  if (opts.entries?.length) {
    const closure = entryClosure(source, all, opts.entries);
    wanted = wanted.filter((p) => closure.has(path.posix.dirname(p)) || opts.entries!.some((e) => p.startsWith(e.replace(/\/$/, '') + '/') && !p.endsWith('.go')));
  }
  const goAll = all.filter((p) => p.endsWith('.go'));
  if ('prefetch' in source && typeof source.prefetch === 'function') {
    (source.prefetch as (p: string[]) => void)([...new Set([...wanted, ...goAll, ...all.filter((p) => p.endsWith('go.mod'))])]);
  }
  const read = (p: string): SourceFile => ({ path: p, content: source.readFile(p) ?? '' });

  const facts: AccessFact[] = [];
  const envReads: EnvRead[] = [];

  // Go: one helper index per module (nearest go.mod).
  const modules = source.allFiles().filter((p) => p === 'go.mod' || p.endsWith('/go.mod')).map((p) => path.posix.dirname(p));
  const moduleOf = (p: string) => modules.filter((m) => m === '.' || p.startsWith(m + '/')).sort((a, b) => b.length - a.length)[0];
  for (const modDir of modules) {
    const modulePath = (source.readFile(modDir === '.' ? 'go.mod' : `${modDir}/go.mod`) ?? '').match(/^module\s+(\S+)/m)?.[1];
    if (!modulePath) continue;
    const inModule = goAll.filter((p) => moduleOf(p) === modDir);
    const rel = (p: string) => (modDir === '.' ? p : p.slice(modDir.length + 1));
    const index = new GoIndex(modulePath, inModule.map((p) => ({ path: rel(p), content: source.readFile(p) ?? '' })));
    const targets = inModule.filter((p) => wanted.includes(p)).map(read);
    const r = extractGo(targets, { index, addedLines: opts.addedLines, moduleDir: modDir });
    // A helper's own call on its parameter is redundant when its callers were scanned: they name the resource.
    const helperPackages = new Set(r.facts.flatMap((f) => (f.viaPackage ? [f.viaPackage] : [])));
    facts.push(...r.facts.filter((f) => !(f.internal && helperPackages.has(index.packageOf(rel(f.file))))));
    envReads.push(...r.envReads);
  }

  const ts = wanted.filter((p) => /\.(ts|tsx|js|mjs|cjs)$/.test(p)).map(read);
  const py = wanted.filter((p) => p.endsWith('.py')).map(read);
  for (const r of [extractTs(ts, { addedLines: opts.addedLines }), extractPython(py, { addedLines: opts.addedLines })]) {
    facts.push(...r.facts);
    envReads.push(...r.envReads);
  }

  // Env vars read in the same directory as each file with facts, at this snapshot.
  const fileEnv = new Map<string, string[]>();
  for (const f of new Set(facts.map((x) => x.file))) {
    const dir = path.posix.dirname(f);
    const names = new Set<string>();
    for (const p of all.filter((x) => path.posix.dirname(x) === dir)) {
      const content = source.readFile(p) ?? '';
      // Env reads in comments do not count, as in extraction.
      const reads = p.endsWith('.go')
        ? envReadsGo(withoutGoComments(content), p)
        : p.endsWith('.py')
          ? envReadsPython(pythonCode(content, false), p)
          : envReadsTs(envCode(content), p);
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
export function entryClosure(source: FileSource, appFiles: string[], entries: string[]): Set<string> {
  const goFiles = appFiles.filter((p) => p.endsWith('.go'));
  const modules = source.allFiles().filter((p) => p === 'go.mod' || p.endsWith('/go.mod')).map((p) => path.posix.dirname(p));
  const modulePaths = modules.map((m) => ({ dir: m, path: (source.readFile(m === '.' ? 'go.mod' : `${m}/go.mod`) ?? '').match(/^module\s+(\S+)/m)?.[1] }));
  const dirOfImport = (imp: string): string | undefined => {
    for (const m of modulePaths) {
      if (!m.path) continue;
      if (imp === m.path) return m.dir;
      if (imp.startsWith(m.path + '/')) return (m.dir === '.' ? '' : m.dir + '/') + imp.slice(m.path.length + 1);
    }
    return undefined;
  };
  const seen = new Set<string>();
  const queue = entries.map((e) => e.replace(/\/$/, ''));
  while (queue.length) {
    const dir = queue.pop()!;
    if (seen.has(dir)) continue;
    seen.add(dir);
    for (const f of goFiles.filter((p) => path.posix.dirname(p) === dir)) {
      for (const imp of parseImports(source.readFile(f) ?? '').values()) {
        const d = dirOfImport(imp);
        if (d !== undefined && !seen.has(d)) queue.push(d);
      }
    }
  }
  return seen;
}
