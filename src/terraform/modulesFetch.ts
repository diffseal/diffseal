import { randomUUID } from 'node:crypto';
import { archiveFiles } from './moduleArchive.js';
import { selectModuleVersion } from './moduleVersions.js';
/** Explicit network phase. Never imported by the offline Action. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { loadModule, isConfigFile } from './config.js';
import { MemorySource, FsSource } from './source.js';
import { MODULE_LOCK, parseModuleLock, defaultModuleCache, moduleDigest, moduleObject, safeModulePath, type ModuleLock, type ModuleLockEntry } from './moduleCache.js';
function git(args: string[]): Buffer {
  const r = spawnSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=', '-c', 'protocol.ext.allow=never', ...args], { env: { PATH: process.env.PATH, HOME: os.tmpdir(), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' }, timeout: 120_000, maxBuffer: 100 * 1024 * 1024 });
  if (r.error || r.status) throw Error(`Module git failed: ${r.error?.message ?? r.stderr.toString().slice(0, 1000)}`);
  return r.stdout;
}
function gitSource(source: string): { url: string; ref: string; subdir: string } {
  let raw = source.startsWith('git::') ? source.slice(5) : source.startsWith('github.com/') ? 'https://' + source : '';
  if (!raw) throw Error(`Unsupported public module source: ${source}`);
  const at = raw.indexOf('//', raw.indexOf('://') + 3);
  let subdir = '';
  if (at >= 0) { subdir = raw.slice(at + 2).split('?')[0]; raw = raw.slice(0, at) + (raw.includes('?') ? '?' + raw.split('?')[1] : ''); }
  if (subdir && !safeModulePath(subdir)) throw Error('Invalid module subdirectory');
  const url = new URL(raw);
  if (!['https:', 'file:'].includes(url.protocol) && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) throw Error('Only public HTTPS git sources are supported; file URLs are for local fixtures');
  if (url.username || url.password) throw Error('Private module credentials are not supported');
  for (const key of url.searchParams.keys()) if (key !== 'ref' && key !== 'depth') throw Error(`Unsupported git module parameter: ${key}`);
  const ref = url.searchParams.get('ref') ?? 'HEAD'; url.search = '';
  if (ref.startsWith('-')) throw Error('Invalid git ref');
  return { url: url.href, ref, subdir };
}
async function download(source: string): Promise<{ files: Record<string, string>; commit?: string; subdir: string }> {
  if (/^https?:/.test(source)) {
    let raw = source;
    const at = raw.indexOf('//', raw.indexOf('://') + 3);
    const subdir = at < 0 ? '' : raw.slice(at + 2).split('?')[0];
    if (at >= 0) raw = raw.slice(0, at) + (raw.includes('?') ? '?' + raw.split('?')[1] : '');
    if (subdir && subdir !== '*' && !safeModulePath(subdir)) throw Error('Invalid archive module subdirectory');
    const response = await request(raw);
    if (!response.body) throw Error('Empty module download');
    const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 100 * 1024 * 1024) throw Error('Module download exceeds 100 MiB'); chunks.push(value); }
    } finally { await reader.cancel(); }
    return { files: archiveFiles(Buffer.concat(chunks), subdir === '*'), subdir: subdir === '*' ? '' : subdir };
  }
  const parsed = gitSource(source), stage = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-module-fetch-'));
  try {
    const repo = path.join(stage, 'repo.git');
    git(['clone', '--bare', '--no-local', '--', parsed.url, repo]);
    const commit = git(['--git-dir', repo, 'rev-parse', '--verify', parsed.ref + '^{commit}']).toString().trim();
    const entries = git(['--git-dir', repo, 'ls-tree', '-rz', '--full-tree', commit]).toString().split('\0').filter(Boolean);
    const files: Record<string, string> = Object.create(null);
    let size = 0;
    for (const entry of entries) {
      const tab = entry.indexOf('\t'), [mode, type, blob] = entry.slice(0, tab).split(' '), name = entry.slice(tab + 1);
      if (type !== 'blob' || !['100644', '100755'].includes(mode)) throw Error('Module symlinks and git submodules are not supported');
      if (!safeModulePath(name)) throw Error('Invalid git module path');
      const bytes = git(['--git-dir', repo, 'cat-file', 'blob', blob]); size += bytes.length;
      if (size > 70 * 1024 * 1024) throw Error('Module exceeds download limit');
      files[name] = bytes.toString('base64');
    }
    return { files, commit, subdir: parsed.subdir };
  } finally { fs.rmSync(stage, { recursive: true, force: true }); }
}
async function request(url: string): Promise<Response> {
  for (let redirects = 0; redirects < 6; redirects++) {
    const target = new URL(url);
    if (target.username || target.password || (target.protocol !== 'https:' && !(target.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(target.hostname)))) throw Error('Public module downloads require HTTPS');
    const response = await fetch(target, { redirect: 'manual', signal: AbortSignal.timeout(30_000) });
    if (response.status >= 300 && response.status < 400 && response.headers.has('location')) { url = new URL(response.headers.get('location')!, target).href; await response.body?.cancel(); continue; }
    if (!response.ok) throw Error(`Module request failed with HTTP ${response.status}`);
    return response;
  }
  throw Error('Too many module redirects');
}
async function resolveDownload(source: string, constraint: string, locked?: ModuleLockEntry): Promise<{ files: Record<string, string>; commit?: string; subdir: string; version?: string }> {
  if (source.startsWith('git::') || source.startsWith('github.com/')) {
    if (constraint) throw Error('Git modules cannot have a registry version constraint');
    const parsed = gitSource(source);
    if (locked && !locked.commit) throw Error('Git lock entry has no commit');
    return download(locked ? 'git::' + parsed.url + (parsed.subdir ? '//' + parsed.subdir : '') + '?ref=' + locked.commit : source);
  }
  const [address, subdir = ''] = source.split('//');
  if (subdir && !safeModulePath(subdir)) throw Error('Invalid registry module subdirectory');
  const parts = address.split('/');
  if (parts.length === 3) parts.unshift('registry.terraform.io');
  if (parts.length !== 4 || parts.some((part) => !/^[A-Za-z0-9_.:-]+$/.test(part))) throw Error(`Unsupported registry module source: ${source}`);
  const [host, ...module] = parts, origin = (host.startsWith('127.0.0.1:') || host.startsWith('localhost:') ? 'http://' : 'https://') + host;
  const discoveryUrl = origin + '/.well-known/terraform.json';
  const discovery = await (await request(discoveryUrl)).json() as Record<string, unknown>;
  if (typeof discovery['modules.v1'] !== 'string') throw Error('Registry does not advertise modules.v1');
  const base = new URL(discovery['modules.v1'], discoveryUrl); if (!base.pathname.endsWith('/')) base.pathname += '/';
  const versions = locked ? undefined : await (await request(new URL(module.join('/') + '/versions', base).href)).json() as { modules?: Array<{ versions?: Array<{ version: string }> }> };
  if (locked && !locked.version) throw Error('Registry lock entry has no version');
  const version = selectModuleVersion(locked ? [locked.version!] : versions?.modules?.[0]?.versions?.map((entry) => entry.version) ?? [], constraint);
  const endpoint = new URL(module.join('/') + '/' + version + '/download', base).href;
  const response = await request(endpoint), location = response.headers.get('X-Terraform-Get'); await response.body?.cancel();
  if (!location) throw Error('Registry download response has no X-Terraform-Get');
  const getter = /^(?:\/|\.\.?\/)/.test(location) ? new URL(location, endpoint).href : location;
  const pinned = locked?.commit && (getter.startsWith('git::') || getter.startsWith('github.com/')) ? (() => { const parsed = gitSource(getter); return 'git::' + parsed.url + (parsed.subdir ? '//' + parsed.subdir : '') + '?ref=' + locked.commit; })() : getter;
  const result = await download(pinned);
  return { ...result, version, subdir: [result.subdir, subdir].filter(Boolean).join('/') };
}
export async function fetchModules(opts: { repo?: string; cache?: string }): Promise<ModuleLock> {
  const repo = path.resolve(opts.repo ?? '.'), cache = path.resolve(opts.cache ?? defaultModuleCache());
  const source = new FsSource(repo), oldLock = parseModuleLock(source.readFile(MODULE_LOCK)), queue: Array<{ source: string; constraint: string }> = [];
  for (const dir of new Set(source.allFiles().filter(isConfigFile).map((file) => path.posix.dirname(file)))) {
    for (const call of loadModule(source, dir)?.moduleCalls.values() ?? []) if (call.source && !call.localDir) queue.push({ source: call.source, constraint: call.version ?? '' });
  }
  const modules: ModuleLockEntry[] = [], seen = new Set<string>();
  while (queue.length) {
    const call = queue.shift()!, key = JSON.stringify([call.source, call.constraint]); if (seen.has(key)) continue; seen.add(key);
    if (seen.size > 200) throw Error('Module graph exceeds 200 packages');
    const locked = oldLock.modules.find((entry) => entry.source === call.source && entry.constraint === call.constraint);
    const result = await resolveDownload(call.source, call.constraint, locked), bytes = moduleObject(result.files), sha256 = moduleDigest(bytes);
    if (locked && (locked.sha256 !== sha256 || locked.subdir !== result.subdir || locked.commit !== result.commit)) throw Error(`Locked module contents changed: ${call.source}`);
    fs.mkdirSync(path.join(cache, 'objects'), { recursive: true });
    const object = path.join(cache, 'objects', sha256 + '.json');
    atomicWrite(object, bytes);
    const snapshot = new MemorySource(Object.fromEntries(Object.entries(result.files).map(([file, data]) => [file, Buffer.from(data, 'base64').toString('utf8')])));
    const pending = [result.subdir || '.'], visited = new Set<string>();
    while (pending.length) {
      const dir = pending.pop()!; if (visited.has(dir)) continue; visited.add(dir);
      if (visited.size > 1000) throw Error('Module local dependency graph exceeds 1000 directories');
      for (const child of loadModule(snapshot, dir)?.moduleCalls.values() ?? []) {
        if (child.localDir) pending.push(child.localDir);
        else if (child.source) queue.push({ source: child.source, constraint: child.version ?? '' });
      }
    }
    modules.push({ ...call, ...(result.commit ? { commit: result.commit } : {}), ...(result.version ? { version: result.version } : {}), sha256, subdir: result.subdir });
  }
  modules.sort((a, b) => { const x = JSON.stringify([a.source, a.constraint]), y = JSON.stringify([b.source, b.constraint]); return x < y ? -1 : x > y ? 1 : 0; });
  const lock: ModuleLock = { format: 'terratrust.modules/v1', modules };
  atomicWrite(path.join(repo, MODULE_LOCK), Buffer.from(JSON.stringify(lock, null, 2) + '\n'));
  return lock;
}

function atomicWrite(file: string, bytes: Buffer): void {
  const temporary = file + '.' + randomUUID() + '.tmp';
  try { fs.writeFileSync(temporary, bytes, { flag: 'wx' }); fs.renameSync(temporary, file); }
  finally { fs.rmSync(temporary, { force: true }); }
}
