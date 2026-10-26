/** Verified, content-addressed module objects. This reader never uses the network. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash } from 'node:crypto';
import type { FileSource } from './source.js';
export const MODULE_LOCK = 'terratrust.modules.lock.json';
export const MODULE_PREFIX = '__terratrust_modules/';
export const MAX_MODULE_BYTES = 100 * 1024 * 1024;
export interface ModuleLockEntry {
  source: string;
  constraint: string;
  version?: string;
  commit?: string;
  sha256: string;
  subdir: string;
}
export interface ModuleLock { format: 'terratrust.modules/v1'; modules: ModuleLockEntry[] }
export const defaultModuleCache = (): string => path.join(process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache'), 'terratrust', 'modules');
export const moduleDigest = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
export const safeModulePath = (p: string): boolean => Boolean(p) && !p.includes('\\') && !p.includes('\0') && !p.startsWith('/') && !p.split('/').some((part) => part === '..' || part === '.' || part === '');
export function moduleObject(files: Record<string, string>): Buffer {
  for (const [name, value] of Object.entries(files)) if (!safeModulePath(name) || typeof value !== 'string') throw Error('Invalid module file');
  const bytes = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))) + '\n');
  if (bytes.length > MAX_MODULE_BYTES) throw Error('Module exceeds the 100 MiB cache object limit');
  return bytes;
}
export function parseModuleLock(text: string | undefined): ModuleLock {
  const lock: ModuleLock = text ? JSON.parse(text) : { format: 'terratrust.modules/v1', modules: [] };
  if (lock.format !== 'terratrust.modules/v1' || !Array.isArray(lock.modules)) throw Error('Invalid module lock format');
  const seen = new Set<string>();
  for (const entry of lock.modules) {
    if (typeof entry.source !== 'string' || typeof entry.constraint !== 'string' || typeof entry.subdir !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256) || (entry.subdir && !safeModulePath(entry.subdir)) || (entry.version !== undefined && typeof entry.version !== 'string') || (entry.commit !== undefined && !/^[a-f0-9]{40,64}$/.test(entry.commit))) throw Error('Invalid module lock entry');
    const key = JSON.stringify([entry.source, entry.constraint]);
    if (seen.has(key)) throw Error('Duplicate module lock entry'); seen.add(key);
  }
  return lock;
}
export class OfflineModules {
  private readonly lock: ModuleLock;
  private readonly objects = new Map<string, Record<string, string>>();
  private readonly sizes = new Map<string, number>();
  private bytes = 0;
  constructor(source: FileSource, private readonly cache: string) {
    this.lock = parseModuleLock(source.readFile(MODULE_LOCK));
  }
  resolve(source: string, constraint = ''): string | undefined {
    const entry = this.lock.modules.find((entry) => entry.source === source && entry.constraint === constraint);
    if (!entry) return;
    if (!this.load(entry.sha256)) return;
    return MODULE_PREFIX + entry.sha256 + (entry.subdir ? '/' + entry.subdir : '');
  }
  private load(digest: string): Record<string, string> | undefined {
    const cached = this.objects.get(digest);
    if (cached) { this.objects.delete(digest); this.objects.set(digest, cached); return cached; }

    const file = path.join(this.cache, 'objects', digest + '.json');
    if (!fs.existsSync(file)) return;
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.size > MAX_MODULE_BYTES) throw Error('Invalid module cache object');
    const bytes = fs.readFileSync(file);
    if (moduleDigest(bytes) !== digest) throw Error(`Module cache SHA-256 mismatch for ${digest}`);
    const files = JSON.parse(bytes.toString());
    if (!files || typeof files !== 'object' || Array.isArray(files) || !moduleObject(files).equals(bytes)) throw Error('Invalid module cache contents');
    while (this.bytes + bytes.length > 128 * 1024 * 1024 && this.objects.size) {
      const oldest = this.objects.keys().next().value!;
      this.bytes -= this.sizes.get(oldest)!; this.objects.delete(oldest); this.sizes.delete(oldest);
    }
    this.objects.set(digest, files); this.sizes.set(digest, bytes.length); this.bytes += bytes.length;
    return files;
  }
  private object(p: string): { files: Record<string, string>; name: string } | undefined {
    const [digest, ...rest] = p.slice(MODULE_PREFIX.length).split('/');
    const files = this.lock.modules.some((entry) => entry.sha256 === digest) ? this.load(digest) : undefined;
    return files ? { files, name: rest.join('/') } : undefined;
  }
  readFile(p: string): string | undefined {
    const value = this.object(p); const bytes = value?.files[value.name];
    return bytes === undefined ? undefined : Buffer.from(bytes, 'base64').toString('utf8');
  }
  listFiles(p: string): string[] {
    const value = this.object(p); if (!value) return [];
    return Object.keys(value.files).filter((file) => path.posix.dirname(file) === (value.name || '.')).map((file) => path.posix.basename(file));
  }
}
