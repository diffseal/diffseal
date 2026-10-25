import { createHash } from 'node:crypto';
/** Bump when parsing or extraction semantics change. Entries never retain parser trees or complete source files. */
export const EXTRACTOR_VERSION = 'app-extraction/2';
interface Limits {
  maxEntries?: number;
  maxBytes?: number;
  version?: string;
}
interface Entry {
  value: unknown;
  bytes: number;
}
export class ExtractionCache {
  private readonly entries = new Map<string, Entry>();
  private bytes = 0;
  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private readonly version: string;
  constructor(limits: Limits = {}) {
    this.maxEntries = limits.maxEntries ?? 8192;
    this.maxBytes = limits.maxBytes ?? 64 * 1024 * 1024;
    this.version = limits.version ?? EXTRACTOR_VERSION;
    for (const limit of [this.maxEntries, this.maxBytes])
      if (!Number.isSafeInteger(limit) || limit < 0) throw new Error('Cache limits must be non-negative integers');
  }
  has(kind: string, blobId: string, context: unknown): boolean {
    return this.entries.has(JSON.stringify([this.version, kind, blobId, context]));
  }
  memo<T>(kind: string, blobId: string, context: unknown, build: () => T): T {
    const key = JSON.stringify([this.version, kind, blobId, context]);
    const found = this.entries.get(key);
    if (found) {
      this.hits++;
      this.entries.delete(key);
      this.entries.set(key, found);
      return structuredClone(found.value) as T;
    }
    this.misses++;
    const value = build();
    if (!this.maxEntries || !this.maxBytes) return value;
    // Conservative serialized size estimate plus per-entry overhead; entry count is capped too.
    const bytes = 2 * (key.length + JSON.stringify(value).length) + 256;
    if (this.maxEntries && bytes <= this.maxBytes) {
      while (this.entries.size >= this.maxEntries || this.bytes + bytes > this.maxBytes) {
        const oldest = this.entries.keys().next().value!;
        const entry = this.entries.get(oldest)!;
        this.entries.delete(oldest);
        this.bytes -= entry.bytes;
        this.evictions++;
      }
      this.entries.set(key, { value: structuredClone(value), bytes });
      this.bytes += bytes;
    }
    return value;
  }
  stats() {
    return {
      entries: this.entries.size,
      bytes: this.bytes,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
    };
  }
}
export const extractionCache = new ExtractionCache();

export function fileIdentity(file: { content: string; blobId?: string }): string {
  return file.blobId ?? 'sha256:' + createHash('sha256').update(file.content).digest('hex');
}
