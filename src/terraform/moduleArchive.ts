/** Bounded tar reader. It never extracts paths or links to the filesystem. */
import { gunzipSync } from 'node:zlib';
import { MAX_MODULE_BYTES, safeModulePath } from './moduleCache.js';
export function archiveFiles(input: Buffer, stripWrapper: boolean): Record<string, string> {
  const bytes = input[0] === 0x1f && input[1] === 0x8b ? gunzipSync(input, { maxOutputLength: MAX_MODULE_BYTES }) : input;
  if (bytes.length > MAX_MODULE_BYTES) throw Error('Module archive exceeds 100 MiB');
  const files: Record<string, string> = Object.create(null);
  let pendingName: string | undefined;
  const text = (buffer: Buffer): string => buffer.toString('utf8').split('\0')[0];
  for (let at = 0; at + 512 <= bytes.length;) {
    const header = bytes.subarray(at, at + 512); if (header.every((v) => v === 0)) break;
    const sizeText = text(header.subarray(124, 136)).trim();
    if (!/^[0-7]+$/.test(sizeText)) throw Error('Invalid module tar size');
    const size = parseInt(sizeText, 8), sumText = text(header.subarray(148, 156)).trim();
    const checksum = header.reduce((sum, value, i) => sum + (i >= 148 && i < 156 ? 32 : value), 0);
    if (checksum !== parseInt(sumText, 8) || at + 512 + size > bytes.length) throw Error('Invalid module tar header');
    const data = bytes.subarray(at + 512, at + 512 + size), type = String.fromCharCode(header[156]);
    at += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') {
      let offset = 0;
      while (offset < data.length) {
        const space = data.indexOf(32, offset), length = Number(data.subarray(offset, space).toString());
        if (space < 0 || !Number.isSafeInteger(length) || length <= space - offset + 1 || offset + length > data.length) throw Error('Invalid tar PAX metadata');
        const row = data.subarray(space + 1, offset + length - 1).toString();
        if (row.startsWith('path=')) pendingName = row.slice(5);
        if (row.startsWith('linkpath=')) throw Error('Module archive links are not supported');
        offset += length;
      }
      continue;
    }
    if (type === 'L') { pendingName = text(data); continue; }
    if (type === 'g') continue;
    const prefix = text(header.subarray(345, 500));
    let name = pendingName ?? [prefix, text(header.subarray(0, 100))].filter(Boolean).join('/'); pendingName = undefined;
    name = name.replace(/^(?:\.\/)+/, '').replace(/\/$/, '');
    if (!name && type === '5') continue;
    if (!safeModulePath(name)) throw Error('Unsafe module archive path');
    if (type === '5') continue;
    if (type !== '0' && type !== '\0') throw Error('Module archive links and special files are not supported');
    if (Object.hasOwn(files, name)) throw Error('Duplicate module archive path');
    files[name] = data.toString('base64');
  }
  if (!Object.keys(files).length) throw Error('Module archive has no files');
  if (!stripWrapper) return files;
  const roots = new Set(Object.keys(files).map((name) => name.split('/')[0]));
  if (roots.size !== 1 || Object.keys(files).some((name) => !name.includes('/'))) throw Error('Module archive wildcard must select exactly one directory');
  return Object.fromEntries(Object.entries(files).map(([name, value]) => [name.slice(name.indexOf('/') + 1), value]));
}
