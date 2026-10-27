/** Offline verification of free exports and signed service packs. Contract v1 sections 7 and 8. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import bundledKeys from '../../keys/evidence-keys.json' with { type: 'json' };

export interface PublicKeyEntry {
  keyId: string;
  alg: 'Ed25519';
  publicKey: string;
  validFrom: string;
  revokedAt: string | null;
  compromised: boolean;
}
export interface KeyList { schema: 'terratrust.keys/v1'; updatedAt: string; keys: PublicKeyEntry[] }
export interface VerifyOptions { keys?: string; account?: string; period?: string; allowUnsigned?: boolean }
export interface VerifyResult { ok: boolean; failures: string[]; keyId?: string; account?: string; period?: string; files: number }
export const CURRENT_KEYS_URL = 'https://terratrust.dev/.well-known/terratrust-keys.json';
export function keySource(options: VerifyOptions): string[] {
  if (options.keys) {
    let updatedAt = '(unavailable)';
    try { updatedAt = JSON.parse(fs.readFileSync(options.keys, 'utf8')).updatedAt ?? updatedAt; } catch { /* Verification reports an invalid list. */ }
    return [
      `Keys used: --keys ${options.keys} (updatedAt ${updatedAt}).`,
      `WARNING: keys from --keys ${options.keys} are not TerraTrust's published list.`,
    ];
  }
  return [`Keys: bundled with this version (updatedAt ${bundledKeys.updatedAt}). Current list: ${CURRENT_KEYS_URL}`];
}

const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const reserved = new Set(['MANIFEST.sha256', 'signature.json']);

export function verifyPack(folder: string, options: VerifyOptions = {}): VerifyResult {
  const failures: string[] = [];
  const result: VerifyResult = { ok: false, failures, files: 0 };
  const fail = (message: string) => { failures.push(message); };
  try {
    const root = fs.lstatSync(folder);
    if (root.isSymbolicLink()) { fail('Symlink is not allowed: pack folder'); return result; }
    if (!root.isDirectory()) { fail('Pack folder is not a directory'); return result; }
    const regular = new Set<string>();
    const walk = (relative: string) => {
      for (const name of fs.readdirSync(path.join(folder, relative)).sort()) {
        const rel = relative ? `${relative}/${name}` : name;
        const stat = fs.lstatSync(path.join(folder, rel));
        if (stat.isSymbolicLink()) fail(`Symlink is not allowed: ${rel}`);
        else if (stat.isDirectory()) walk(rel);
        else if (stat.isFile()) regular.add(rel);
        else fail(`Not a regular file: ${rel}`);
      }
    };
    walk('');
    result.files = [...regular].filter((f) => !reserved.has(f)).length;
    if (!regular.has('MANIFEST.sha256')) { fail('Missing MANIFEST.sha256'); return result; }
    const bytes = fs.readFileSync(path.join(folder, 'MANIFEST.sha256'));
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { fail('Malformed manifest: expected UTF-8'); return result; }
    const entries = new Map<string, string>(), folded = new Set<string>();
    if (!text.endsWith('\n')) fail('Malformed manifest: missing final newline');
    const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n');
    for (const [index, line] of lines.entries()) {
      const match = /^([a-f0-9]{64})  ([^\r\n\x00]+)$/.exec(line);
      if (!match) { fail(`Malformed manifest line ${index + 1}`); continue; }
      const [, hash, name] = match;
      if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) { fail(`Absolute manifest path is not allowed: ${name}`); continue; }
      if (name.includes('\\')) { fail(`Backslash in manifest path: ${name}`); continue; }
      if (name.split('/').includes('..')) { fail(`Parent traversal in manifest path: ${name}`); continue; }
      if (name.split('/').some((part) => !part || part === '.')) { fail(`Non-canonical manifest path: ${name}`); continue; }
      if (reserved.has(name)) { fail(`Manifest must not list ${name}`); continue; }
      if (entries.has(name)) { fail(`Duplicate manifest path: ${name}`); continue; }
      if (folded.has(name.toLowerCase())) { fail(`Case-folded duplicate manifest path: ${name}`); continue; }
      folded.add(name.toLowerCase()); entries.set(name, hash);
    }
    const names = [...entries.keys()];
    if (names.join('\n') !== [...names].sort().join('\n')) fail('Manifest paths are not sorted');
    for (const name of regular) if (!reserved.has(name) && !entries.has(name)) fail(`Extra file: ${name}`);
    for (const [name, hash] of entries) {
      if (!regular.has(name)) fail(`Missing file: ${name}`);
      else if (digest(fs.readFileSync(path.join(folder, name))) !== hash) fail(`Changed file: ${name}`);
    }
    if (!regular.has('pack.json')) { fail('Missing pack.json'); return result; }
    let pack: { schema?: string; generatedAt?: string; account?: { login?: string }; period?: { label?: string }; since?: string; until?: string; signing?: { keyId?: string; alg?: string; payload?: string } };
    try { pack = JSON.parse(fs.readFileSync(path.join(folder, 'pack.json'), 'utf8')); if (!pack || typeof pack !== 'object') throw new Error(); }
    catch { fail('Malformed pack.json'); return result; }
    if (!['terratrust.pack/v2', 'terratrust.evidence-pack/v1'].includes(pack.schema ?? '')) fail('Unsupported pack.json schema');
    result.account = typeof pack.account?.login === 'string' ? pack.account.login : undefined;
    result.period = typeof pack.period?.label === 'string' ? pack.period.label : pack.since && pack.until ? `${pack.since} to ${pack.until}` : undefined;
    if (options.account !== undefined && options.account !== result.account) fail(`Account mismatch: expected ${options.account}, found ${result.account ?? '(not supplied)'}`);
    if (options.period !== undefined && options.period !== result.period) fail(`Period mismatch: expected ${options.period}, found ${result.period ?? '(not supplied)'}`);
    if (!regular.has('signature.json')) {
      if (!options.allowUnsigned) fail('The files match the manifest, but the pack is not signed');
      result.ok = failures.length === 0; return result;
    }
    let signature: { alg?: string; keyId?: string; signature?: string };
    try { signature = JSON.parse(fs.readFileSync(path.join(folder, 'signature.json'), 'utf8')); if (!signature || typeof signature !== 'object') throw new Error(); }
    catch { fail('Malformed signature.json'); return result; }
    result.keyId = signature.keyId;
    if (typeof signature.keyId !== 'string' || !/^[a-f0-9]{16}$/.test(signature.keyId)) fail('Invalid signature key id');
    if (signature.alg !== 'Ed25519') fail('Unsupported signature algorithm');
    if (pack.signing?.keyId !== signature.keyId) fail('pack.json key id differs from signature.json');
    if (pack.signing?.alg !== 'Ed25519' || pack.signing?.payload !== 'MANIFEST.sha256') fail('Invalid pack.json signing metadata');
    let list: KeyList;
    try {
      list = options.keys ? JSON.parse(fs.readFileSync(options.keys, 'utf8')) as KeyList : bundledKeys as KeyList;
      if (list.schema !== 'terratrust.keys/v1' || !Array.isArray(list.keys) || typeof list.updatedAt !== 'string') throw new Error();
    } catch { fail('Invalid key list'); return result; }
    const matching = list.keys.filter((key) => key?.keyId === signature.keyId);
    const key = matching[0];
    if (!key) { fail(`Unknown key id: ${signature.keyId ?? '(missing)'}`); return result; }
    if (matching.length !== 1) fail('Duplicate key id in key list');
    const raw = typeof key.publicKey === 'string' ? Buffer.from(key.publicKey, 'base64') : Buffer.alloc(0);
    if (raw.length !== 32 || raw.toString('base64') !== key.publicKey) { fail('Invalid raw Ed25519 public key'); return result; }
    if (digest(raw).slice(0, 16) !== key.keyId) fail('Key id does not match the public key');
    if (key.alg !== 'Ed25519') fail('Unsupported public key algorithm');
    if (key.compromised) fail('Signing key is compromised');
    if (typeof key.compromised !== 'boolean' || (key.revokedAt !== null && typeof key.revokedAt !== 'string')) fail('Invalid key status');
    const generated = Date.parse(pack.generatedAt ?? ''), valid = Date.parse(key.validFrom), revoked = key.revokedAt === null ? Infinity : Date.parse(key.revokedAt);
    if (!Number.isFinite(generated)) fail('Invalid pack.json generatedAt');
    if (!Number.isFinite(valid) || Number.isNaN(revoked)) fail('Invalid key validity dates');
    if (generated < valid) fail('Pack generatedAt is before key validFrom');
    if (generated >= revoked) fail('Pack generatedAt is at or after key revokedAt');
    const sig = typeof signature.signature === 'string' ? Buffer.from(signature.signature, 'base64') : Buffer.alloc(0);
    const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), type: 'spki', format: 'der' });
    if (sig.length !== 64 || sig.toString('base64') !== signature.signature || !verify(null, bytes, publicKey, sig)) fail('Bad Ed25519 signature');
    result.ok = failures.length === 0;
  } catch (e) { fail(`Cannot verify pack: ${(e as Error).message}`); }
  return result;
}

export function verificationSummary(result: VerifyResult): string {
  return `Account: ${result.account ?? '(not supplied)'}. Period: ${result.period ?? '(not supplied)'}. Key id: ${result.keyId ?? '(unsigned or unavailable)'}. Files: ${result.files}.`;
}
