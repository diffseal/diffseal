import { expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { manifest } from './changeRecord.js';
import { verifyPack, keySource, type KeyList, type VerifyOptions } from './verify.js';
import { evidencePack } from './pack.js';

function fixture() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-verify-')), folder = path.join(temp, 'pack'), keys = path.join(temp, 'keys.json');
  fs.mkdirSync(folder);
  const pair = generateKeyPairSync('ed25519');
  const raw = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const keyId = createHash('sha256').update(raw).digest('hex').slice(0, 16);
  const list: KeyList = { schema: 'terratrust.keys/v1', updatedAt: '2026-10-27T00:00:00Z', keys: [{ keyId, alg: 'Ed25519', publicKey: raw.toString('base64'), validFrom: '2026-10-01T00:00:00Z', revokedAt: null, compromised: false }] };
  const pack = { schema: 'terratrust.pack/v2', account: { id: 7, login: 'example' }, period: { label: '2026-Q4', since: '2026-10-01T00:00:00Z', until: '2027-01-01T00:00:00Z' }, generatedAt: '2026-10-27T00:00:00Z', signing: { keyId, alg: 'Ed25519', payload: 'MANIFEST.sha256' } };
  const files = { 'pack.json': JSON.stringify(pack), 'index.md': 'Evidence\n', 'changes/a.json': '{"change":1}\n' };
  const write = (name: string, text: string) => { fs.mkdirSync(path.dirname(path.join(folder, name)), { recursive: true }); fs.writeFileSync(path.join(folder, name), text); };
  let seal = manifest(files);
  const signature = { alg: 'Ed25519', keyId, signature: '' };
  const writeSignature = () => { signature.signature = sign(null, Buffer.from(seal), pair.privateKey).toString('base64'); write('signature.json', JSON.stringify(signature)); };
  const writeList = () => fs.writeFileSync(keys, JSON.stringify(list));
  const reseal = () => { files['pack.json'] = JSON.stringify(pack); for (const [name, text] of Object.entries(files)) write(name, text); seal = manifest(files); write('MANIFEST.sha256', seal); writeSignature(); };
  reseal(); writeList();
  return { folder, keys, keyId, pack, list, files, signature, write, writeList, reseal, writeSignature, get seal() { return seal; }, verify: (options: VerifyOptions = {}) => verifyPack(folder, { keys, ...options }), done: () => fs.rmSync(temp, { recursive: true, force: true }) };
}

function failure(mutate: (f: ReturnType<typeof fixture>) => void, message: string, options?: VerifyOptions) {
  const f = fixture();
  try { mutate(f); const r = f.verify(options); expect(r.ok).toBe(false); expect(r.failures.some((text) => text.includes(message))).toBe(true); }
  finally { f.done(); }
}

test('valid signed pack verifies offline with account, period and exact file count', () => {
  const f = fixture(); try { expect(f.verify({ account: 'example', period: '2026-Q4' })).toEqual({ ok: true, failures: [], keyId: f.keyId, account: 'example', period: '2026-Q4', files: 3 }); } finally { f.done(); }
});
for (const [name, mutate, message] of [
  ['changed file', (f) => f.write('index.md', 'changed'), 'Changed file: index.md'],
  ['extra file', (f) => f.write('extra', 'extra'), 'Extra file: extra'],
  ['missing file', (f) => fs.unlinkSync(path.join(f.folder, 'index.md')), 'Missing file: index.md'],
  ['symlink', (f) => fs.symlinkSync('/does-not-exist', path.join(f.folder, 'link')), 'Symlink is not allowed: link'],
  ['parent traversal', (f) => f.write('MANIFEST.sha256', `${'0'.repeat(64)}  ../outside\n`), 'Parent traversal'],
  ['absolute path', (f) => f.write('MANIFEST.sha256', `${'0'.repeat(64)}  /outside\n`), 'Absolute manifest path'],
  ['Windows absolute path', (f) => f.write('MANIFEST.sha256', `${'0'.repeat(64)}  C:/outside\n`), 'Absolute manifest path'],
  ['backslash path', (f) => f.write('MANIFEST.sha256', `${'0'.repeat(64)}  changes\\a.json\n`), 'Backslash'],
  ['duplicate line', (f) => f.write('MANIFEST.sha256', f.seal + f.seal.split('\n')[0] + '\n'), 'Duplicate manifest path'],
  ['case-folded duplicate', (f) => f.write('MANIFEST.sha256', f.seal + `${'0'.repeat(64)}  INDEX.md\n`), 'Case-folded duplicate'],
  ['malformed line', (f) => f.write('MANIFEST.sha256', 'invalid\n'), 'Malformed manifest line'],
  ['missing newline', (f) => f.write('MANIFEST.sha256', f.seal.trimEnd()), 'missing final newline'],
  ['unsorted lines', (f) => f.write('MANIFEST.sha256', f.seal.trimEnd().split('\n').reverse().join('\n') + '\n'), 'not sorted'],
  ['unknown key', (f) => { f.list.keys = []; f.writeList(); }, 'Unknown key id'],
  ['key id does not match public key', (f) => { f.list.keys[0].publicKey = Buffer.alloc(32, 1).toString('base64'); f.writeList(); }, 'Key id does not match the public key'],
  ['pack and signature key id differ', (f) => { f.pack.signing.keyId = 'other'; f.reseal(); }, 'pack.json key id differs'],
  ['compromised key', (f) => { f.list.keys[0].compromised = true; f.writeList(); }, 'Signing key is compromised'],
  ['revoked at generation', (f) => { f.list.keys[0].revokedAt = f.pack.generatedAt; f.writeList(); }, 'at or after key revokedAt'],
  ['revoked before generation', (f) => { f.list.keys[0].revokedAt = '2026-10-26T00:00:00Z'; f.writeList(); }, 'at or after key revokedAt'],
  ['not yet valid', (f) => { f.list.keys[0].validFrom = '2026-11-01T00:00:00Z'; f.writeList(); }, 'before key validFrom'],
  ['bad signature', (f) => { f.signature.signature = Buffer.alloc(64).toString('base64'); f.write('signature.json', JSON.stringify(f.signature)); }, 'Bad Ed25519 signature'],
  ['unsupported schema', (f) => { f.pack.schema = 'unknown'; f.reseal(); }, 'Unsupported pack.json schema'],
] satisfies Array<[string, (f: ReturnType<typeof fixture>) => void, string]>) {
  test(`verifier rejects ${name} with a specific diagnostic`, () => failure(mutate, message));
}
test('account and period mismatches each have their own message', () => {
  failure(() => {}, 'Account mismatch', { account: 'another' });
  failure(() => {}, 'Period mismatch', { period: '2026-Q3' });
});
test('unsigned packs require allow-unsigned and still reject changed files', () => {
  const f = fixture(); try {
    fs.unlinkSync(path.join(f.folder, 'signature.json'));
    expect(f.verify().failures).toEqual(['The files match the manifest, but the pack is not signed']);
    expect(f.verify({ allowUnsigned: true }).ok).toBe(true);
    f.write('index.md', 'bad'); expect(f.verify({ allowUnsigned: true }).ok).toBe(false);
  } finally { f.done(); }
});
test('symlinked pack folders and symlinked manifest are rejected', () => {
  const f = fixture(); const alias = `${f.folder}-link`;
  try { fs.symlinkSync(f.folder, alias); expect(verifyPack(alias).failures).toContain('Symlink is not allowed: pack folder');
    fs.unlinkSync(path.join(f.folder, 'MANIFEST.sha256')); fs.symlinkSync(f.keys, path.join(f.folder, 'MANIFEST.sha256')); expect(f.verify().failures).toContain('Symlink is not allowed: MANIFEST.sha256');
  } finally { f.done(); }
});
test('CLI JSON output is parseable, exit codes reflect verification and key provenance is always visible', () => {
  const f = fixture();
  const cli = path.resolve(import.meta.dirname, '../cli.ts');
  const run = (...args: string[]) => spawnSync('bun', [cli, 'verify', f.folder, ...args], { encoding: 'utf8' });
  try {
    const valid = run('--keys', f.keys, '--json'); expect(valid.status).toBe(0); expect(JSON.parse(valid.stdout)).toEqual(f.verify());
    expect(valid.stderr).toContain('WARNING: keys from --keys'); expect(valid.stderr).toContain('updatedAt 2026-10-27'); expect(valid.stderr).toContain(`Keys used: --keys ${f.keys}`); expect(valid.stderr).not.toContain('bundled with this version'); expect(valid.stderr).toContain('Account: example'); expect(valid.stderr).toContain(f.keyId);
    const unknown = run('--json'); expect(unknown.status).toBe(1); expect(JSON.parse(unknown.stdout).failures[0]).toContain('Unknown key id'); expect(unknown.stderr).not.toContain('WARNING'); expect(unknown.stderr).toContain('Keys: bundled with this version'); expect(unknown.stderr).toContain('https://terratrust.dev/.well-known/terratrust-keys.json');
    f.write('index.md', 'bad'); const invalid = run('--keys', f.keys); expect(invalid.status).toBe(1); expect(invalid.stderr).toContain('Changed file: index.md');
  } finally { f.done(); }
});
test('terratrust evidence output verifies with allow-unsigned and both schemas are accepted', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-export-verify-')), repo = path.join(temp, 'repo'), outDir = path.join(temp, 'export');
  fs.mkdirSync(repo);
  const git = (...args: string[]) => { const r = spawnSync('git', ['-C', repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args], { encoding: 'utf8' }); if (r.status) throw new Error(r.stderr); };
  try {
    git('init', '-q'); fs.writeFileSync(path.join(repo, 'README'), 'base'); git('add', '.'); git('commit', '-qm', 'base');
    fs.writeFileSync(path.join(repo, 'README'), 'head'); git('commit', '-qam', 'head');
    await evidencePack({ repo, outDir, since: '2090-01-01', until: '2091-01-01' });
    const result = verifyPack(outDir, { allowUnsigned: true }); expect(result.ok).toBe(true); expect(result.files).toBe(3);
    expect(verifyPack(outDir).failures).toContain('The files match the manifest, but the pack is not signed');
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test('key provenance identifies only the list actually used', () => {
  expect(keySource({})).toEqual(['Keys: bundled with this version (updatedAt 2026-10-28T00:00:00Z). Current list: https://terratrust.dev/.well-known/terratrust-keys.json']);
  const f = fixture();
  try {
    f.list.updatedAt = '2026-10-26T12:00:00Z'; f.writeList();
    expect(keySource({ keys: f.keys })).toEqual([
      `Keys used: --keys ${f.keys} (updatedAt 2026-10-26T12:00:00Z).`,
      `WARNING: keys from --keys ${f.keys} are not TerraTrust's published list.`,
    ]);
  } finally { f.done(); }
});
