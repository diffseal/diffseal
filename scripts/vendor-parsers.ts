/** Copy exact, reviewed npm parser artefacts into the offline runtime. No compiler or network. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
const pins = [
  {
    package: 'tree-sitter-java',
    version: '0.23.5',
    published: '2024-12-21T18:26:25.436Z',
    files: ['tree-sitter-java.wasm'],
  },
  {
    package: 'tree-sitter-c-sharp',
    version: '0.23.5',
    published: '2026-04-14T18:41:16.033Z',
    files: ['tree-sitter-c_sharp.wasm'],
  },
  {
    package: '@tree-sitter-grammars/tree-sitter-kotlin',
    version: '1.1.0',
    published: '2025-01-09T19:06:24.768Z',
    files: ['tree-sitter-kotlin.wasm'],
  },
  {
    package: 'web-tree-sitter',
    version: '0.25.10',
    published: '2025-09-22T22:23:13.426Z',
    files: ['tree-sitter.wasm'],
  },
  {
    package: 'tree-sitter-go',
    version: '0.25.0',
    published: '2025-08-29T06:22:53.571Z',
    files: ['tree-sitter-go.wasm'],
  },
  {
    package: 'tree-sitter-python',
    version: '0.25.0',
    published: '2025-09-11T06:49:18.276Z',
    files: ['tree-sitter-python.wasm'],
  },
  {
    package: 'tree-sitter-typescript',
    version: '0.23.2',
    published: '2024-11-11T02:39:43.600Z',
    files: ['tree-sitter-typescript.wasm', 'tree-sitter-tsx.wasm'],
  },
];
const dest = path.resolve(import.meta.dirname, '../src/app/grammars');
fs.mkdirSync(dest, { recursive: true });
const packages = pins.map((pin) => {
  const dir = path.resolve(import.meta.dirname, '../node_modules', pin.package);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  if (pkg.version !== pin.version) throw new Error(`Expected ${pin.package}@${pin.version}, found ${pkg.version}`);
  const files = pin.files.map((file) => {
    const bytes = fs.readFileSync(path.join(dir, file));
    fs.writeFileSync(path.join(dest, file), bytes);
    return {
      file,
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  });
  const license = fs.readdirSync(dir).find((f) => /^licen[cs]e(?:\.|$)/i.test(f));
  if (!license) throw new Error('Missing parser licence');
  fs.copyFileSync(
    path.join(dir, license),
    path.join(dest, pin.package.replace(/^@/, '').replaceAll('/', '-') + '.LICENSE'),
  );
  return {
    package: pin.package,
    version: pin.version,
    published: pin.published,
    registry: `https://registry.npmjs.org/${pin.package}/${pin.version}`,
    license: pkg.license,
    files,
  };
});
fs.writeFileSync(
  path.join(dest, 'manifest.json'),
  JSON.stringify({ format: 'terratrust.parser-assets/v1', packages }, null, 2) + '\n',
);
