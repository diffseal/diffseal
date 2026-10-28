/** Package the current build for an offline, advisory pilot. Never changes Git refs or settings. */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { VERSION } from '../src/replay/render.js';
const root = path.resolve(import.meta.dirname, '..');
const destination = process.argv[2] && path.resolve(process.argv[2]);
if (!destination) throw Error('Usage: bun scripts/prepare-pilot.ts <new-or-empty-output-folder>');
if (destination === root || (destination.startsWith(root + path.sep) && !destination.startsWith(path.join(root, 'dry-runs') + path.sep))) throw Error('Pilot output inside the repository must be under ignored dry-runs');
if (fs.existsSync(destination) && (!fs.statSync(destination).isDirectory() || fs.readdirSync(destination).length)) throw Error('Pilot output must be a new or empty folder');
if (JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version !== VERSION) throw Error('Package and engine versions differ');
const dist = path.join(root, 'dist');
// The pilot vendors only the Action, whose bundle and parser assets are committed, so this works from a fresh clone.
const files = fs.readdirSync(dist).filter((file) => file === 'action.js' || /\.wasm(?:-[^.]+\.gz)?$/.test(file));
if (files.filter((file) => /\.wasm(?:-[^.]+\.gz)?$/.test(file)).length !== 8 || !files.includes('action.js')) throw Error('dist/ is incomplete; the package needs action.js and eight parser assets');
const tool = path.join(destination, '.github/actions/diffseal');
fs.mkdirSync(path.join(tool, 'dist/licenses'), { recursive: true });
for (const file of files) fs.copyFileSync(path.join(dist, file), path.join(tool, 'dist', file));
for (const file of fs.readdirSync(path.join(root, 'src/app/grammars')).filter((file) => file.endsWith('.LICENSE') || file === 'manifest.json')) fs.copyFileSync(path.join(root, 'src/app/grammars', file), path.join(tool, 'dist/licenses', file));
for (const file of ['action.yml', 'LICENSE']) fs.copyFileSync(path.join(root, file), path.join(tool, file));
fs.writeFileSync(path.join(destination, 'VERSION'), VERSION + '\n');
fs.writeFileSync(path.join(tool, 'VERSION'), VERSION + '\n');
fs.mkdirSync(path.join(destination, '.github/workflows'), { recursive: true });
fs.writeFileSync(path.join(destination, '.github/workflows/diffseal.yml'), `name: Diffseal advisory pilot
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  diffseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Review changes
        uses: ./.github/actions/diffseal
        continue-on-error: true
        with:
          mode: pr
          advisory: 'true'
          strict: 'false'
`);
const rows: string[] = [];
function walk(dir: string) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else rows.push(createHash('sha256').update(fs.readFileSync(full)).digest('hex') + '  ' + path.relative(destination!, full).split(path.sep).join('/'));
  }
}
walk(destination);
fs.writeFileSync(path.join(destination, 'MANIFEST.sha256'), rows.join('\n') + '\n');
console.log(`Prepared advisory pilot ${VERSION}`);
