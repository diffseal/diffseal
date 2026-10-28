/**
 * Parses every `.tf` file under a directory with the Diffseal HCL parser and reports totals.
 *
 *   bun run scripts/parse-corpus.ts <dir>
 *
 * Prints file, block and diagnostic counts, then every diagnostic as file:line:col. Exits 1 when any
 * file has diagnostics, 2 on bad usage. Read-only: it never writes into the scanned directory.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Body } from '../src/hcl/ast.js';
import { parseHcl } from '../src/hcl/parser.js';

function findTfFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) findTfFiles(full, out);
    else if (entry.isFile() && entry.name.endsWith('.tf')) out.push(full);
  }
  return out;
}

function countBlocks(body: Body): number {
  return body.blocks.reduce((n, b) => n + 1 + countBlocks(b.body), 0);
}

const dir = process.argv[2];
if (!dir || !fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
  console.error('usage: bun run scripts/parse-corpus.ts <directory>');
  process.exit(2);
}

const files = findTfFiles(path.resolve(dir)).sort();
let lines = 0;
let topBlocks = 0;
let allBlocks = 0;
let diagCount = 0;
const failing: Array<{ file: string; messages: string[] }> = [];
const started = performance.now();

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  lines += src.split('\n').length;
  const { body, diagnostics } = parseHcl(src, file);
  topBlocks += body.blocks.length;
  allBlocks += countBlocks(body);
  diagCount += diagnostics.length;
  if (diagnostics.length > 0) {
    failing.push({
      file: path.relative(process.cwd(), file),
      messages: diagnostics.map((d) => `${d.range.start.line}:${d.range.start.col}: ${d.message}`),
    });
  }
}

const elapsed = performance.now() - started;
console.log(`files:       ${files.length}`);
console.log(`lines:       ${lines}`);
console.log(`blocks:      ${allBlocks} (${topBlocks} top-level)`);
console.log(`diagnostics: ${diagCount} in ${failing.length} file(s)`);
console.log(`time:        ${elapsed.toFixed(0)} ms`);
for (const f of failing) {
  console.log(`\n${f.file}`);
  for (const m of f.messages) console.log(`  ${f.file}:${m}`);
}
process.exit(diagCount > 0 ? 1 : 0);
