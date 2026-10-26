import { describe, expect, test } from 'bun:test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runFixtureCase, type FixtureSuite } from './fixtures.js';

function findFixtureFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findFixtureFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.json')) out.push(full);
  }
  return out.sort();
}

const fixturesDir = path.resolve(import.meta.dirname, '../../fixtures');
const files = findFixtureFiles(fixturesDir);

describe('implementation-independent specification fixtures', () => {
  test('fixture directory contains suites', async () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const file of files) {
    const rel = path.relative(fixturesDir, file);
    const suite = JSON.parse(fs.readFileSync(file, 'utf8')) as FixtureSuite;
    describe(`${rel}: ${suite.suite}`, () => {
      for (const tc of suite.cases) {
        test(tc.name, async () => {
          await runFixtureCase(tc);
        });
      }
    });
  }
});
