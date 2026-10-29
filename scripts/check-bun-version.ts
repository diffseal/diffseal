// dist/ is committed and the release workflow rebuilds it and fails on any difference.
// Different Bun versions bundle differently, so build only with the version CI pins.
import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
const pinned = workflow.match(/bun-version:\s*'([^']+)'/)?.[1];
if (!pinned) throw new Error('No bun-version found in .github/workflows/release.yml');
if (Bun.version !== pinned) {
  console.error(`dist/ must be built with Bun ${pinned} (the release workflow's version), not ${Bun.version}.`);
  console.error(`Run: npx -y bun@${pinned} run build`);
  process.exit(1);
}
