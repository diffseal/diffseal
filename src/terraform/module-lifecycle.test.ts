import { expect, test } from 'bun:test';
import { MemorySource } from './source.js';
import { evaluateRoot } from './expand.js';
import { compareEvaluations } from './compare.js';
for (const meta of ['count', 'for_each'])
  test(`a local module retains prevent_destroy when ${meta} removes every instance`, () => {
    const config = (live: boolean) =>
      new MemorySource({
        'main.tf': `module "guarded" {\n source="./child"\n ${meta}=${meta === 'count' ? (live ? '1' : '0') : live ? '{one=true}' : '{}'}\n}`,
        'child/main.tf': 'resource "terraform_data" "guarded" {\n input="keep"\n lifecycle { prevent_destroy=true }\n}',
      });
    const before = evaluateRoot(config(true), '.'),
      after = evaluateRoot(config(false), '.');
    const changes = compareEvaluations(before, after).filter((c) => c.action === 'delete');
    expect(changes).toHaveLength(1);
    expect(changes[0].preventDestroy).toBe(true);
  });
