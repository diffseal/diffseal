import { expect, test } from 'bun:test';
import { ExtractionCache } from './cache.js';
import { scanApp } from './scan.js';
import { MemorySource } from '../terraform/source.js';

const helper = (bucket: string) =>
  `package helper\nimport "github.com/aws/aws-sdk-go-v2/service/s3"\nfunc Read(){ _ = &s3.GetObjectInput{Bucket: aws.String("${bucket}")} }\n`;
const files = (bucket: string) => ({
  'go.mod': 'module example.com/app\n',
  'helper/read.go': helper(bucket),
  'cmd/main.go': 'package main\nimport "example.com/app/helper"\nfunc main(){ helper.Read() }\n',
  'app.ts': 'import {PutObjectCommand} from "@aws-sdk/client-s3";\nnew PutObjectCommand({Bucket:"uploads"});\n',
});

test('unchanged file summaries are reused while changes to helpers invalidate their callers', () => {
  const cache = new ExtractionCache();
  const first = scanApp(new MemorySource(files('first')), { cache });
  const before = cache.stats();
  const again = scanApp(new MemorySource(files('first')), { cache });
  expect(again).toEqual(first);
  expect(cache.stats().hits).toBeGreaterThan(before.hits);
  const changed = scanApp(new MemorySource(files('second')), { cache });
  expect(changed).toEqual(scanApp(new MemorySource(files('second')), { cache: new ExtractionCache({ maxBytes: 0 }) }));
  expect(changed.facts.filter((f) => f.file === 'cmd/main.go').map((f) => f.resource)).toEqual([
    { kind: 'literal', value: 'second' },
  ]);
});

test('cache hits preserve changed-line filtering and file names after a rename', () => {
  const cache = new ExtractionCache();
  const text =
    'import {PutObjectCommand} from "@aws-sdk/client-s3";\nnew PutObjectCommand({\n Bucket:"uploads",\n});\n';
  const first = scanApp(new MemorySource({ 'a.ts': text }), { cache, addedLines: new Map([['a.ts', new Set([3])]]) });
  expect(first.facts).toHaveLength(1);
  const unchangedLines = scanApp(new MemorySource({ 'a.ts': text }), {
    cache,
    addedLines: new Map([['a.ts', new Set([1])]]),
  });
  expect(unchangedLines.facts).toHaveLength(0);
  const renamed = scanApp(new MemorySource({ 'b.ts': text }), { cache });
  expect(renamed.facts[0].file).toBe('b.ts');
  expect(renamed).toEqual(
    scanApp(new MemorySource({ 'b.ts': text }), { cache: new ExtractionCache({ maxEntries: 0 }) }),
  );
});
