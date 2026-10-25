/**
 * Extract a compact provider schema snapshot from `terraform providers schema -json`
 * for a pinned release of `hashicorp/aws`.
 *
 *   bun run scripts/extract-schema.ts [version] > src/terraform/aws-schema.json
 *
 * Runs `terraform init` in a temporary directory with an isolated TF_DATA_DIR and
 * `CHECKPOINT_DISABLE=1`, then runs `terraform providers schema -json` offline with
 * no cloud credentials.
 */
import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const version = (process.argv[2] ?? '6.70.0').replace(/^v/, '');
const MAX_DEPTH = 3;

interface SchemaAttribute {
  type?: unknown;
  nested_type?: {
    nesting_mode?: string;
    attributes?: Record<string, SchemaAttribute>;
  };
  required?: boolean;
  optional?: boolean;
  computed?: boolean;
  sensitive?: boolean;
  write_only?: boolean;
}

interface SchemaBlockType {
  nesting_mode: string;
  min_items?: number;
  max_items?: number;
  block?: SchemaBlock;
}

interface SchemaBlock {
  attributes?: Record<string, SchemaAttribute>;
  block_types?: Record<string, SchemaBlockType>;
}

interface ResourceEntry {
  bool?: string[];
  number?: string[];
  computed?: string[];
  sensitive?: string[];
  write_only?: string[];
  blocks?: Record<string, string>;
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-schema-'));
try {
  fs.writeFileSync(
    path.join(tmpDir, 'main.tf'),
    `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= ${version}"
    }
  }
}
`
  );

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    CHECKPOINT_DISABLE: '1',
    TF_IN_AUTOMATION: '1',
    TF_DATA_DIR: path.join(tmpDir, '.terraform'),
    AWS_CONFIG_FILE: '/dev/null',
    AWS_SHARED_CREDENTIALS_FILE: '/dev/null',
  };
  for (const k of Object.keys(env)) {
    if (k.startsWith('AWS_') && k !== 'AWS_CONFIG_FILE' && k !== 'AWS_SHARED_CREDENTIALS_FILE') {
      delete env[k];
    }
  }

  const tfVerRes = spawnSync('terraform', ['version', '-json'], { cwd: tmpDir, env, encoding: 'utf8' });
  if (tfVerRes.status !== 0) {
    console.error('terraform version failed:', tfVerRes.stderr);
    process.exit(1);
  }
  const tfVersion = (JSON.parse(tfVerRes.stdout) as { terraform_version: string }).terraform_version;

  const initRes = spawnSync('terraform', ['init', '-input=false', '-no-color'], {
    cwd: tmpDir,
    env,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (initRes.status !== 0) {
    console.error('terraform init failed:', initRes.stderr || initRes.stdout);
    process.exit(1);
  }

  const lockContent = fs.readFileSync(path.join(tmpDir, '.terraform.lock.hcl'), 'utf8');
  const h1Match = lockContent.match(/"(h1:[^"]+)"/);
  const h1 = h1Match ? h1Match[1] : 'unknown';

  const schemaRes = spawnSync('terraform', ['providers', 'schema', '-json'], {
    cwd: tmpDir,
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (schemaRes.status !== 0) {
    console.error('terraform providers schema -json failed:', schemaRes.stderr?.toString('utf8'));
    process.exit(1);
  }

  const rawBuf = schemaRes.stdout;
  const schemaSha256 = crypto.createHash('sha256').update(rawBuf).digest('hex');
  const parsed = JSON.parse(rawBuf.toString('utf8')) as {
    format_version: string;
    provider_schemas: Record<
      string,
      {
        resource_schemas?: Record<string, { version: number; block: SchemaBlock }>;
      }
    >;
  };

  const providerKey = 'registry.terraform.io/hashicorp/aws';
  const resourceSchemas = parsed.provider_schemas?.[providerKey]?.resource_schemas ?? {};

  const resources: Record<string, ResourceEntry> = {};

  for (const type of Object.keys(resourceSchemas).sort()) {
    const rootBlock = resourceSchemas[type].block;
    const boolSet = new Set<string>();
    const numberSet = new Set<string>();
    const computedSet = new Set<string>();
    const sensitiveSet = new Set<string>();
    const writeOnlySet = new Set<string>();
    const blocksMap: Record<string, string> = {};

    const walkCtyType = (ctyType: unknown, p: string, depth: number) => {
      if (depth > MAX_DEPTH) return;
      if (ctyType === 'bool') {
        boolSet.add(p);
      } else if (ctyType === 'number') {
        numberSet.add(p);
      } else if (Array.isArray(ctyType)) {
        const [kind, elem] = ctyType;
        if (kind === 'list' || kind === 'set') {
          walkCtyType(elem, p, depth);
        } else if (kind === 'object' && elem && typeof elem === 'object' && !Array.isArray(elem)) {
          if (depth + 1 <= MAX_DEPTH) {
            for (const [field, fieldType] of Object.entries(elem as Record<string, unknown>)) {
              walkCtyType(fieldType, `${p}.${field}`, depth + 1);
            }
          }
        }
      }
    };

    const walkAttrs = (attrs: Record<string, SchemaAttribute> | undefined, prefix: string, depth: number) => {
      if (!attrs || depth > MAX_DEPTH) return;
      for (const [name, attr] of Object.entries(attrs)) {
        const p = prefix ? `${prefix}.${name}` : name;
        if (attr.computed && !attr.optional && !attr.required) computedSet.add(p);
        if (attr.sensitive) sensitiveSet.add(p);
        if (attr.write_only) writeOnlySet.add(p);
        if (attr.type !== undefined) walkCtyType(attr.type, p, depth);
        if (attr.nested_type?.attributes && depth + 1 <= MAX_DEPTH) {
          walkAttrs(attr.nested_type.attributes, p, depth + 1);
        }
      }
    };

    const walkBlock = (block: SchemaBlock | undefined, prefix: string, depth: number) => {
      if (!block || depth > MAX_DEPTH) return;
      walkAttrs(block.attributes, prefix, depth);
      for (const [blockName, bt] of Object.entries(block.block_types ?? {})) {
        const p = prefix ? `${prefix}.${blockName}` : blockName;
        const mode = bt.nesting_mode === 'list' && bt.max_items === 1 ? 'list1' : bt.nesting_mode;
        blocksMap[p] = mode;
        if (bt.block && depth + 1 <= MAX_DEPTH) {
          walkBlock(bt.block, p, depth + 1);
        }
      }
    };

    walkBlock(rootBlock, '', 1);

    const entry: ResourceEntry = {};
    if (boolSet.size) entry.bool = [...boolSet].sort();
    if (numberSet.size) entry.number = [...numberSet].sort();
    if (computedSet.size) entry.computed = [...computedSet].sort();
    if (sensitiveSet.size) entry.sensitive = [...sensitiveSet].sort();
    if (writeOnlySet.size) entry.write_only = [...writeOnlySet].sort();
    const sortedBlockKeys = Object.keys(blocksMap).sort();
    if (sortedBlockKeys.length) {
      entry.blocks = Object.fromEntries(sortedBlockKeys.map((k) => [k, blocksMap[k]]));
    }
    resources[type] = entry;
  }

  const output = {
    source: providerKey,
    version,
    lock: { h1 },
    terraform: tfVersion,
    format_version: parsed.format_version,
    schema_sha256: schemaSha256,
    max_depth: MAX_DEPTH,
    resources,
  };

  process.stdout.write(JSON.stringify(output, null, 1) + '\n');
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
