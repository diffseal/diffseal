#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { analyze } from './analysis/analyze.js';
import { readPlan } from './plan/readPlan.js';
import { renderMarkdown } from './report/markdown.js';
import { VERSION, renderReplay } from './replay/render.js';
import { replayCommit } from './replay/replay.js';

/*
 * MCP server for coding agents. Every tool is read-only: it reads repositories and plan files and
 * returns a report. Nothing is written, nothing leaves the machine.
 */

const server = new McpServer({ name: 'diffseal', version: VERSION });

type ToolResult = { content: Array<{ type: 'text'; text: string }>; structuredContent?: Record<string, unknown>; isError?: boolean };

async function run(fn: () => ToolResult | Promise<ToolResult>): Promise<ToolResult> {
  try {
    return await fn();
  } catch (e) {
    return { isError: true, content: [{ type: 'text', text: `Diffseal could not complete this check: ${(e as Error).message}` }] };
  }
}

server.registerTool(
  'diffseal_review_plan',
  {
    title: 'Review a Terraform plan',
    description:
      'Review the output of `terraform show -json <planfile>`: destructive changes to stateful resources and what forced them, ' +
      'policy checks mapped to ISO/IEC 27001:2022 controls, and fixed monthly cost changes.',
    inputSchema: { planJsonPath: z.string().describe('Path to the plan JSON file') },
  },
  async (args) =>
    run(async () => {
      const result = analyze(readPlan(JSON.parse(fs.readFileSync(path.resolve(args.planJsonPath), 'utf8'))));
      return {
        content: [{ type: 'text', text: renderMarkdown(result, { title: `Plan review of \`${path.basename(args.planJsonPath)}\`.`, version: VERSION }) }],
        structuredContent: { gate: result.gate.result, reasons: result.gate.reasons },
      };
    })
);

server.registerTool(
  'diffseal_replay_commit',
  {
    title: 'Replay a commit',
    description:
      'Statically replay one commit of a local clone, without credentials or terraform: which resources it creates, updates, ' +
      'replaces or deletes, and the policy findings it introduces.',
    inputSchema: {
      repo: z.string().describe('Path to the repository'),
      commit: z.string().describe('Commit to replay'),
      base: z.string().optional().describe('Compare against this revision instead of the first parent'),
    },
  },
  async (args) =>
    run(async () => {
      const r = await replayCommit({ repo: path.resolve(args.repo), head: args.commit, base: args.base });
      return { content: [{ type: 'text', text: renderReplay(r) }], structuredContent: { gate: r.combined.gate.result, reasons: r.combined.gate.reasons } };
    })
);

await server.connect(new StdioServerTransport());
