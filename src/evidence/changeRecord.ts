import { createHash } from 'node:crypto';
import type { AnalysisResult } from '../core/model.js';
import type { AppLink } from '../reconcile/reconcile.js';
import { frameworksFor, type FrameworkRefs } from '../compliance/crosswalk.js';
import type { CommitInfo } from '../terraform/source.js';

/**
 * One record per change, in the shape an auditor samples for ISO/IEC 27001:2022 A.8.32 (change
 * management): what changed, who wrote and approved it, what was checked, and what was found.
 * Records are append-only JSON; a period's records are sealed with a sha256 manifest.
 */

export interface Approvals {
  pr?: number;
  approvedBy: Array<{ login: string; at?: string }>;
  mergedBy?: string;
}

export interface ChangeRecord {
  schema: 'terratrust.change-record/v1';
  change: { commit: string; base: string; subject: string; author: string; date: string };
  approvals: Approvals | null;
  engine: { version: string; replaceCatalog: string; mode: 'static-replay' };
  roots: string[];
  gate: AnalysisResult['gate'];
  resources: Array<{ address: string; type: string; action: string; confidence: string; replacePaths?: string[][] }>;
  risks: Array<{ resource: string; severity: string; reason: string; accepted?: unknown }>;
  controls: Array<{
    control: string;
    rule: string;
    resource: string;
    status: string;
    detail: string;
    /** Crosswalk category of the rule, and the verified references in other frameworks for it. */
    category?: string;
    frameworks: FrameworkRefs;
    preExisting?: boolean;
    accepted?: unknown;
  }>;
  access: Array<{ status: string; callsite: string; actions: string[]; resource: string; detail: string }>;
  notes: string[];
}

export function changeRecord(input: {
  commit: CommitInfo;
  base: string;
  roots: string[];
  result: AnalysisResult;
  appLinks: AppLink[];
  approvals?: Approvals;
  engine: { version: string; replaceCatalog: string };
  /** HCL parse diagnostics at the change, as `file:line: message`. */
  diagnostics?: string[];
}): ChangeRecord {
  const { commit, result } = input;
  const notes: string[] = [];
  const diagnostics = [...new Set(input.diagnostics ?? [])];
  if (diagnostics.length) notes.push(`Terraform at this change does not parse, so it was checked only in part: ${diagnostics.join('; ')}`);
  if (!input.approvals) notes.push('No approvals were supplied for this change (pass --approvals with a GitHub export).');
  const likely = result.changes.filter((c) => c.confidence !== 'proven').length;
  if (likely) notes.push(`${likely} change(s) depend on values known only after apply; their action is likely, not proven.`);
  return {
    schema: 'terratrust.change-record/v1',
    change: { commit: commit.sha, base: input.base, subject: commit.subject, author: commit.author, date: commit.date },
    approvals: input.approvals ?? null,
    engine: { ...input.engine, mode: 'static-replay' },
    roots: input.roots,
    gate: result.gate,
    resources: result.changes.map((c) => ({
      address: c.address,
      type: c.type,
      action: c.action,
      confidence: c.confidence,
      ...(c.replacePaths ? { replacePaths: c.replacePaths } : {}),
    })),
    risks: result.blast.filter((b) => b.severity !== 'INFO').map((b) => ({ resource: b.resource, severity: b.severity, reason: b.reason, ...(b.accepted ? { accepted: b.accepted } : {}) })),
    controls: result.findings.flatMap((f) =>
      f.controls.map((control) => ({
        control,
        rule: f.ruleId,
        resource: f.resource,
        status: f.status,
        detail: f.detail,
        ...frameworksFor(f.ruleId),
        ...(f.preExisting ? { preExisting: true } : {}),
        ...(f.accepted ? { accepted: f.accepted } : {}),
      }))
    ),
    access: input.appLinks.map((l) => ({ status: l.status, callsite: l.callsite, actions: l.actions, resource: l.resource, detail: l.detail })),
    notes,
  };
}

/** `sha256  file` lines, sorted by file name, as `sha256sum -c` reads them. */
export function manifest(files: Record<string, string>): string {
  return (
    Object.keys(files)
      .sort()
      .map((f) => `${createHash('sha256').update(files[f]).digest('hex')}  ${f}`)
      .join('\n') + '\n'
  );
}

/**
 * Approvals per commit from a JSON export: { "<sha>": { "pr": 42, "approvedBy": [{ "login": "a", "at": "..." }], "mergedBy": "b" } }.
 * Produce it read-only with the GitHub CLI; TerraTrust makes no network calls itself.
 */
export function loadApprovals(text: string): Map<string, Approvals> {
  const data = JSON.parse(text) as Record<string, Approvals>;
  return new Map(Object.entries(data));
}
