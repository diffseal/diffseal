import { createHash } from 'node:crypto';
import { hasRedacted, isUnknown, type AnalysisResult } from '../core/model.js';
import { changedAttrs } from '../analysis/blastRadius.js';
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

/** Contract section 1, shared/src/record.ts. */
export interface Accepted {
  reason?: string;
  owner?: string;
  expires?: string;
}

export interface ChangeRecord {
  schema: 'diffseal.change-record/v1';
  change: { commit: string; base: string; subject: string; author: string; date: string };
  approvals: Approvals | null;
  engine: { version: string; replaceCatalog: string; mode: 'static-replay' };
  roots: string[];
  gate: AnalysisResult['gate'];
  resources: Array<{
    address: string;
    type: string;
    action: string;
    confidence: string;
    replacePaths?: string[][];
    /**
     * For an update or a replace: the names of the top-level settings that changed, sorted, at most
     * CHANGED_NAMES_MAX. Absent when no setting can be named, as when the prior values are not known. An
     * absent list does not mean nothing changed.
     */
    changed?: string[];
    /** How many more settings changed than `changed` lists. */
    changedMore?: number;
    /**
     * Old and new values, only for the settings in RECORD_VALUES and only when the value has the shape
     * that setting allows. A value marked sensitive is `(sensitive)`; one known only after apply is
     * `(known after apply)`; a setting that is absent on one side is `(not set)`.
     */
    values?: Array<{ attribute: string; before: string; after: string }>;
  }>;
  risks: Array<{ resource: string; severity: string; reason: string; accepted?: Accepted }>;
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
    accepted?: Accepted;
  }>;
  /**
   * Required by `diffseal.change-record/v1`. It held application access checks, which were removed;
   * it is always empty now, and stays so records keep the schema the evidence service validates.
   */
  access: Array<{ status: string; callsite: string; actions: string[]; resource: string; detail: string }>;
  notes: string[];
}

export function changeRecord(input: {
  commit: CommitInfo;
  base: string;
  roots: string[];
  result: AnalysisResult;
  approvals?: Approvals;
  engine: { version: string; replaceCatalog: string };
  /** HCL parse diagnostics at the change, as `file:line: message`. */
  diagnostics?: string[];
  /** What the replay could not cover that does not change the gate (workspaces not found, a mapping problem). */
  replayNotes?: string[];
  /** Serialized size the record is trimmed to; MAX_RECORD_BYTES unless a test says otherwise. */
  maxBytes?: number;
  /**
   * Where else a trimmed record says the full list is, as in "the diffseal-0123456 artifact of this run".
   * The note names the replay report for the commit too, which can be written again after the artifact expires.
   */
  fullListIn?: string;
}): ChangeRecord {
  const { commit, result } = input;
  const notes: string[] = [];
  const diagnostics = [...new Set(input.diagnostics ?? [])];
  if (diagnostics.length) notes.push(`Terraform at this change does not parse, so it was checked only in part: ${diagnostics.join('; ')}`);
  if (!input.approvals) notes.push('No approvals were supplied for this change (pass --approvals with a GitHub export).');
  const likely = result.changes.filter((c) => c.confidence !== 'proven').length;
  if (likely) notes.push(`${likely} change(s) depend on values known only after apply; their action is likely, not proven.`);
  for (const n of input.replayNotes ?? []) notes.push(`${n}.`);
  return fitRecord({
    schema: 'diffseal.change-record/v1',
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
      ...whatChanged(c),
    })),
    risks: result.blast.filter((b) => b.severity !== 'INFO').map((b) => ({ resource: b.resource, severity: b.severity, reason: b.reason, ...(b.accepted ? { accepted: b.accepted } : {}) })),
    // Keep existing rows per ISO control, with a SOC 2 fallback for findings that have no ISO tag.
    controls: result.findings.flatMap((f) => {
      const iso = f.controls.filter((control) => !control.startsWith('SOC2:'));
      return (iso.length ? iso : f.controls).map((control) => ({
        control,
        rule: f.ruleId,
        resource: f.resource,
        status: f.status,
        detail: f.detail,
        ...frameworksFor(f.ruleId),
        ...(f.preExisting ? { preExisting: true } : {}),
        ...(f.accepted ? { accepted: f.accepted } : {}),
      }));
    }),
    access: [],
    notes,
  }, input.maxBytes ?? MAX_RECORD_BYTES, `${input.fullListIn ? `${input.fullListIn}, and in ` : ''}the replay report for this commit (the JSON that diffseal replay writes)`);
}

export const CHANGED_NAMES_MAX = 32;

const INTEGER = /^-?\d{1,9}$/;
const BOOLEAN = /^(true|false)$/;
const SCHEDULE = /^(rate\(\d{1,6} (minute|minutes|hour|hours|day|days)\)|cron\([0-9A-Z*?,/#\- ]{1,100}\)|at\(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\))$/;

/**
 * The only settings whose values a record carries, each with the shape its value must have. They are
 * operational settings an auditor reads a routine change by: size, version, timeout and schedule. A value
 * of any other shape is left out, so a secret typed into one of these settings does not leave CI. Adding a
 * setting here widens what the Action uploads: the upload section of docs/guide/action.md must say so.
 */
export const RECORD_VALUES: Record<string, Record<string, RegExp>> = {
  aws_cloudwatch_event_rule: { schedule_expression: SCHEDULE, state: /^(ENABLED|DISABLED|ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS)$/, is_enabled: BOOLEAN },
  aws_scheduler_schedule: { schedule_expression: SCHEDULE, state: /^(ENABLED|DISABLED)$/ },
  aws_lambda_function: { memory_size: INTEGER, timeout: INTEGER, reserved_concurrent_executions: INTEGER },
  aws_db_instance: { instance_class: /^db\.[a-z0-9-]{1,20}\.[a-z0-9-]{1,20}$/, engine_version: /^\d{1,4}(\.[0-9A-Za-z_-]{1,20}){0,8}$/, allocated_storage: INTEGER },
};

/** A top-level setting name; anything else is counted in `changedMore`, never printed. */
const SETTING_NAME = /^[a-z_][a-z0-9_]{0,63}$/;

/** What changed in one resource, for the record: the names of changed settings and the listed values. */
function whatChanged(c: AnalysisResult['changes'][number]): Pick<ChangeRecord['resources'][number], 'changed' | 'changedMore' | 'values'> {
  if ((c.action !== 'update' && c.action !== 'replace') || !c.before || !c.after) return {};
  // Static replay names what its comparison found changed (set order, null semantics, ignore_changes and
  // settings that read a replaced resource); a plan is compared here.
  const listed = Object.entries(RECORD_VALUES[c.type] ?? {}).map(([attribute, shape]) => ({ attribute, before: shown(c.before![attribute], shape), after: shown(c.after![attribute], shape) }));
  // A listed setting whose two sides read the same (`20` and `"20"`, or null and absent) did not change.
  const same = new Set(listed.filter((v) => v.before !== undefined && v.before === v.after && v.before !== '(sensitive)' && v.before !== '(known after apply)').map((v) => v.attribute));
  const all = [...new Set(c.changedKeys ?? changedAttrs(c.before, c.after))].filter((a) => a !== 'tags_all' && !same.has(a)).sort();
  const names = all.filter((a) => SETTING_NAME.test(a));
  const changed = names.slice(0, CHANGED_NAMES_MAX);
  const values = listed
    .filter((v) => changed.includes(v.attribute) && v.before !== undefined && v.after !== undefined)
    .sort((a, b) => (a.attribute < b.attribute ? -1 : 1)) as Array<{ attribute: string; before: string; after: string }>;
  return {
    ...(changed.length ? { changed } : {}),
    ...(all.length > changed.length ? { changedMore: all.length - changed.length } : {}),
    ...(values.length ? { values } : {}),
  };
}

/** A listed setting's value as the record shows it, or undefined when it does not have the allowed shape. */
function shown(v: unknown, shape: RegExp): string | undefined {
  if (v === undefined || v === null) return '(not set)';
  if (hasRedacted(v)) return '(sensitive)';
  if (isUnknown(v)) return '(known after apply)';
  if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') return undefined;
  const text = String(v);
  return shape.test(text) ? text : undefined;
}

/**
 * The evidence service rejects an upload over 1 MiB, and the upload wraps the record. A record over this
 * size leaves out resources until it fits.
 */
export const MAX_RECORD_BYTES = 900 * 1024;

const SEVERITY_RANK: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const STATUS_RANK: Record<string, number> = { INFO: 0, PASS: 0, UNKNOWN: 1, WARN: 2, FAIL: 3 };
const UNCHANGED = new Set(['no-op', 'read', 'move', 'forget']);

/**
 * A resource address without the root labels a replay of several roots puts before it (`a, b: x` is `x`):
 * what follows the first `: ` that starts an address. An instance key is quoted, so a `: ` after a quote is
 * part of the address.
 */
function bareAddress(address: string): string {
  for (let i = address.indexOf(': '); i >= 0 && !address.slice(0, i).includes('"'); i = address.indexOf(': ', i + 1)) {
    if (/^[a-z][a-z0-9_]*\.[A-Za-z_]/.test(address.slice(i + 2))) return address.slice(i + 2);
  }
  return address;
}

/**
 * Leave out resources, with their risks and findings, until the serialized record fits in `maxBytes`:
 * the lowest risk first, and among those the unchanged ones and those whose action is unknown. A resource
 * a gate item names is always kept, so every risk and finding that raises the gate stays, and the gate,
 * its reasons and items, and the roots are never touched. A note says how many were left out and that the
 * full list is in `fullListIn`.
 */
function fitRecord(record: ChangeRecord, maxBytes: number, fullListIn: string): ChangeRecord {
  const size = (r: ChangeRecord) => Buffer.byteLength(JSON.stringify(r));
  if (size(record) <= maxBytes) return record;
  // With several roots, rows carry root labels (`a: x`, or `a, b: x` for a row the same in both) and gate
  // items name the bare address; a resource is kept or left out in every root together.
  // What raises the gate: a resource a gate item names, and, since a blocked gate lists only what blocks,
  // every new FAIL and every HIGH or CRITICAL risk not accepted.
  const protectedResources = new Set([
    ...record.gate.items.flatMap((i) => (i.resource ? [i.resource] : [])),
    ...record.risks.filter((r) => (r.severity === 'HIGH' || r.severity === 'CRITICAL') && !r.accepted).map((r) => bareAddress(r.resource)),
    ...record.controls.filter((c) => c.status === 'FAIL' && !c.preExisting && !c.accepted).map((c) => bareAddress(c.resource)),
  ]);
  // A row a gate item names is kept whatever its labels look like.
  const protectedList = [...protectedResources];
  const gated = (address: string) => protectedResources.has(bareAddress(address)) || protectedList.some((r) => address === r || address.endsWith(`: ${r}`));
  // Rank each resource by its worst risk or finding (a FAIL weighs as a HIGH risk), then by how sure its change is.
  const rank = new Map<string, [number, number]>();
  const at = (address: string) => rank.get(bareAddress(address)) ?? rank.set(bareAddress(address), [-1, 2]).get(bareAddress(address))!;
  for (const r of record.resources) {
    const k = at(r.address);
    k[1] = Math.min(k[1], UNCHANGED.has(r.action) || r.confidence === 'unknown' ? 0 : r.confidence === 'proven' ? 2 : 1);
  }
  for (const r of record.risks) { const k = at(r.resource); k[0] = Math.max(k[0], SEVERITY_RANK[r.severity] ?? 4); }
  for (const c of record.controls) { const k = at(c.resource); k[0] = Math.max(k[0], STATUS_RANK[c.status] ?? 3); }
  const order = [...rank.entries()]
    .filter(([address]) => !protectedResources.has(address))
    .sort(([, a], [, b]) => a[0] - b[0] || a[1] - b[1])
    .map(([address]) => address);
  // Bytes each resource takes, a comma included, to estimate how many must go before measuring again.
  const bytes = new Map<string, number>();
  const add = (address: string, row: unknown) => bytes.set(bareAddress(address), (bytes.get(bareAddress(address)) ?? 0) + Buffer.byteLength(JSON.stringify(row)) + 1);
  for (const r of record.resources) add(r.address, r);
  for (const r of record.risks) add(r.resource, r);
  for (const c of record.controls) add(c.resource, c);
  const total = record.resources.length;
  const build = (left: Set<string>): ChangeRecord => {
    const kept = (address: string) => !left.has(bareAddress(address)) || gated(address);
    const resources = record.resources.filter((r) => kept(r.address));
    const dropped = total - resources.length;
    return {
      ...record,
      resources,
      risks: record.risks.filter((r) => kept(r.resource)),
      controls: record.controls.filter((c) => kept(c.resource)),
      notes: [
        ...record.notes,
        `${dropped} of ${total} resource entries were left out, with their risks and findings, to keep this record under the evidence service's upload limit: the lowest risk first, and unchanged ones or ones whose action is unknown before the others. None of them raises the gate. The full list is in ${fullListIn}.`,
      ],
    };
  };
  const left = new Set<string>();
  let excess = size(record) - maxBytes + 1024;
  let i = 0;
  for (;;) {
    while (excess > 0 && i < order.length) { excess -= bytes.get(order[i])!; left.add(order[i++]); }
    const trimmed = build(left);
    const over = size(trimmed) - maxBytes;
    if (over <= 0 || i >= order.length) return trimmed;
    excess = over;
  }
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
 * Produce it read-only with the GitHub CLI; Diffseal makes no network calls itself.
 */
export function loadApprovals(text: string): Map<string, Approvals> {
  const data = JSON.parse(text) as Record<string, Approvals>;
  return new Map(Object.entries(data));
}
