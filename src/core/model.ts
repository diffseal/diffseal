/**
 * Core contracts shared by plan review and static replay.
 * Every analyzer consumes ResourceChange[]; where it came from (plan JSON or static HCL) does not matter.
 */

/** A value Terraform will only know after apply, or that static evaluation could not resolve. */
export class Unknown {
  /**
   * @param reason why the value is unknown
   * @param pattern for strings built from a template: the known text with each unknown part replaced by
   *   `{?}`, e.g. `arn:aws:secretsmanager:{?}:{?}:secret:provider/*`. `{?}` alone means "an attribute of
   *   a referenced resource", such as `aws_s3_bucket.b.arn`.
   * @param refs resource addresses the value was derived from
   */
  constructor(
    readonly reason: string,
    readonly pattern?: string,
    readonly refs: string[] = []
  ) {}
  toJSON() {
    return this.pattern !== undefined ? `(unknown: ${this.pattern})` : `(unknown: ${this.reason})`;
  }
}

export const UNKNOWN_PART = '{?}';

/**
 * A value that must never be printed. Rules still judge it: the value is held in a private field that
 * JSON, string conversion and inspection do not reach, and only `reveal()` returns it. The digest is
 * keyed per process, so two values can be compared within a run but a printed digest cannot be
 * matched against guesses.
 */
export class Redacted {
  readonly #value: unknown;
  readonly #known: boolean;
  // Private, so nothing that walks an object's own keys (Object.keys, for_each, iteration) sees it.
  readonly #digest: string | undefined;
  constructor(digest?: string, ...value: [] | [unknown]) {
    this.#digest = digest;
    this.#known = value.length > 0;
    this.#value = value[0];
  }
  get digest(): string | undefined {
    return this.#digest;
  }
  /** The hidden value, or undefined when only the fact that it is sensitive is known. */
  get revealed(): { value: unknown } | undefined {
    return this.#known ? { value: this.#value } : undefined;
  }
  toJSON() {
    return '(sensitive)';
  }
  toString() {
    return '(sensitive)';
  }
}

export const isUnknown = (v: unknown): v is Unknown => v instanceof Unknown;
export const isRedacted = (v: unknown): v is Redacted => v instanceof Redacted;

/** Replace every Redacted whose value is known by that value, deeply. For judging, never for printing. */
export function reveal(v: unknown): unknown {
  if (isRedacted(v)) {
    const r = v.revealed;
    return r ? reveal(r.value) : v;
  }
  if (Array.isArray(v)) return v.some(hasRedacted) ? v.map(reveal) : v;
  if (v && typeof v === 'object' && !isUnknown(v) && Object.getPrototypeOf(v) === Object.prototype) {
    return hasRedacted(v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, reveal(x)])) : v;
  }
  return v;
}

export function hasRedacted(v: unknown): boolean {
  if (isRedacted(v)) return true;
  if (Array.isArray(v)) return v.some(hasRedacted);
  if (v && typeof v === 'object' && !isUnknown(v) && Object.getPrototypeOf(v) === Object.prototype) return Object.values(v).some(hasRedacted);
  return false;
}

/**
 * The printable leaves (strings and numbers) hidden inside Redacted values, to scrub them from text.
 * Leaves shorter than three characters are left alone: replacing every `1` or `22` would garble reports.
 */
export function sensitiveLeaves(v: unknown, inside = false, out: string[] = []): string[] {
  if (isRedacted(v)) {
    const r = v.revealed;
    if (r) sensitiveLeaves(r.value, true, out);
  } else if (Array.isArray(v)) {
    for (const x of v) sensitiveLeaves(x, inside, out);
  } else if (isUnknown(v)) {
    // The known text of a partly unknown sensitive string, without ARN scaffolding ("arn:aws:iam::").
    if (inside && v.pattern) for (const part of v.pattern.split(UNKNOWN_PART)) if (worthHiding(part.replace(ARN_PREFIX, ''))) out.push(part);
  } else if (v && typeof v === 'object') {
    for (const x of Object.values(v)) sensitiveLeaves(x, inside, out);
  } else if (inside && (typeof v === 'string' || typeof v === 'number') && worthHiding(String(v))) {
    out.push(String(v));
    // A sensitive JSON document (a policy, container definitions) hides every value inside it too.
    if (typeof v === 'string' && /^\s*[[{]/.test(v)) {
      try {
        sensitiveLeaves(JSON.parse(v), true, out);
      } catch {
        // not JSON
      }
    }
  }
  return out;
}

// Partition, service and region only: the account may be the sensitive part.
const ARN_PREFIX = /^arn:aws[\w-]*:[\w-]*:[\w-]*:/;

/**
 * Whether a sensitive leaf is specific enough to scrub from reports. Short values, policy grammar and
 * IAM action names are not secrets, and replacing them everywhere would garble every report.
 */
function worthHiding(x: string): boolean {
  const core = x.replace(/^[:/]+|[:/]+$/g, '');
  return core.length >= 4 && !POLICY_GRAMMAR.has(core) && !/^[a-z][a-z0-9-]*:[A-Za-z*?][A-Za-z0-9*?]*$/.test(core);
}

/**
 * The free-text fields of analysis results, the only ones a sensitive value can reach. Everything else
 * is an address, an id or an enum the gate and the reports compute with (`gate.result`, `status`), and
 * scrubbing those would change verdicts.
 */
export const ANALYSIS_TEXT = new Set(['detail', 'remediation', 'reason', 'reasons', 'note']);

/** Strings under the given text fields, scrubbed of sensitive leaves. Other values are kept as they are. */
export function scrubDeep<T>(v: T, leaves: string[], text: Set<string> = ANALYSIS_TEXT): T {
  if (!leaves.length) return v;
  const go = (x: unknown, inText: boolean): unknown => {
    if (typeof x === 'string') return inText ? scrub(x, leaves) : x;
    if (Array.isArray(x)) return x.map((y) => go(y, inText));
    if (x && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype) {
      return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, go(y, inText || text.has(k))]));
    }
    return x;
  };
  return go(v, false) as T;
}

const POLICY_GRAMMAR = new Set(['Allow', 'Deny', '2012-10-17', '2008-10-17', 'root', 'true', 'false', 'null']);

/** Replace sensitive leaves in text, longest first, so no part of a hidden value is printed. */
export function scrub(text: string, leaves: string[]): string {
  if (!leaves.length || !text) return text;
  for (const leaf of [...new Set(leaves)].sort((a, b) => b.length - a.length)) text = text.split(leaf).join('(sensitive)');
  return text;
}

export type Action = 'create' | 'update' | 'replace' | 'delete' | 'no-op' | 'read' | 'import' | 'forget' | 'move';

export type Attrs = Record<string, unknown>;

export interface SourceRef {
  file: string;
  line: number;
}

export interface ResourceChange {
  /** Full instance address, e.g. `module.orders.aws_sqs_queue.queue["a"]`. */
  address: string;
  type: string;
  name: string;
  mode: 'managed' | 'data';
  /** `module.orders` for resources inside modules. */
  moduleAddress?: string;
  /** Selected provider configuration, used to scope account/regional configuration helpers. */
  providerAddress?: string;
  action: Action;
  before: Attrs | null;
  after: Attrs | null;
  /** Attribute paths that forced replacement, when known. */
  replacePaths?: string[][];
  /** `delete-first` (default Terraform behaviour) or `create-first` (create_before_destroy). */
  replaceOrder?: 'delete-first' | 'create-first';
  actionReason?: string;
  /** Top-level attribute -> referenced resource addresses (module-qualified, without instance keys). */
  references: Record<string, string[]>;
  /** Plan configuration expression paths, including nested block indices. Absent for static HCL values. */
  configuredPaths?: string[];
  /** Configured plan arguments, using literal configuration values before provider-populated values. */
  configuredAfter?: Attrs;
  /** Prior static configuration evidence, when available. */
  configuredBefore?: Attrs;
  previousAddress?: string;
  /** lifecycle { prevent_destroy = true }: Terraform refuses to plan a destroy. */
  preventDestroy?: boolean;
  /**
   * The base had lifecycle { prevent_destroy = true } on it and the head does not: the change removes the
   * guard (with the block, or from it), so a destroy the team had ruled out is now planned.
   */
  protectedAtBase?: boolean;
  source?: SourceRef;
  /** How sure the producer is about `action`. Plan JSON is `proven`; static replay may be less. */
  confidence: 'proven' | 'likely' | 'unknown';
}

export type FindingStatus = 'PASS' | 'FAIL' | 'WARN' | 'UNKNOWN' | 'INFO';

export interface Finding {
  ruleId: string;
  title: string;
  status: FindingStatus;
  resource: string;
  /** Control identifiers, e.g. `ISO27001:A.8.24` and `SOC2:CC6.1`. */
  controls: string[];
  detail: string;
  remediation?: string;
  /** True when the same result already held before this change, so the change did not introduce it. */
  preExisting?: boolean;
  /** Set when a policy exception accepts this finding. */
  accepted?: Acceptance;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface BlastFinding {
  severity: Severity;
  resource: string;
  type: string;
  action: Action;
  reason: string;
  dataLoss: boolean;
  downtime: 'yes' | 'possible' | 'no';
  accepted?: Acceptance;
  /** The confidence of the change behind this row, absent when proven. */
  confidence?: 'likely' | 'unknown';
}

export interface CostItem {
  resource: string;
  type: string;
  /** fixed: a monthly charge independent of traffic. usage: billed per request/GB only. scaling: a change in a pricing dimension. */
  kind: 'fixed' | 'usage' | 'scaling';
  monthlyDeltaUsd?: number;
  note: string;
}

export interface CostSummary {
  items: CostItem[];
  /** Sum of fixed charges added minus fixed charges removed. Usage-based costs are listed, not summed. */
  fixedMonthlyDeltaUsd: number;
  basis: string;
}

export interface GateItem {
  level: 'block' | 'review';
  kind: 'risk' | 'control' | 'exception' | 'coverage' | 'policy';
  rule?: string;
  resource?: string;
  text: string;
}

/** Append structured reasons together so their ordering cannot drift. */
export function addGateItem(gate: Gate, item: GateItem): void {
  gate.items.push(item);
  gate.reasons.push(item.text);
}

export interface Gate {
  result: 'pass' | 'review' | 'block';
  reasons: string[];
  items: GateItem[];
}

export interface PolicyConfig {
  /** Require customer managed KMS keys where AWS offers them. Off by default: ISO 27001 does not mandate CMKs, your policy might. */
  requireCustomerManagedKeys?: boolean;
  /** Minimum RDS/Aurora backup retention in days. */
  minBackupRetentionDays?: number;
  /** Minimum finite CloudWatch log retention in days. 0 means no minimum; logs that never expire always qualify. */
  minLogRetentionDays?: number;
  /** Severities that block the gate. */
  blockOn?: Severity[];
  /** Accepted findings. Kept in the repository so they are reviewed like any other change. */
  exceptions?: PolicyException[];
}

export interface PolicyException {
  /** Rule id (e.g. `network.open-ingress`), or `blast-radius`. Omit to match every rule. */
  rule?: string;
  /** Resource address; `*` matches any characters. */
  resource: string;
  reason: string;
  owner?: string;
  /** YYYY-MM-DD. Required: an exception nobody revisits is a hole, not a decision. */
  expires: string;
}

export interface Acceptance {
  reason: string;
  owner?: string;
  expires: string;
}

export interface AnalysisResult {
  /** Resources this change touches (no-op and read excluded). */
  changes: ResourceChange[];
  findings: Finding[];
  blast: BlastFinding[];
  cost: CostSummary;
  gate: Gate;
}

/** Strip instance keys: `module.a["x"].aws_s3_bucket.b[0]` -> `module.a.aws_s3_bucket.b`. */
export function configAddress(address: string): string {
  return address.replace(/\[[^\]]*\]/g, '');
}

/** Instance keys of each module segment, e.g. `module.a["x"].module.b[0].t.n` -> `["x"]`, `[0]`. */
function modulePath(address: string): Array<{ name: string; key?: string }> {
  return [...address.matchAll(/(?:^|\.)module\.([\w-]+)(\[[^\]]*\])?/g)].map((m) => ({ name: m[1], key: m[2] }));
}

/**
 * True when two addresses can refer to the same module instance and the same resource instance. Keys
 * are compared only where the module paths agree: along the shared prefix of module calls, and the
 * resource key when both sit in the same module. Equal, absent or unknown (`[*]`) keys are compatible.
 * For a helper and the resource it configures, this keeps `module.b["a"]` from matching `module.b["b"]`,
 * while the keys of two different modules say nothing about each other.
 */
export function instancesCompatible(a: string, b: string): boolean {
  const same = (x: string | undefined, y: string | undefined) => x === undefined || y === undefined || x === '[*]' || y === '[*]' || x === y;
  const ma = modulePath(a);
  const mb = modulePath(b);
  let shared = 0;
  while (shared < ma.length && shared < mb.length && ma[shared].name === mb[shared].name) {
    if (!same(ma[shared].key, mb[shared].key)) return false;
    shared++;
  }
  if (shared !== ma.length || shared !== mb.length) return true;
  const last = (x: string) => x.match(/(\[[^\]]*\])$/)?.[1];
  const resourceKey = (x: string) => (x.replace(/\[[^\]]*\]$/, '').endsWith(']') ? undefined : last(x));
  return same(resourceKey(a), resourceKey(b));
}
