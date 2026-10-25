/** What application code does with AWS, as found by the language extractors. */

export type ResourceRef =
  /** A fixed name, URL or ARN in the code. */
  | { kind: 'literal'; value: string }
  /** A formatted name such as fmt.Sprintf("provider/%s/creds", id): `*` marks the variable parts. */
  | { kind: 'pattern'; glob: string }
  /** The value of an environment variable, and the code's fallback when it is unset. */
  | { kind: 'env'; name: string; fallback?: string }
  /** Could not be followed statically; `text` is the expression as written. */
  | { kind: 'unresolved'; text: string };

export interface AccessFact {
  /** SDK service name as the SDK spells it: s3, sqs, secretsmanager, sfn... */
  service: string;
  /** SDK operation: PutObject, SendMessage, GetSecretValue... */
  operation: string;
  /** IAM actions the call needs. */
  actions: string[];
  resource: ResourceRef;
  file: string;
  line: number;
  /** Set when the call happens inside a helper, e.g. `pubsub.NewSNSPublisher`. */
  via?: string;
  /** The helper can make this call, but the code may not use that path (e.g. the value is passed on). */
  possible?: boolean;
  /** DynamoDB IndexName ('*' when not a literal): the call needs the index ARN, not just the table. */
  index?: string;
  /** Import path of the helper package, for calls found through a helper. */
  viaPackage?: string;
  /** The resource is a parameter or field of the enclosing helper; its callers name the real resource. */
  internal?: boolean;
}

export interface EnvRead {
  name: string;
  file: string;
  line: number;
  /** The code supplies a fallback when the variable is unset. */
  hasDefault?: boolean;
}

export interface AppScan {
  facts: AccessFact[];
  envReads: EnvRead[];
}

/** Line ranges (1-based, inclusive) that a diff added, per file. Undefined means "whole file". */
export type AddedLines = Map<string, Set<number>>;
