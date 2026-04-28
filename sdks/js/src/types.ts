/** Severity levels reported on a finding. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Aggregate risk level for a scan. */
export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Safe";

/** Type of asset that was scanned. */
export type ScanType =
  | "url"
  | "github"
  | "aws"
  | "azure"
  | "kubernetes"
  | "bulk";

/** Where the scan was submitted from. */
export type ScanSource = "cli" | "helm" | "lambda" | "bicep" | "web" | "sdk";

/** Options for constructing a PostQ client. */
export interface PostQOptions {
  /** PostQ API key (e.g. `pq_live_…`). */
  apiKey: string;
  /** Override the API base URL. Defaults to `https://api.postq.dev`. */
  baseUrl?: string;
  /** Request timeout in milliseconds. Defaults to 30000. */
  timeoutMs?: number;
  /** Custom fetch implementation. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

/** A single quantum-vulnerability finding attached to a scan submission. */
export interface Finding {
  severity: Severity;
  title: string;
  description?: string;
  location?: string;
  algorithm?: string;
  remediation?: string;
  vulnerable?: boolean;
}

/** Optional metadata about the agent/tool that produced the scan. */
export interface AgentInfo {
  name?: string;
  version?: string;
  hostname?: string;
  os?: string;
}

/** Input for `scans.submit()`. */
export interface ScanSubmitInput {
  type: ScanType;
  target: string;
  riskScore: number;
  riskLevel: RiskLevel;
  findings?: Finding[];
  source?: ScanSource;
  metadata?: Record<string, string>;
  agent?: AgentInfo;
}

/** Response from `scans.submit()`. */
export interface ScanSubmitResult {
  id: string;
  createdAt: string;
  url: string;
}

/** A single row returned by `scans.list()`. */
export interface ScanListItem {
  id: string;
  type: ScanType;
  target: string;
  source: ScanSource;
  riskScore: number;
  riskLevel: RiskLevel;
  findingsCount: number;
  createdAt: string;
  url: string;
}

/** Pagination metadata returned by `scans.list()`. */
export interface Pagination {
  limit: number;
  nextCursor: string | null;
}

/** Full response envelope for `scans.list()`. */
export interface ScanListResult {
  data: ScanListItem[];
  pagination: Pagination;
}

/* ────────────────────────────── Scan detail ────────────────────────────── */

/** HNDL severity bands surfaced on URL scans. */
export type HndlSeverity = "critical" | "high" | "medium" | "low" | "none";

/** Harvest-Now-Decrypt-Later exposure for a single scan. */
export interface HndlAssessment {
  /** 0–100 risk number; 100 = data captured today is fully decryptable while still sensitive. */
  score: number;
  severity: HndlSeverity;
  /** Years of overlap between "data still sensitive" and "CRQC available". */
  exposureWindowYears: number;
  /** Estimated year a CRQC breaks the underlying algorithm. 9999 = PQ-safe. */
  crqcBreakYear: number;
  /** Years the protected data is assumed to remain sensitive. */
  dataLifetimeYears: number;
  /** True when exposure is essentially zero. */
  pqSafe: boolean;
  rationale: string;
  recommendation: string;
}

/** Certificate metadata captured during URL scans. */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: number;
  fingerprint: string;
  subjectAltNames: string[];
  isExpired: boolean;
  daysUntilExpiry: number;
}

/** TLS handshake metadata captured during URL scans. */
export interface TlsInfo {
  protocol: string;
  cipherSuite: string;
  keyExchange: string;
  keyExchangeSize?: number;
  authentication: string;
  encryption: string;
  mac: string;
}

/** A normalized finding row stored alongside a scan (CLI/agent submissions). */
export interface ScanFindingRow {
  id?: string;
  severity: Severity;
  title: string;
  description?: string;
  location?: string;
  algorithm?: string | null;
  remediation?: string;
  vulnerable?: boolean;
}

/** Aggregated counts surfaced on URL scans. */
export interface ScanSummary {
  totalEndpoints?: number;
  quantumVulnerable?: number;
  hybridEnabled?: number;
  pqReady?: number;
  /** CLI/agent submissions also include severity-bucketed counts. */
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
}

/** Full scan record returned by `scans.get(id)`. Fields hndl/certificate/tls
 *  are populated for URL scans run from the dashboard, and may be null for
 *  CLI/agent submissions that only carry findings + metadata. */
export interface ScanDetail {
  id: string;
  type: ScanType;
  target: string;
  source: ScanSource;
  riskScore: number;
  riskLevel: RiskLevel;
  findingsCount: number;
  mode: "live" | "mock";
  createdAt: string;
  url: string;
  agent: AgentInfo;
  findings: ScanFindingRow[];
  hndl: HndlAssessment | null;
  certificate: CertificateInfo | null;
  tls: TlsInfo | null;
  summary: ScanSummary | null;
  metadata: Record<string, string> | null;
  /** Relative URL to the CycloneDX 1.6 CBOM export for this scan. */
  cbomUrl: string;
}

/** Health-check response. */
export interface HealthResult {
  status: string;
  version?: string;
  [key: string]: unknown;
}

/* ────────────────────────────── Assets ────────────────────────────── */

/** Where an asset / key was discovered. */
export type Provider =
  | "aws"
  | "azure"
  | "gcp"
  | "kubernetes"
  | "github"
  | "vault"
  | "url"
  | "other";

/** Coarse classification of a discovered asset. */
export type AssetType = "ENDPOINT" | "CERTIFICATE" | "KEY" | "DATA_STORE";

/** Risk level on individual cloud resources (uppercase, mirrors API). */
export type ResourceRisk = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

/** A single row returned by `assets.list()`. */
export interface Asset {
  id: string;
  provider: Provider | null;
  externalId: string | null;
  name: string;
  type: AssetType;
  algorithm: string;
  risk: ResourceRisk;
  environment: string;
  region: string | null;
  lastScanned: string | null;
  pqReady: boolean;
  scanId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

/** Filters for `assets.list()`. */
export interface AssetListOptions {
  limit?: number;
  cursor?: string;
  provider?: Provider;
  type?: AssetType;
  risk?: ResourceRisk;
  environment?: string;
}

export interface AssetListResult {
  data: Asset[];
  pagination: Pagination;
}

/* ──────────────────────────────── Keys ─────────────────────────────── */

/** Subset of providers that can have managed cryptographic keys. */
export type KeyProvider = "aws" | "azure" | "gcp" | "kubernetes" | "vault" | "other";

/** A discovered cryptographic key. */
export interface Key {
  id: string;
  provider: KeyProvider;
  externalId: string;
  region: string | null;
  algorithm: string;
  keySize: number | null;
  keyUsage: string | null;
  pqSafe: boolean;
  risk: RiskLevel;
  scanId: string | null;
  metadata: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
}

/** Filters for `keys.list()`. */
export interface KeyListOptions {
  limit?: number;
  cursor?: string;
  provider?: KeyProvider;
  algorithm?: string;
  risk?: RiskLevel;
}

export interface KeyListResult {
  data: Key[];
  pagination: Pagination;
}

/* ─────────────────────────── Hybrid Signing ─────────────────────────── */

/**
 * PostQ-managed composite signing algorithm.
 *
 * Each algorithm pairs a NIST-standardized post-quantum signature (FIPS 204
 * ML-DSA) with classical Ed25519. Verification requires BOTH halves to
 * validate, so a future break in either Ed25519 OR ML-DSA does not allow
 * forgery on its own.
 */
export type HybridAlgorithm =
  | "mldsa44+ed25519"
  | "mldsa65+ed25519"
  | "mldsa87+ed25519"
  | "mldsa44+ecdsa-p256"
  | "mldsa65+ecdsa-p256"
  | "mldsa87+ecdsa-p256";

/** KEK provider — who wraps the data-encryption key that seals private bytes. */
export type KekProvider = "env" | "aws-kms" | "azure-kv";

/** Where the classical signing-key half lives. */
export type KeyHolderProvider = "postq-managed" | "aws-kms" | "azure-kv";

/** Where the post-quantum signing-key half lives. */
export type PqProvider = "postq-managed" | "aws-cloudhsm" | "azure-managed-hsm";

/** A managed signing key owned by your org. */
export interface HybridKey {
  id: string;
  name: string;
  algorithm: HybridAlgorithm;
  /** ISO-8601. Set when the key is revoked; null otherwise. */
  revokedAt: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  metadata: Record<string, unknown>;
}

/** Returned from `hybridKeys.create()` and `hybridKeys.get()`. */
export interface HybridKeyWithPublic extends HybridKey {
  /**
   * Composite public key as a JSON string:
   * `{"v":1,"alg":"mldsa65+ed25519","classical":"<b64>","pq":"<b64>"}`.
   * Hand this to anyone who needs to verify your signatures offline.
   */
  publicKey: string;
}

export interface HybridKeyCreateInput {
  name: string;
  algorithm?: HybridAlgorithm;
  /** KEK provider (where the data-encryption key is wrapped). */
  kekProvider?: KekProvider;
  /** Where the classical signing-key half lives. */
  keyProvider?: KeyHolderProvider;
  /** Where the post-quantum half lives. */
  pqProvider?: PqProvider;
  metadata?: Record<string, unknown>;
}

export interface HybridKeyListOptions {
  limit?: number;
  cursor?: string;
  algorithm?: HybridAlgorithm;
  includeRevoked?: boolean;
}

export interface HybridKeyListResult {
  data: HybridKey[];
  pagination: Pagination;
}

export interface HybridSignInput {
  keyId: string;
  /** Raw bytes to sign. SDK base64-encodes this for the wire. */
  payload: Uint8Array | string;
  metadata?: Record<string, unknown>;
}

export interface HybridSignResult {
  keyId: string;
  algorithm: HybridAlgorithm;
  /** Base64-encoded composite signature. Pass directly to `verify()`. */
  signature: string;
  /** Composite public key JSON. Distribute to verifiers. */
  publicKey: string;
  payloadSha256: string;
  payloadSize: number;
}

export interface HybridVerifyInput {
  payload: Uint8Array | string;
  signature: string;
  /** One of `keyId` or `publicKey` is required. */
  keyId?: string;
  publicKey?: string;
}

export interface HybridVerifyResult {
  ok: boolean;
  algorithm: HybridAlgorithm;
  /** Per-component breakdown — useful when one half is misbehaving. */
  classicalOk: boolean;
  pqOk: boolean;
}

/* ────────────────────────── Hybrid key audit ────────────────────────── */

export interface HybridKeyAuditEntry {
  id: string;
  operation: "sign" | "verify";
  payloadSha256: string;
  payloadSize: number;
  verified: boolean | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface HybridKeyAuditResult {
  data: HybridKeyAuditEntry[];
  pagination: Pagination;
}

/* ────────────────────────── Policies ────────────────────────── */

export type PolicyAction = "enforce" | "warn" | "audit";
export type PolicyOperation = "sign" | "verify" | "key_create" | "*";

export interface PolicyRule {
  matchOperation: PolicyOperation;
  /** Whitelist. If non-null/non-empty, algorithm MUST be in this set. */
  algorithmIn?: string[] | null;
  /** Blacklist. If non-null/non-empty, algorithm MUST NOT be in this set. */
  algorithmNotIn?: string[] | null;
  /** If true, only hybrid algorithms (containing '+') pass. */
  requireHybrid?: boolean;
  /** Minimum NIST PQ level: 2 (ML-DSA-44), 3 (ML-DSA-65), 5 (ML-DSA-87). */
  minPqLevel?: 2 | 3 | 5 | null;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  action: PolicyAction;
  enabled: boolean;
  /** Empty array means "any environment". */
  environments: string[];
  rule: PolicyRule;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyCreateInput {
  name: string;
  description?: string;
  action: PolicyAction;
  enabled?: boolean;
  environments?: string[];
  rule: PolicyRule;
}

export interface PolicyUpdateInput {
  name?: string;
  description?: string;
  action?: PolicyAction;
  enabled?: boolean;
  environments?: string[];
  rule?: Partial<PolicyRule>;
}

/* ────────────────────────── Ledger ────────────────────────── */

export type LedgerEventType =
  | "key.created"
  | "key.rotated"
  | "key.revoked"
  | "signature.issued"
  | "signature.verified"
  | "vault.settings_changed"
  | "scan.completed"
  | "policy.violated"
  | "custom.event";

export interface LedgerEntry {
  id: string;
  seq: number;
  prevHashHex: string;
  entryHashHex: string;
  payload: Record<string, unknown>;
  eventType: LedgerEventType | string;
  subjectId: string | null;
  actorId: string | null;
  createdAt: string;
}

export interface LedgerCheckpoint {
  id: string;
  treeSize: number;
  merkleRootHex: string;
  signatureBase64: string;
  signingKeyId: string;
  publishedTo: string[];
  createdAt: string;
}

export interface LedgerInclusionProof {
  entryId: string;
  leafIndex: number;
  leafHashHex: string;
  checkpoint: {
    treeSize: number;
    merkleRootHex: string;
    signatureBase64: string;
    signingKeyId: string;
    createdAt: string;
  };
  proofHex: string[];
}

export interface LedgerSealResult {
  treeSize: number;
  merkleRootHex: string;
  signatureBase64: string;
  signingKeyId: string;
  createdAt: string;
}

export interface LedgerAppendInput {
  /** Required short label (e.g. "build.released"). */
  name: string;
  /** Optional human-readable message. */
  message?: string;
  /** Optional correlation id for the event. */
  subjectId?: string;
  /** Optional structured payload. Must be JSON-serializable. */
  data?: Record<string, unknown>;
}

export interface LedgerEntryListOptions {
  /** Lower bound on `seq` (inclusive). */
  since?: number;
  limit?: number;
  /** Filter to a single event type. */
  eventType?: string;
}

export interface LedgerBundleSigningKey {
  id: string;
  algorithm: HybridAlgorithm;
  publicClassicalBase64: string;
  publicPqBase64: string;
}

export interface LedgerBundle {
  version: number;
  org: string;
  generatedAt: string;
  entries: {
    id: string;
    seq: number;
    prevHashHex: string;
    entryHashHex: string;
    payload: Record<string, unknown>;
    createdAt: string;
  }[];
  checkpoints: {
    treeSize: number;
    merkleRootHex: string;
    signatureBase64: string;
    signingKeyId: string;
    createdAt: string;
  }[];
  signingKeys: LedgerBundleSigningKey[];
}

/* ────────────────────────── Vault settings ────────────────────────── */

export interface VaultSettingsAws {
  keyArn: string;
  roleArn?: string | null;
  externalId?: string | null;
  region?: string | null;
}

export interface VaultSettingsAzure {
  vaultUrl: string;
  kekName: string;
  tenantId?: string | null;
  clientId?: string | null;
  /** Server never echoes the secret. True if one was previously stored. */
  clientSecretConfigured?: boolean;
}

export interface VaultSettings {
  defaultKekProvider: KekProvider;
  aws: VaultSettingsAws | null;
  azure: VaultSettingsAzure | null;
  updatedAt: string;
}

export interface VaultSettingsInput {
  defaultKekProvider: KekProvider;
  aws?: {
    keyArn: string;
    roleArn?: string;
    externalId?: string;
    region?: string;
  };
  azure?: {
    vaultUrl: string;
    kekName: string;
    tenantId?: string;
    clientId?: string;
    /** Provide once; encrypted server-side and never echoed. */
    clientSecret?: string;
  };
}
