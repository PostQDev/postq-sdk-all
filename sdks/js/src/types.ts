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
  | "gcp"
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
  /** Retries for idempotent requests on 429/5xx/network failure. Defaults to 2. */
  maxRetries?: number;
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

/* ─────────────────────── Server-side scan execution ─────────────────────── */

export interface CloudScanAwsOptions {
  regions?: string[];
  roleArn?: string;
  externalId?: string;
}

export interface CloudScanAzureOptions {
  subscriptionId: string;
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  vaultNames?: string[];
}

export interface CloudScanGcpOptions {
  keyRingName: string;
}

export interface CloudScanInput {
  provider: "aws" | "azure" | "gcp";
  target: string;
  aws?: CloudScanAwsOptions;
  azure?: CloudScanAzureOptions;
  gcp?: CloudScanGcpOptions;
}

export interface CloudScanSummary {
  totalEndpoints: number;
  quantumVulnerable: number;
  hybridEnabled: number;
  pqReady: number;
}

export interface CloudScanResult {
  id: string;
  createdAt: string;
  provider: CloudScanInput["provider"];
  target: string;
  mode: "live" | "mock";
  riskScore: number;
  riskLevel: RiskLevel;
  findingsCount: number;
  resourcesCount: number;
  summary: CloudScanSummary;
  url: string;
}

export interface UrlScanInput {
  target: string;
  timeoutMs?: number;
}

export interface UrlScanResult {
  id: string;
  createdAt: string;
  target: string;
  mode: "live" | "mock";
  riskScore: number;
  riskLevel: RiskLevel;
  findingsCount: number;
  summary: ScanSummary;
  metadata: Record<string, string>;
  findings: ScanFindingRow[];
  certificate: CertificateInfo | null;
  tls: TlsInfo | null;
  hndl: HndlAssessment | null;
  scanDurationMs: number;
  url: string;
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
  workflowStatus?: "discovered" | "assessed" | "planned" | "migrating" | "hybrid-enabled" | "pq-ready" | "deprecated" | "exception";
  ownerTeam?: string | null;
  assignedTo?: string | null;
  criticality?: "low" | "medium" | "high" | "mission-critical";
  dataLifetimeYears?: number | null;
  exposure?: "internal" | "partner" | "internet" | "unknown";
  migrationDueAt?: string | null;
  exception?: Record<string, unknown> | null;
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
export type KekProvider = "env" | "aws-kms" | "azure-kv" | "gcp-kms";

/** Where the classical signing-key half lives. */
export type KeyHolderProvider =
  | "postq-managed"
  | "aws-kms"
  | "azure-kv"
  | "gcp-kms";

/** Where the post-quantum signing-key half lives. */
export type PqProvider =
  | "postq-managed"
  | "aws-kms"
  | "gcp-kms"
  | "aws-cloudhsm"
  | "azure-managed-hsm"
  /** Phase-1 attested signing: the PQ half lives inside the postq-enclave
   *  mock backend and every sign returns an attestation doc. */
  | "enclave-mock";

/* ─────────────────────────── Migrations ─────────────────────────── */

export type MigrationActionStatus = "pending" | "ready" | "in-progress" | "validating" | "blocked" | "completed" | "waived";
export interface MigrationAction {
  id: string; projectId: string; assetId: string | null; title: string; provider: string;
  sourceAlgorithm: string | null; targetAlgorithm: string; executionMode: "guided" | "native-provider" | "manual";
  status: MigrationActionStatus; assignee: string | null; dueAt: string | null;
  beforeScanId: string | null; afterScanId: string | null; downgradeProtected: boolean | null;
  dependentCredentialsRotated: boolean; validation: Record<string, unknown>;
  exception: Record<string, unknown> | null; externalIssueUrl: string | null; createdAt: string; updatedAt: string;
}
export interface MigrationProject {
  id: string; name: string; description: string; framework: string;
  track: "key-establishment" | "digital-signature" | "both";
  status: "planned" | "active" | "blocked" | "completed" | "cancelled";
  targetDate: string | null; sourceScanId: string | null; metadata: Record<string, unknown>;
  createdAt: string; updatedAt: string; actionCount?: number;
  actions?: MigrationAction[]; evidence?: MigrationEvidenceBundle[];
}
export interface MigrationUpdateInput {
  status?: "planned" | "active" | "blocked" | "completed" | "cancelled";
  targetDate?: string | null; description?: string;
}
export interface MigrationCreateInput {
  name: string; description?: string; framework?: string;
  track?: "key-establishment" | "digital-signature" | "both";
  targetDate?: string; sourceScanId?: string; assetIds?: string[];
  includeRisk?: Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW">;
}
export interface MigrationEvidenceBundle {
  id: string; projectId: string; actionId: string | null; format: "postq-migration-evidence/v1";
  bundle: Record<string, unknown>; bundleSha256: string; ledgerEntryId: string | null;
  checkpointId: string | null; createdAt: string;
}
export interface Eo14412Status {
  framework: "EO-14412"; generatedAt: string;
  deadlines: { keyEstablishment: "2030-12-31"; digitalSignatures: "2031-12-31" };
  totals: { assets: number; pqReady: number; hybridEnabled: number; atRisk: number; exceptions: number };
  readinessPercent: number;
}

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
  /**
   * Bind this key to an attestation policy. REQUIRED for enclave-kind
   * `pqProvider` values (e.g. `enclave-mock`, future `aws-nitro-enclave`).
   * Every sign call with this key returns an attestation doc that the API
   * verifies against this policy before persisting the signature.
   */
  attestationPolicyId?: string;
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
  /**
   * Only present when the key is bound to an attestation policy and the
   * signing backend produced an attestation doc. Use `verifyAttestationDoc()`
   * to independently re-verify the doc on the caller side.
   */
  attestation?: AttestationOutcome;
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
  fresh: boolean;
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

export interface VaultSettingsGcp {
  kekKeyName: string;
  keyRingName?: string | null;
  protectionLevel: "SOFTWARE" | "HSM";
}

export interface VaultSettings {
  defaultKekProvider: KekProvider;
  aws: VaultSettingsAws | null;
  azure: VaultSettingsAzure | null;
  gcp: VaultSettingsGcp | null;
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
  gcp?: {
    kekKeyName: string;
    keyRingName?: string;
    protectionLevel?: "SOFTWARE" | "HSM";
  };
}

export interface VaultSettingsSaveResult {
  savedAt: string;
}

export interface VaultSettingsClearResult {
  cleared: true;
}

/* ─────────────────────── Attestation policies ─────────────────────── */

/**
 * Which trusted-execution backend produced the attestation document.
 *
 *   • `mock`                    Dev backend (ed25519 root over a JWS-shaped doc).
 *   • `aws-nitro-enclave`       Reserved — real Nitro EIF + AWS Nitro root CA.
 *   • `azure-confidential-vm`   Reserved — MAA-issued JWT.
 *   • `gcp-confidential-space`  Reserved — Confidential Space OIDC token.
 */
export type AttestationVendor =
  | "mock"
  | "aws-nitro-enclave"
  | "azure-confidential-vm"
  | "gcp-confidential-space";

/** Verdict the API records for a sign call. */
export type AttestationVerdict = "pass" | "fail" | "absent";

/**
 * Per-vendor verification rules. For `mock` this is
 * `{ allowedImageHashes: string[], rootPublicKeyB64: string }`.
 * For real vendors (Phase 2+) this carries PCR allow-lists, root certs, etc.
 */
export type AttestationMatchRules = Record<string, unknown>;

/**
 * An attestation policy bound to one or more hybrid keys. Single-vendor.
 */
export interface AttestationPolicy {
  id: string;
  name: string;
  vendor: AttestationVendor;
  matchRules: AttestationMatchRules;
  /** Reject docs older than this. */
  maxDocAgeSeconds: number;
  /** When false, failures are recorded but signing still succeeds. */
  enforce: boolean;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface AttestationPolicyCreateInput {
  name: string;
  vendor: AttestationVendor;
  matchRules?: AttestationMatchRules;
  /** Default: 300s. Range 5–86400. */
  maxDocAgeSeconds?: number;
  /** Default: true. */
  enforce?: boolean;
  metadata?: Record<string, unknown>;
}

export interface AttestationPolicyUpdateInput {
  name?: string;
  matchRules?: AttestationMatchRules;
  maxDocAgeSeconds?: number;
  enforce?: boolean;
  metadata?: Record<string, unknown>;
}

export interface AttestationPolicyListOptions {
  vendor?: AttestationVendor;
  limit?: number;
}

export interface AttestationPolicyListResult {
  data: AttestationPolicy[];
}

/**
 * The attestation summary attached to a sign response. The raw doc is in
 * `docB64`; pass it to `verifyAttestationDoc()` to re-check it yourself.
 */
export interface AttestationOutcome {
  vendor: AttestationVendor;
  /** Hex sha256 of the enclave image / EIF / CVM measurement. */
  imageHash: string;
  /** Monotonic counter the enclave bumped for this sign call. */
  counter: number;
  /** Base64 of the raw vendor-specific attestation document. */
  docB64: string;
  verdict: AttestationVerdict;
  /** Populated when verdict !== "pass". */
  reason?: string;
}

/**
 * Input for the client-side `verifyAttestationDoc()` helper. Lets a caller
 * re-verify a doc without trusting the API's verdict.
 */
export interface AttestationVerifyInput {
  /** Base64 of the raw attestation doc (i.e. `attestation.docB64`). */
  docB64: string;
  vendor: AttestationVendor;
  /** Policy to verify against — usually the one bound to the signing key. */
  policy: Pick<AttestationPolicy, "vendor" | "matchRules" | "maxDocAgeSeconds">;
  /**
   * Optional hash bindings. Pass these if you also have the corresponding
   * sign result + payload — the verifier will reject the doc when claims do
   * not match. Hex sha256 strings.
   */
  expectedSigSha256?: string;
  expectedPayloadSha256?: string;
  /**
   * If true (default), reject docs older than `policy.maxDocAgeSeconds`.
   * Set false when verifying historic signatures from the audit ledger.
   */
  enforceFreshness?: boolean;
}

export interface AttestationVerifyResult {
  ok: boolean;
  reason?: string;
  vendor: AttestationVendor;
  imageHash?: string;
  counter?: number;
  claims?: Record<string, unknown>;
}
