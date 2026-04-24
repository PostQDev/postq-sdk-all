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
