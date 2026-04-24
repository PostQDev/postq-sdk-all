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
