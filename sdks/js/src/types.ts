/** Supported hybrid signature algorithms. */
export type Algorithm =
  | "dilithium3+ed25519"
  | "dilithium5+p384"
  | "falcon512+ed25519";

/** Options for constructing a PostQ client. */
export interface PostQOptions {
  /** PostQ API key (e.g. pq_live_sk_...). */
  apiKey: string;
  /** Target environment. Defaults to "production". */
  environment?: "production" | "staging" | "development";
  /** Override the base URL (useful for testing). */
  baseUrl?: string;
}

/** Input for the sign operation. */
export interface SignInput {
  /** Raw bytes to sign. */
  payload: Buffer | Uint8Array;
  /** Hybrid algorithm to use. */
  algorithm: Algorithm;
  /** Key identifier (e.g. vault://signing/production). */
  keyId: string;
  /** Optional metadata attached to the signing context. */
  context?: Record<string, string>;
}

/** Response returned by POST /v1/sign. */
export interface SignResponse {
  /** Combined (hybrid) signature, base64-encoded. */
  signature: string;
  /** Classical component signature, base64-encoded. */
  classical_sig: string;
  /** Post-quantum component signature, base64-encoded. */
  pq_sig: string;
  /** Algorithm used. */
  algorithm: Algorithm;
  /** Key identifier used. */
  key_id: string;
  /** ISO 8601 timestamp of the signing operation. */
  timestamp: string;
  /** Whether the signing complies with the active policy. */
  policy_compliant: boolean;
}

/** Input for the verify operation. */
export interface VerifyInput {
  /** Raw bytes that were signed. */
  payload: Buffer | Uint8Array;
  /** Combined (hybrid) signature to verify, base64-encoded. */
  signature: string;
  /** Key identifier used when signing. */
  keyId: string;
}

/** Response returned by POST /v1/verify. */
export interface VerifyResponse {
  /** Overall validity (both components valid). */
  valid: boolean;
  /** Classical component validity. */
  classical_valid: boolean;
  /** Post-quantum component validity. */
  pq_valid: boolean;
  /** Algorithm detected. */
  algorithm: Algorithm;
  /** Key identifier used. */
  key_id: string;
}

/** A single managed cryptographic key. */
export interface Key {
  /** Key identifier. */
  id: string;
  /** Algorithm the key uses. */
  algorithm: string;
  /** ISO 8601 creation timestamp. */
  created_at: string;
  /** Operational status. */
  status: "active" | "inactive" | "expired";
  /** Storage backend. */
  backend: string;
  /** Whether the key uses a post-quantum algorithm. */
  pq_ready: boolean;
}

/** Response returned by GET /v1/keys. */
export interface ListKeysResponse {
  keys: Key[];
}

/** Input for the scan operation. */
export interface ScanInput {
  /** Targets to scan (e.g. "kubernetes://production"). */
  targets: string[];
  /** Scan depth. */
  depth?: "quick" | "full";
  /** Cryptographic categories to include in the scan. */
  include?: ("tls" | "signing" | "encryption")[];
}

/** Summary of a completed scan. */
export interface ScanSummary {
  /** Total number of endpoints assessed. */
  total_endpoints: number;
  /** Number of endpoints using quantum-vulnerable algorithms. */
  quantum_vulnerable: number;
  /** Aggregate risk score (0–100). */
  risk_score: number;
  /** Human-readable recommendation. */
  recommendation: string;
}

/** Response returned by POST /v1/scan. */
export interface ScanResponse {
  /** Unique identifier for the scan job. */
  scan_id: string;
  /** Scan status. */
  status: "pending" | "running" | "completed" | "failed";
  /** Summary results (present when status is "completed"). */
  summary?: ScanSummary;
}

/** Structured error returned by the PostQ API. */
export interface PostQApiError {
  code: string;
  message: string;
}
