import {
  PostQAuthError,
  PostQConfigError,
  PostQError,
  PostQNetworkError,
  PostQNotFoundError,
  PostQRateLimitError,
  PostQServerError,
} from "./errors";
import {
  HealthResult,
  PostQOptions,
  ScanListItem,
  ScanListResult,
  ScanSubmitInput,
  ScanSubmitResult,
  ScanDetail,
  Asset,
  AssetListOptions,
  AssetListResult,
  Key,
  KeyListOptions,
  KeyListResult,
  Pagination,
  HybridKey,
  HybridKeyAuditEntry,
  HybridKeyAuditResult,
  HybridKeyCreateInput,
  HybridKeyListOptions,
  HybridKeyListResult,
  HybridKeyWithPublic,
  HybridSignInput,
  HybridSignResult,
  HybridVerifyInput,
  HybridVerifyResult,
  Policy,
  PolicyCreateInput,
  PolicyUpdateInput,
  LedgerEntry,
  LedgerEntryListOptions,
  LedgerCheckpoint,
  LedgerInclusionProof,
  LedgerSealResult,
  LedgerAppendInput,
  LedgerBundle,
  VaultSettings,
  VaultSettingsInput,
} from "./types";

const DEFAULT_BASE_URL = "https://api.postq.dev";
const SDK_VERSION = "0.5.0";

/**
 * PostQ SDK client.
 *
 * @example
 * ```ts
 * import { PostQ } from "@postq/sdk";
 *
 * const pq = new PostQ({ apiKey: process.env.POSTQ_API_KEY! });
 *
 * const result = await pq.scans.submit({
 *   type: "url",
 *   target: "example.com",
 *   riskScore: 85,
 *   riskLevel: "High",
 *   findings: [
 *     { severity: "high", title: "RSA-2048 public key" },
 *   ],
 * });
 * console.log(result.url);
 * ```
 */
export class PostQ {
  readonly scans: ScansResource;
  readonly assets: AssetsResource;
  readonly keys: KeysResource;
  readonly hybridKeys: HybridKeysResource;
  readonly policies: PoliciesResource;
  readonly ledger: LedgerResource;
  readonly vault: VaultResource;

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: PostQOptions) {
    if (!options || !options.apiKey || options.apiKey.trim() === "") {
      throw new PostQConfigError(
        "apiKey is required. Pass it explicitly or set POSTQ_API_KEY in your environment.",
      );
    }
    this.apiKey = options.apiKey.trim();
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 30000;

    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new PostQConfigError(
        "global fetch is not available. Pass `fetch` in PostQOptions or use Node 18+.",
      );
    }
    this.fetchImpl = f.bind(globalThis);

    this.scans = new ScansResource(this);
    this.assets = new AssetsResource(this);
    this.keys = new KeysResource(this);
    this.hybridKeys = new HybridKeysResource(this);
    this.policies = new PoliciesResource(this);
    this.ledger = new LedgerResource(this);
    this.vault = new VaultResource(this);
  }

  /** Hit `GET /health`. Throws if the API is down. */
  async health(): Promise<HealthResult> {
    return this.request<HealthResult>("GET", "/health");
  }

  /**
   * `POST /v1/sign` — sign `payload` with a managed hybrid key.
   * Convenience wrapper around `hybridKeys.sign()`.
   */
  sign(input: HybridSignInput): Promise<HybridSignResult> {
    return this.hybridKeys.sign(input);
  }

  /**
   * `POST /v1/verify` — verify a composite signature.
   * Convenience wrapper around `hybridKeys.verify()`.
   */
  verify(input: HybridVerifyInput): Promise<HybridVerifyResult> {
    return this.hybridKeys.verify(input);
  }

  /** @internal */
  async request<T>(
    method: "GET" | "POST" | "DELETE" | "PATCH" | "PUT",
    path: string,
    opts: { body?: unknown; query?: Record<string, string | number | boolean | undefined> } = {},
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url.toString(), {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": `postq-sdk-js/${SDK_VERSION}`,
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (err) {
      const e = err as { name?: string; message?: string };
      if (e.name === "AbortError") {
        throw new PostQNetworkError(
          `${method} ${path} timed out after ${this.timeoutMs}ms`,
        );
      }
      throw new PostQNetworkError(`${method} ${path}: ${e.message ?? String(err)}`);
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let json: unknown;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        throw new PostQError(
          `Non-JSON response from ${method} ${path}: ${text.slice(0, 200)}`,
          { status: response.status },
        );
      }
    }

    if (!response.ok) {
      const body = (json ?? {}) as { error?: string; message?: string; code?: string };
      const message = body.error ?? body.message ?? `HTTP ${response.status}`;
      const code = body.code;
      switch (response.status) {
        case 401:
          throw new PostQAuthError(message, code);
        case 404:
          throw new PostQNotFoundError(message, code);
        case 429:
          throw new PostQRateLimitError(message, code);
        default:
          if (response.status >= 500) {
            throw new PostQServerError(message, response.status, code);
          }
          throw new PostQError(message, { status: response.status, code });
      }
    }

    return (json ?? {}) as T;
  }

  /** @internal Same as `request` but returns the raw response body as text
   *  without any JSON parsing or envelope handling. Used for endpoints that
   *  return non-JSON-envelope payloads (e.g. CBOM exports). */
  async requestRaw(
    method: "GET" | "POST" | "DELETE",
    path: string,
    opts: { query?: Record<string, string | number | boolean | undefined> } = {},
  ): Promise<string> {
    const url = new URL(this.baseUrl + path);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url.toString(), {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          Accept: "*/*",
          "User-Agent": `postq-sdk-js/${SDK_VERSION}`,
        },
        signal: controller.signal,
      });
    } catch (err) {
      const e = err as { name?: string; message?: string };
      if (e.name === "AbortError") {
        throw new PostQNetworkError(`${method} ${path} timed out after ${this.timeoutMs}ms`);
      }
      throw new PostQNetworkError(`${method} ${path}: ${e.message ?? String(err)}`);
    } finally {
      clearTimeout(timer);
    }
    const text = await response.text();
    if (!response.ok) {
      const message = text ? text.slice(0, 500) : `HTTP ${response.status}`;
      switch (response.status) {
        case 401: throw new PostQAuthError(message);
        case 404: throw new PostQError(message, { status: 404 });
        default:
          if (response.status >= 500) {
            throw new PostQServerError(message, response.status);
          }
          throw new PostQError(message, { status: response.status });
      }
    }
    return text;
  }
}

/**
 * Scans resource — submit new scans and list recent ones.
 */
export class ScansResource {
  constructor(private readonly client: PostQ) {}

  /** `POST /v1/scans` — submit a scan from your own scanner/agent. */
  async submit(input: ScanSubmitInput): Promise<ScanSubmitResult> {
    const body = {
      type: input.type,
      target: input.target,
      source: input.source ?? "sdk",
      riskScore: input.riskScore,
      riskLevel: input.riskLevel,
      findings: input.findings ?? [],
      metadata: input.metadata ?? {},
      agent: input.agent ?? {},
    };
    const envelope = await this.client.request<{
      success: boolean;
      data: ScanSubmitResult;
    }>("POST", "/v1/scans", { body });
    return envelope.data;
  }

  /** `GET /v1/scans` — one page of recent scans for your org. */
  async list(opts: { limit?: number; cursor?: string } = {}): Promise<ScanListResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: ScanListItem[];
      pagination: { limit: number; nextCursor: string | null };
    }>("GET", "/v1/scans", {
      query: { limit: opts.limit ?? 20, cursor: opts.cursor },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** `GET /v1/scans/:id` — full scan record including hndl/certificate/tls
   *  when populated by URL scans. */
  async get(id: string): Promise<ScanDetail> {
    const envelope = await this.client.request<{
      success: boolean;
      data: ScanDetail;
    }>("GET", `/v1/scans/${encodeURIComponent(id)}`);
    return envelope.data;
  }

  /** `GET /v1/scans/:id/cbom` — CycloneDX 1.6 CBOM as a parsed object.
   *  Pass `{ raw: true }` to receive the JSON string instead. */
  async cbom(id: string): Promise<unknown>;
  async cbom(id: string, opts: { raw: true }): Promise<string>;
  async cbom(id: string, opts?: { raw?: boolean }): Promise<unknown> {
    const text = await this.client.requestRaw(
      "GET",
      `/v1/scans/${encodeURIComponent(id)}/cbom`,
    );
    if (opts?.raw) return text;
    return JSON.parse(text);
  }

  /** Async iterator over every scan, walking the cursor automatically. */
  async *iterAll(opts: { pageSize?: number } = {}): AsyncIterableIterator<ScanListItem> {
    let cursor: string | undefined;
    const limit = opts.pageSize ?? 100;
    while (true) {
      const page = await this.list({ limit, cursor });
      for (const row of page.data) yield row;
      if (!page.pagination.nextCursor) return;
      cursor = page.pagination.nextCursor;
    }
  }
}

/**
 * Assets resource — list every cryptographic asset PostQ has discovered for
 * your org (TLS certificates, KMS keys, K8s secrets, …).
 */
export class AssetsResource {
  constructor(private readonly client: PostQ) {}

  /** `GET /v1/assets` — one page of assets. */
  async list(opts: AssetListOptions = {}): Promise<AssetListResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: Asset[];
      pagination: { limit: number; nextCursor: string | null };
    }>("GET", "/v1/assets", {
      query: {
        limit: opts.limit ?? 20,
        cursor: opts.cursor,
        provider: opts.provider,
        type: opts.type,
        risk: opts.risk,
        environment: opts.environment,
      },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** Walk every asset across pages. */
  async *iterAll(
    opts: AssetListOptions & { pageSize?: number } = {},
  ): AsyncIterableIterator<Asset> {
    let cursor: string | undefined;
    const limit = opts.pageSize ?? 100;
    while (true) {
      const page = await this.list({ ...opts, limit, cursor });
      for (const row of page.data) yield row;
      if (!page.pagination.nextCursor) return;
      cursor = page.pagination.nextCursor;
    }
  }
}

/**
 * Keys resource — list every managed cryptographic key (KMS / Key Vault /
 * Vault Transit / etc.) PostQ has discovered for your org.
 */
export class KeysResource {
  constructor(private readonly client: PostQ) {}

  /** `GET /v1/keys` — one page of discovered keys. */
  async list(opts: KeyListOptions = {}): Promise<KeyListResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: Key[];
      pagination: { limit: number; nextCursor: string | null };
    }>("GET", "/v1/keys", {
      query: {
        limit: opts.limit ?? 20,
        cursor: opts.cursor,
        provider: opts.provider,
        algorithm: opts.algorithm,
        risk: opts.risk,
      },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** Walk every discovered key across pages. */
  async *iterAll(
    opts: KeyListOptions & { pageSize?: number } = {},
  ): AsyncIterableIterator<Key> {
    let cursor: string | undefined;
    const limit = opts.pageSize ?? 100;
    while (true) {
      const page = await this.list({ ...opts, limit, cursor });
      for (const row of page.data) yield row;
      if (!page.pagination.nextCursor) return;
      cursor = page.pagination.nextCursor;
    }
  }
}

/**
 * Hybrid signing — create / list / revoke PostQ-managed signing keys, and
 * call `POST /v1/sign` and `POST /v1/verify`.
 *
 * Every key signs with BOTH a post-quantum algorithm (ML-DSA) and Ed25519.
 * Verification requires both halves, so a future break in either alone does
 * not allow forgery.
 *
 * @example
 * ```ts
 * const k = await pq.hybridKeys.create({ name: "release-signing", algorithm: "mldsa65+ed25519" });
 * const sig = await pq.sign({ keyId: k.id, payload: new TextEncoder().encode("ship it") });
 * const ok = await pq.verify({ keyId: k.id, payload: "ship it", signature: sig.signature });
 * ```
 */
export class HybridKeysResource {
  constructor(private readonly client: PostQ) {}

  /** `POST /v1/hybrid-keys` — create a new managed signing key. */
  async create(input: HybridKeyCreateInput): Promise<HybridKeyWithPublic> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridKeyWithPublic;
    }>("POST", "/v1/hybrid-keys", { body: input });
    return envelope.data;
  }

  /** `GET /v1/hybrid-keys` — one page of managed signing keys. */
  async list(opts: HybridKeyListOptions = {}): Promise<HybridKeyListResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridKey[];
      pagination: Pagination;
    }>("GET", "/v1/hybrid-keys", {
      query: {
        limit: opts.limit ?? 20,
        cursor: opts.cursor,
        algorithm: opts.algorithm,
        includeRevoked: opts.includeRevoked,
      },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** `GET /v1/hybrid-keys/:id` — fetch one key, including its public key. */
  async get(id: string): Promise<HybridKeyWithPublic> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridKeyWithPublic;
    }>("GET", `/v1/hybrid-keys/${encodeURIComponent(id)}`);
    return envelope.data;
  }

  /**
   * `DELETE /v1/hybrid-keys/:id` — revoke a key. Existing signatures continue
   * to verify; new sign calls return 409.
   */
  async revoke(id: string): Promise<{ id: string; revokedAt: string }> {
    const envelope = await this.client.request<{
      success: boolean;
      data: { id: string; revokedAt: string };
    }>("DELETE", `/v1/hybrid-keys/${encodeURIComponent(id)}`);
    return envelope.data;
  }

  /** `POST /v1/hybrid-keys/:id/rotate` — generate a new keypair under the
   *  same logical key. Old material is retained for verification. */
  async rotate(id: string, opts: { name?: string } = {}): Promise<HybridKeyWithPublic> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridKeyWithPublic;
    }>("POST", `/v1/hybrid-keys/${encodeURIComponent(id)}/rotate`, {
      body: { name: opts.name },
    });
    return envelope.data;
  }

  /** `GET /v1/hybrid-keys/:id/audit` — recent ledger entries for this key
   *  (creation, rotations, signs, revocation). */
  async audit(
    id: string,
    opts: { limit?: number; cursor?: string } = {},
  ): Promise<HybridKeyAuditResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridKeyAuditEntry[];
      pagination: Pagination;
    }>("GET", `/v1/hybrid-keys/${encodeURIComponent(id)}/audit`, {
      query: { limit: opts.limit, cursor: opts.cursor },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** `POST /v1/sign`. */
  async sign(input: HybridSignInput): Promise<HybridSignResult> {
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridSignResult;
    }>("POST", "/v1/sign", {
      body: {
        keyId: input.keyId,
        payload: encodeBase64(input.payload),
        metadata: input.metadata,
      },
    });
    return envelope.data;
  }

  /** `POST /v1/verify`. */
  async verify(input: HybridVerifyInput): Promise<HybridVerifyResult> {
    if (!input.keyId && !input.publicKey) {
      throw new Error("verify() requires either keyId or publicKey");
    }
    const envelope = await this.client.request<{
      success: boolean;
      data: HybridVerifyResult;
    }>("POST", "/v1/verify", {
      body: {
        keyId: input.keyId,
        publicKey: input.publicKey,
        payload: encodeBase64(input.payload),
        signature: input.signature,
      },
    });
    return envelope.data;
  }
}

function encodeBase64(payload: Uint8Array | string): string {
  if (typeof payload === "string") {
    // Assume UTF-8 text; if the caller already has base64 they should pass bytes.
    return Buffer.from(payload, "utf8").toString("base64");
  }
  return Buffer.from(payload).toString("base64");
}

/**
 * Policies resource — manage org-level signing/verification policy rules
 * enforced by `/v1/sign` and `/v1/verify`.
 */
export class PoliciesResource {
  constructor(private readonly client: PostQ) {}

  /** `GET /v1/policies` — list all policies for the org (seeds defaults on first call). */
  async list(): Promise<Policy[]> {
    const envelope = await this.client.request<{ success: boolean; data: Policy[] }>(
      "GET",
      "/v1/policies",
    );
    return envelope.data;
  }

  /** `GET /v1/policies/:id` — fetch one policy. */
  async get(id: string): Promise<Policy> {
    const envelope = await this.client.request<{ success: boolean; data: Policy }>(
      "GET",
      `/v1/policies/${encodeURIComponent(id)}`,
    );
    return envelope.data;
  }

  /** `POST /v1/policies` — create a new policy. */
  async create(input: PolicyCreateInput): Promise<Policy> {
    const envelope = await this.client.request<{ success: boolean; data: Policy }>(
      "POST",
      "/v1/policies",
      { body: input },
    );
    return envelope.data;
  }

  /** `PATCH /v1/policies/:id` — update a policy. */
  async update(id: string, input: PolicyUpdateInput): Promise<Policy> {
    const envelope = await this.client.request<{ success: boolean; data: Policy }>(
      "PATCH",
      `/v1/policies/${encodeURIComponent(id)}`,
      { body: input },
    );
    return envelope.data;
  }

  /** `DELETE /v1/policies/:id`. */
  async delete(id: string): Promise<{ id: string; deletedAt: string }> {
    const envelope = await this.client.request<{
      success: boolean;
      data: { id: string; deletedAt: string };
    }>("DELETE", `/v1/policies/${encodeURIComponent(id)}`);
    return envelope.data;
  }
}

/**
 * Ledger resource — read the tamper-evident hash chain of signing events,
 * fetch checkpoints / inclusion proofs, and download verifiable bundles.
 */
export class LedgerResource {
  constructor(private readonly client: PostQ) {}

  /** `GET /v1/ledger/entries` — one page of ledger entries. */
  async entries(opts: LedgerEntryListOptions = {}): Promise<{
    data: LedgerEntry[];
    pagination: Pagination;
  }> {
    const envelope = await this.client.request<{
      success: boolean;
      data: LedgerEntry[];
      pagination: Pagination;
    }>("GET", "/v1/ledger/entries", {
      query: {
        limit: opts.limit,
        since: opts.since,
        eventType: opts.eventType,
      },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** `POST /v1/ledger/entries` — append a custom entry to the org ledger. */
  async append(input: LedgerAppendInput): Promise<LedgerEntry> {
    const envelope = await this.client.request<{ success: boolean; data: LedgerEntry }>(
      "POST",
      "/v1/ledger/entries",
      { body: input },
    );
    return envelope.data;
  }

  /** `GET /v1/ledger/checkpoints` — list signed Merkle-root checkpoints. */
  async checkpoints(opts: { limit?: number; cursor?: string } = {}): Promise<{
    data: LedgerCheckpoint[];
    pagination: Pagination;
  }> {
    const envelope = await this.client.request<{
      success: boolean;
      data: LedgerCheckpoint[];
      pagination: Pagination;
    }>("GET", "/v1/ledger/checkpoints", {
      query: { limit: opts.limit, cursor: opts.cursor },
    });
    return { data: envelope.data, pagination: envelope.pagination };
  }

  /** `GET /v1/ledger/checkpoints/latest` — most recent checkpoint, or null. */
  async latestCheckpoint(): Promise<LedgerCheckpoint | null> {
    const envelope = await this.client.request<{
      success: boolean;
      data: LedgerCheckpoint | null;
    }>("GET", "/v1/ledger/checkpoints/latest");
    return envelope.data;
  }

  /** `POST /v1/ledger/seal` — force a new checkpoint over current entries. */
  async seal(): Promise<LedgerSealResult> {
    const envelope = await this.client.request<{ success: boolean; data: LedgerSealResult }>(
      "POST",
      "/v1/ledger/seal",
    );
    return envelope.data;
  }

  /** `GET /v1/ledger/proof/:entryId` — Merkle inclusion proof; auto-seals
   *  if no checkpoint covers the entry yet. */
  async proof(entryId: string): Promise<LedgerInclusionProof> {
    const envelope = await this.client.request<{
      success: boolean;
      data: LedgerInclusionProof;
    }>("GET", `/v1/ledger/proof/${encodeURIComponent(entryId)}`);
    return envelope.data;
  }

  /** `GET /v1/ledger/bundle` — full verifiable bundle: entries + checkpoints
   *  + signing keys. Verify with `postq ledger verify` (Go CLI) or any of the
   *  SDK verify helpers. */
  async bundle(): Promise<LedgerBundle> {
    const envelope = await this.client.request<{ success: boolean; data: LedgerBundle }>(
      "GET",
      "/v1/ledger/bundle",
    );
    return envelope.data;
  }
}

/**
 * Vault resource — manage per-org KMS settings (BYOK). The encrypted secret
 * is never returned in plaintext; updates write-through to the server.
 */
export class VaultResource {
  constructor(private readonly client: PostQ) {}

  /** `GET /v1/vault/settings` — current vault settings, or null. */
  async getSettings(): Promise<VaultSettings | null> {
    const envelope = await this.client.request<{
      success: boolean;
      data: VaultSettings | null;
    }>("GET", "/v1/vault/settings");
    return envelope.data;
  }

  /** `PUT /v1/vault/settings` — set or update KMS settings for the org. */
  async putSettings(input: VaultSettingsInput): Promise<VaultSettings> {
    const envelope = await this.client.request<{ success: boolean; data: VaultSettings }>(
      "PUT",
      "/v1/vault/settings",
      { body: input },
    );
    return envelope.data;
  }

  /** `DELETE /v1/vault/settings` — clear vault settings (revert to env-managed KEK). */
  async clearSettings(): Promise<{ deleted: true }> {
    const envelope = await this.client.request<{ success: boolean; data: { deleted: true } }>(
      "DELETE",
      "/v1/vault/settings",
    );
    return envelope.data;
  }
}