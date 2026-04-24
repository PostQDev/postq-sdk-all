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
  Asset,
  AssetListOptions,
  AssetListResult,
  Key,
  KeyListOptions,
  KeyListResult,
} from "./types";

const DEFAULT_BASE_URL = "https://api.postq.dev";
const SDK_VERSION = "0.3.0";

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
  }

  /** Hit `GET /health`. Throws if the API is down. */
  async health(): Promise<HealthResult> {
    return this.request<HealthResult>("GET", "/health");
  }

  /** @internal */
  async request<T>(
    method: "GET" | "POST",
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

  /** Walk every key across pages. */
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
