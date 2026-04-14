import {
  PostQOptions,
  SignInput,
  SignResponse,
  VerifyInput,
  VerifyResponse,
  ListKeysResponse,
  ScanInput,
  ScanResponse,
  PostQApiError,
} from "./types";
import { PostQConfigError, PostQError } from "./errors";

const DEFAULT_BASE_URL = "https://api.postq.io/v1";
const DEFAULT_ENVIRONMENT = "production";

/**
 * PostQ SDK client.
 *
 * @example
 * ```ts
 * import { PostQ } from "@postq/sdk";
 *
 * const pq = new PostQ({ apiKey: process.env.POSTQ_API_KEY! });
 *
 * const signature = await pq.sign({
 *   payload: Buffer.from("Hello Quantum World"),
 *   algorithm: "dilithium3+ed25519",
 *   keyId: "vault://signing/production",
 * });
 * ```
 */
export class PostQ {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly environment: string;

  constructor(options: PostQOptions) {
    if (!options.apiKey || options.apiKey.trim() === "") {
      throw new PostQConfigError(
        "apiKey is required. Provide it via the PostQ constructor options."
      );
    }
    this.apiKey = options.apiKey;
    this.environment = options.environment ?? DEFAULT_ENVIRONMENT;
    this.baseUrl = options.baseUrl?.replace(/\/$/, "") ?? DEFAULT_BASE_URL;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Create a hybrid signature combining a classical and a post-quantum algorithm.
   *
   * @param input - Signing parameters.
   * @returns The composite signature plus metadata.
   */
  async sign(input: SignInput): Promise<SignResponse> {
    const body: Record<string, unknown> = {
      payload: this.toBase64(input.payload),
      algorithm: input.algorithm,
      key_id: input.keyId,
    };
    if (input.context) {
      body.context = input.context;
    }
    return this.request<SignResponse>("POST", "/sign", body);
  }

  /**
   * Verify a hybrid signature.
   *
   * @param input - Verification parameters.
   * @returns Validity information for both signature components.
   */
  async verify(input: VerifyInput): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("POST", "/verify", {
      payload: this.toBase64(input.payload),
      signature: input.signature,
      key_id: input.keyId,
    });
  }

  /**
   * List all cryptographic keys managed by PostQ.
   *
   * @returns List of keys with algorithm and PQ-readiness metadata.
   */
  async listKeys(): Promise<ListKeysResponse> {
    return this.request<ListKeysResponse>("GET", "/keys");
  }

  /**
   * Trigger a quantum risk scan across specified infrastructure targets.
   *
   * @param input - Scan parameters.
   * @returns Scan job identifier and results summary.
   */
  async scan(input: ScanInput): Promise<ScanResponse> {
    return this.request<ScanResponse>("POST", "/scan", {
      targets: input.targets,
      depth: input.depth ?? "full",
      include: input.include ?? ["tls", "signing", "encryption"],
    });
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private buildHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      "Content-Type": "application/json",
      "X-PostQ-Environment": this.environment,
    };
  }

  private toBase64(data: Buffer | Uint8Array): string {
    return Buffer.from(data).toString("base64");
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: Record<string, unknown>
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const init: RequestInit = {
      method,
      headers: this.buildHeaders(),
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (err) {
      throw new PostQError(
        `Network error while calling ${method} ${path}: ${(err as Error).message}`,
        0
      );
    }

    const text = await response.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new PostQError(
        `Unexpected non-JSON response from ${method} ${path}: ${text}`,
        response.status
      );
    }

    if (!response.ok) {
      const apiErr = json as Partial<PostQApiError>;
      throw new PostQError(
        apiErr.message ?? `Request failed with status ${response.status}`,
        response.status,
        apiErr.code
      );
    }

    return json as T;
  }
}
