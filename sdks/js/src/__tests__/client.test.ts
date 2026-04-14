import { PostQ, PostQError, PostQConfigError } from "../index";
import type { SignResponse, VerifyResponse, ListKeysResponse, ScanResponse } from "../index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockFetch(body: unknown, status = 200) {
  const text = JSON.stringify(body);
  return jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(text),
  });
}

const SIGN_RESPONSE: SignResponse = {
  signature: "base64-combined-signature",
  classical_sig: "base64-ed25519-signature",
  pq_sig: "base64-dilithium3-signature",
  algorithm: "dilithium3+ed25519",
  key_id: "vault://signing/production",
  timestamp: "2026-04-05T12:00:00Z",
  policy_compliant: true,
};

const VERIFY_RESPONSE: VerifyResponse = {
  valid: true,
  classical_valid: true,
  pq_valid: true,
  algorithm: "dilithium3+ed25519",
  key_id: "vault://signing/production",
};

const LIST_KEYS_RESPONSE: ListKeysResponse = {
  keys: [
    {
      id: "vault://signing/production",
      algorithm: "dilithium3+ed25519",
      created_at: "2026-01-15T08:00:00Z",
      status: "active",
      backend: "azure-key-vault",
      pq_ready: true,
    },
    {
      id: "vault://signing/staging",
      algorithm: "ed25519",
      created_at: "2025-06-01T10:00:00Z",
      status: "active",
      backend: "hashicorp-vault",
      pq_ready: false,
    },
  ],
};

const SCAN_RESPONSE: ScanResponse = {
  scan_id: "scan_abc123",
  status: "completed",
  summary: {
    total_endpoints: 4184,
    quantum_vulnerable: 3012,
    risk_score: 72,
    recommendation: "Begin hybrid migration for signing keys",
  },
};

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe("PostQ constructor", () => {
  it("throws PostQConfigError when apiKey is empty", () => {
    expect(() => new PostQ({ apiKey: "" })).toThrow(PostQConfigError);
  });

  it("throws PostQConfigError when apiKey is whitespace", () => {
    expect(() => new PostQ({ apiKey: "   " })).toThrow(PostQConfigError);
  });

  it("creates a client with valid apiKey", () => {
    expect(() => new PostQ({ apiKey: "pq_live_sk_test" })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// sign()
// ---------------------------------------------------------------------------

describe("PostQ.sign()", () => {
  let pq: PostQ;

  beforeEach(() => {
    pq = new PostQ({ apiKey: "pq_live_sk_test", baseUrl: "https://api.example.com/v1" });
    global.fetch = mockFetch(SIGN_RESPONSE);
  });

  it("POSTs to /sign and returns a SignResponse", async () => {
    const result = await pq.sign({
      payload: Buffer.from("Hello Quantum World"),
      algorithm: "dilithium3+ed25519",
      keyId: "vault://signing/production",
    });

    expect(result).toEqual(SIGN_RESPONSE);
    expect(global.fetch).toHaveBeenCalledTimes(1);

    const [url, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/sign");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.algorithm).toBe("dilithium3+ed25519");
    expect(body.key_id).toBe("vault://signing/production");
    expect(typeof body.payload).toBe("string"); // base64
  });

  it("includes context when provided", async () => {
    await pq.sign({
      payload: Buffer.from("data"),
      algorithm: "dilithium3+ed25519",
      keyId: "vault://signing/production",
      context: { service: "payment-api", environment: "production" },
    });

    const [, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.context).toEqual({ service: "payment-api", environment: "production" });
  });

  it("sets Authorization header", async () => {
    await pq.sign({
      payload: Buffer.from("data"),
      algorithm: "dilithium3+ed25519",
      keyId: "vault://signing/production",
    });

    const [, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer pq_live_sk_test");
  });

  it("throws PostQError on non-2xx response", async () => {
    global.fetch = mockFetch({ code: "UNAUTHORIZED", message: "Invalid API key" }, 401);
    await expect(
      pq.sign({
        payload: Buffer.from("data"),
        algorithm: "dilithium3+ed25519",
        keyId: "vault://signing/production",
      })
    ).rejects.toThrow(PostQError);
  });
});

// ---------------------------------------------------------------------------
// verify()
// ---------------------------------------------------------------------------

describe("PostQ.verify()", () => {
  let pq: PostQ;

  beforeEach(() => {
    pq = new PostQ({ apiKey: "pq_live_sk_test", baseUrl: "https://api.example.com/v1" });
    global.fetch = mockFetch(VERIFY_RESPONSE);
  });

  it("POSTs to /verify and returns a VerifyResponse", async () => {
    const result = await pq.verify({
      payload: Buffer.from("Hello Quantum World"),
      signature: "base64-combined-signature",
      keyId: "vault://signing/production",
    });

    expect(result).toEqual(VERIFY_RESPONSE);
    expect(result.valid).toBe(true);
    expect(result.classical_valid).toBe(true);
    expect(result.pq_valid).toBe(true);

    const [url, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/verify");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.signature).toBe("base64-combined-signature");
    expect(body.key_id).toBe("vault://signing/production");
  });

  it("throws PostQError when signature is invalid (API 422)", async () => {
    global.fetch = mockFetch({ code: "INVALID_SIGNATURE", message: "Signature mismatch" }, 422);
    await expect(
      pq.verify({
        payload: Buffer.from("data"),
        signature: "bad-sig",
        keyId: "vault://signing/production",
      })
    ).rejects.toThrow(PostQError);
  });
});

// ---------------------------------------------------------------------------
// listKeys()
// ---------------------------------------------------------------------------

describe("PostQ.listKeys()", () => {
  let pq: PostQ;

  beforeEach(() => {
    pq = new PostQ({ apiKey: "pq_live_sk_test", baseUrl: "https://api.example.com/v1" });
    global.fetch = mockFetch(LIST_KEYS_RESPONSE);
  });

  it("GETs /keys and returns a ListKeysResponse", async () => {
    const result = await pq.listKeys();

    expect(result.keys).toHaveLength(2);
    expect(result.keys[0].pq_ready).toBe(true);
    expect(result.keys[1].pq_ready).toBe(false);

    const [url, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/keys");
    expect(init.method).toBe("GET");
  });
});

// ---------------------------------------------------------------------------
// scan()
// ---------------------------------------------------------------------------

describe("PostQ.scan()", () => {
  let pq: PostQ;

  beforeEach(() => {
    pq = new PostQ({ apiKey: "pq_live_sk_test", baseUrl: "https://api.example.com/v1" });
    global.fetch = mockFetch(SCAN_RESPONSE);
  });

  it("POSTs to /scan and returns a ScanResponse", async () => {
    const result = await pq.scan({
      targets: ["kubernetes://production", "azure://subscription-id"],
      depth: "full",
      include: ["tls", "signing", "encryption"],
    });

    expect(result.scan_id).toBe("scan_abc123");
    expect(result.status).toBe("completed");
    expect(result.summary?.risk_score).toBe(72);

    const [url, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/scan");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.targets).toEqual(["kubernetes://production", "azure://subscription-id"]);
  });

  it("defaults depth to full and include to all categories", async () => {
    await pq.scan({ targets: ["kubernetes://production"] });

    const [, init] = (global.fetch as jest.Mock).mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.depth).toBe("full");
    expect(body.include).toEqual(["tls", "signing", "encryption"]);
  });
});

// ---------------------------------------------------------------------------
// Network error handling
// ---------------------------------------------------------------------------

describe("PostQ network errors", () => {
  let pq: PostQ;

  beforeEach(() => {
    pq = new PostQ({ apiKey: "pq_live_sk_test", baseUrl: "https://api.example.com/v1" });
  });

  it("throws PostQError when fetch rejects (network failure)", async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    await expect(
      pq.listKeys()
    ).rejects.toThrow(PostQError);
  });
});
