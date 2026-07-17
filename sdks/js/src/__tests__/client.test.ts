import {
  PostQ,
  PostQAuthError,
  PostQConfigError,
  PostQError,
  PostQNotFoundError,
  PostQRateLimitError,
  PostQServerError,
} from "../index";

function mockFetch(body: unknown, status = 200) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(text),
  });
}

describe("PostQ constructor", () => {
  it("throws PostQConfigError when apiKey is empty", () => {
    expect(() => new PostQ({ apiKey: "" })).toThrow(PostQConfigError);
  });

  it("throws PostQConfigError when apiKey is whitespace", () => {
    expect(() => new PostQ({ apiKey: "   " })).toThrow(PostQConfigError);
  });

  it("accepts a valid apiKey", () => {
    expect(
      () => new PostQ({ apiKey: "pq_live_test", fetch: jest.fn() as never }),
    ).not.toThrow();
  });
});

describe("PostQ.scans.submit()", () => {
  it("POSTs the payload to /v1/scans and returns ScanSubmitResult", async () => {
    const fetchMock = mockFetch(
      {
        success: true,
        data: {
          id: "abc-123",
          createdAt: "2026-04-23T12:00:00Z",
          url: "https://app.postq.dev/scans/abc-123",
        },
      },
      201,
    );

    const pq = new PostQ({
      apiKey: "pq_live_test",
      baseUrl: "https://api.example.com",
      fetch: fetchMock as never,
    });

    const result = await pq.scans.submit({
      type: "url",
      target: "example.com",
      riskScore: 85,
      riskLevel: "High",
      findings: [{ severity: "high", title: "RSA-2048 public key" }],
    });

    expect(result.id).toBe("abc-123");
    expect(result.url).toContain("/scans/abc-123");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/scans");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer pq_live_test",
    );
    const body = JSON.parse(init.body as string);
    expect(body.type).toBe("url");
    expect(body.source).toBe("sdk");
    expect(body.findings).toHaveLength(1);
  });

  it("defaults source to 'sdk' but accepts overrides", async () => {
    const fetchMock = mockFetch(
      { success: true, data: { id: "x", createdAt: "x", url: "x" } },
      201,
    );
    const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });
    await pq.scans.submit({
      type: "url",
      target: "a.com",
      riskScore: 0,
      riskLevel: "Safe",
      source: "lambda",
    });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string).source).toBe("lambda");
  });
});

describe("PostQ.scans.list()", () => {
  it("GETs /v1/scans with limit and parses the response", async () => {
    const fetchMock = mockFetch({
      success: true,
      data: [
        {
          id: "s1",
          type: "url",
          target: "a.com",
          source: "cli",
          riskScore: 50,
          riskLevel: "Medium",
          findingsCount: 2,
          createdAt: "2026-04-22T00:00:00Z",
          url: "https://app.postq.dev/scans/s1",
        },
      ],
      pagination: { limit: 20, nextCursor: null },
    });

    const pq = new PostQ({
      apiKey: "pq_live_test",
      baseUrl: "https://api.example.com",
      fetch: fetchMock as never,
    });
    const page = await pq.scans.list({ limit: 20 });

    expect(page.data).toHaveLength(1);
    expect(page.data[0].id).toBe("s1");
    expect(page.pagination.nextCursor).toBeNull();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.com/v1/scans?limit=20");
    expect(init.method).toBe("GET");
  });
});

describe("server-side scan execution", () => {
  it("POSTs cloud scan options to /v1/scans/cloud", async () => {
    const fetchMock = mockFetch({
      success: true,
      data: {
        id: "scan-cloud",
        createdAt: "2026-07-16T00:00:00Z",
        provider: "aws",
        target: "123456789012",
        mode: "live",
        riskScore: 80,
        riskLevel: "Critical",
        findingsCount: 4,
        resourcesCount: 10,
        summary: {
          totalEndpoints: 10,
          quantumVulnerable: 4,
          hybridEnabled: 0,
          pqReady: 6,
        },
        url: "https://app.postq.dev/scans/scan-cloud",
      },
    }, 201);
    const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });

    const result = await pq.scans.runCloud({
      provider: "aws",
      target: "123456789012",
      aws: { regions: ["us-east-1"] },
    });

    expect(result.provider).toBe("aws");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.postq.dev/v1/scans/cloud");
    expect(JSON.parse(init.body as string).aws.regions).toEqual(["us-east-1"]);
  });

  it("POSTs URL scan requests to /v1/scans/url", async () => {
    const fetchMock = mockFetch({
      success: true,
      data: { id: "scan-url", target: "example.com" },
    }, 201);
    const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });
    const result = await pq.scans.runUrl({ target: "example.com", timeoutMs: 5000 });
    expect(result.id).toBe("scan-url");
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.postq.dev/v1/scans/url");
  });
});

describe("hybrid payload encoding", () => {
  it("base64-encodes UTF-8 text without relying on a Node-only Buffer path", async () => {
    const fetchMock = mockFetch({
      success: true,
      data: {
        keyId: "00000000-0000-4000-8000-000000000001",
        algorithm: "mldsa65+ed25519",
        signature: "sig",
        publicKey: "{}",
        payloadSha256: "00",
        payloadSize: 6,
      },
    });
    const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });
    await pq.sign({
      keyId: "00000000-0000-4000-8000-000000000001",
      payload: "héllo",
    });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string).payload).toBe(
      Buffer.from("héllo", "utf8").toString("base64"),
    );
  });

  it("base64-encodes without btoa or Buffer in the SDK runtime", async () => {
    const originalBtoa = globalThis.btoa;
    Object.defineProperty(globalThis, "btoa", {
      configurable: true,
      value: undefined,
    });
    try {
      const fetchMock = mockFetch({
        success: true,
        data: {
          keyId: "00000000-0000-4000-8000-000000000001",
          algorithm: "mldsa65+ed25519",
          signature: "sig",
          publicKey: "{}",
          payloadSha256: "00",
          payloadSize: 6,
        },
      });
      const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });
      await pq.sign({
        keyId: "00000000-0000-4000-8000-000000000001",
        payload: "héllo",
      });
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(init.body as string).payload).toBe("aMOpbGxv");
    } finally {
      Object.defineProperty(globalThis, "btoa", {
        configurable: true,
        value: originalBtoa,
      });
    }
  });
});

describe("Vault settings", () => {
  it("returns the savedAt mutation result and sends defaultKekProvider", async () => {
    const fetchMock = mockFetch({
      success: true,
      data: { savedAt: "2026-07-16T00:00:00Z" },
    });
    const pq = new PostQ({ apiKey: "pq_live_test", fetch: fetchMock as never });
    const result = await pq.vault.putSettings({
      defaultKekProvider: "gcp-kms",
      gcp: {
        kekKeyName: "projects/acme/locations/global/keyRings/postq/cryptoKeys/kek",
      },
    });
    expect(result.savedAt).toBe("2026-07-16T00:00:00Z");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string).defaultKekProvider).toBe("gcp-kms");
  });
});

describe("error mapping", () => {
  it("401 -> PostQAuthError", async () => {
    const pq = new PostQ({
      apiKey: "pq_live_bad",
      fetch: mockFetch({ success: false, error: "Invalid API key" }, 401) as never,
    });
    await expect(pq.scans.list()).rejects.toThrow(PostQAuthError);
  });

  it("404 -> PostQNotFoundError", async () => {
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: mockFetch({ success: false, error: "Not found" }, 404) as never,
    });
    await expect(pq.scans.list()).rejects.toThrow(PostQNotFoundError);
  });

  it("429 -> PostQRateLimitError", async () => {
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: mockFetch({ success: false, error: "Slow down" }, 429) as never,
    });
    await expect(pq.scans.list()).rejects.toThrow(PostQRateLimitError);
  });

  it("503 -> PostQServerError", async () => {
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: mockFetch({ success: false, error: "Down" }, 503) as never,
    });
    await expect(pq.scans.list()).rejects.toThrow(PostQServerError);
  });

  it("400 with no specific mapping -> base PostQError", async () => {
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: mockFetch({ success: false, error: "Bad" }, 400) as never,
    });
    await expect(pq.scans.list()).rejects.toThrow(PostQError);
  });
});

describe("retry safety", () => {
  it("retries an idempotent GET after a transient 503", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        headers: { get: () => "0" },
        text: () => Promise.resolve('{"error":"temporary"}'),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: () => null },
        text: () =>
          Promise.resolve(
            '{"success":true,"data":[],"pagination":{"limit":20,"nextCursor":null}}',
          ),
      });
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: fetchMock as never,
      maxRetries: 1,
    });
    await expect(pq.scans.list()).resolves.toEqual({
      data: [],
      pagination: { limit: 20, nextCursor: null },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never retries a non-idempotent POST", async () => {
    const fetchMock = mockFetch({ success: false, error: "temporary" }, 503);
    const pq = new PostQ({
      apiKey: "pq_live_test",
      fetch: fetchMock as never,
      maxRetries: 3,
    });
    await expect(
      pq.scans.submit({
        type: "url",
        target: "example.com",
        riskScore: 0,
        riskLevel: "Safe",
      }),
    ).rejects.toThrow(PostQServerError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("PostQ.health()", () => {
  it("GETs /health", async () => {
    const fetchMock = mockFetch({ status: "ok" });
    const pq = new PostQ({
      apiKey: "pq_live_test",
      baseUrl: "https://api.example.com",
      fetch: fetchMock as never,
    });
    const out = await pq.health();
    expect(out.status).toBe("ok");
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toBe("https://api.example.com/health");
  });
});
