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
