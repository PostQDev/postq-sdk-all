# @postq/sdk

Official PostQ SDK for JavaScript and TypeScript. Submit quantum-risk scans and read results from the [PostQ API](https://api.postq.dev).

```bash
npm install @postq/sdk
```

## Quickstart

```ts
import { PostQ } from "@postq/sdk";

const pq = new PostQ({ apiKey: process.env.POSTQ_API_KEY! });

// Submit a scan
const result = await pq.scans.submit({
  type: "url",
  target: "example.com",
  riskScore: 85,
  riskLevel: "High",
  findings: [
    { severity: "high", title: "RSA-2048 public key" },
  ],
});
console.log(result.url); // https://app.postq.dev/scans/...

// List recent scans
const page = await pq.scans.list({ limit: 10 });
for (const scan of page.data) {
  console.log(scan.target, scan.riskLevel);
}

// Iterate every scan with automatic pagination
for await (const scan of pq.scans.iterAll()) {
  // ...
}

// Fetch a full scan record (HNDL, certificate, TLS, normalized findings)
const detail = await pq.scans.get(result.id);
console.log(detail.hndl?.severity, detail.certificate?.daysUntilExpiry);

// Download the CycloneDX 1.6 CBOM for a scan
const cbom = await pq.scans.cbom(result.id);            // parsed object
const raw = await pq.scans.cbom(result.id, { raw: true }); // JSON string
```

## Assets and keys (0.3.0+)

```ts
// Browse your cryptographic inventory
const assets = await pq.assets.list({ provider: "aws", risk: "high", limit: 50 });
for (const a of assets.data) {
  console.log(a.name, a.algorithm, a.riskLevel);
}

// Or stream every asset
for await (const a of pq.assets.iterAll({ environment: "production" })) {
  // ...
}

// Browse keys discovered by cloud scans
const keys = await pq.keys.list({ algorithm: "RSA", quantumVulnerable: true });
for (const k of keys.data) {
  console.log(k.provider, k.region, k.keyId, k.algorithm);
}
```

## Configuration

| Option      | Default                  | Notes                                       |
| ----------- | ------------------------ | ------------------------------------------- |
| `apiKey`    | _required_               | `pq_live_…` from your PostQ dashboard       |
| `baseUrl`   | `https://api.postq.dev`  | Override for staging or self-hosted         |
| `timeoutMs` | `30000`                  | Per-request timeout                         |
| `fetch`     | `globalThis.fetch`       | Pass a custom fetch (testing, polyfill)     |

## Errors

All errors extend `PostQError`. Catch the base class to catch them all:

```ts
import { PostQ, PostQAuthError, PostQRateLimitError } from "@postq/sdk";

try {
  await pq.scans.list();
} catch (err) {
  if (err instanceof PostQAuthError)      console.error("bad API key");
  else if (err instanceof PostQRateLimitError) console.error("slow down");
  else throw err;
}
```

| Class                  | When                                  |
| ---------------------- | ------------------------------------- |
| `PostQConfigError`     | Missing/invalid constructor input     |
| `PostQAuthError`       | 401 — bad, revoked, or expired key    |
| `PostQNotFoundError`   | 404                                   |
| `PostQRateLimitError`  | 429                                   |
| `PostQServerError`     | 5xx                                   |
| `PostQNetworkError`    | DNS, connection refused, timeout      |
| `PostQError`           | Base class, thrown for any other 4xx  |

## Requirements

- Node 18+ (uses global `fetch`). For older Node, pass a `fetch` polyfill.
- TypeScript 5.0+ (types are bundled).

## License

MIT — see [LICENSE](../../LICENSE).
