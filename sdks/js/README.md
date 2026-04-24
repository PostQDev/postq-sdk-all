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
