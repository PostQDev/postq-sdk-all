# postq-sdk

Official PostQ SDK for Python. Submit quantum-risk scans and read results from the [PostQ API](https://api.postq.dev).

```bash
pip install postq-sdk
```

## Quickstart

```python
from postq import PostQ, Finding

pq = PostQ(api_key="pq_live_…")  # or set POSTQ_API_KEY env var

# Submit a scan
result = pq.scans.submit(
    type="url",
    target="example.com",
    risk_score=85,
    risk_level="High",
    findings=[
        Finding(severity="high", title="RSA-2048 public key"),
    ],
)
print(result.url)  # https://app.postq.dev/scans/...

# List recent scans
for scan in pq.scans.list(limit=10):
    print(scan.target, scan.risk_level)

# Iterate every scan with automatic pagination
for scan in pq.scans.iter_all():
    ...
```

## Assets and keys (0.3.0+)

```python
# Browse your cryptographic inventory
assets = pq.assets.list(provider="aws", risk="high", limit=50)
for a in assets.data:
    print(a.name, a.algorithm, a.risk_level)

# Or stream every asset
for a in pq.assets.iter_all(environment="production"):
    ...

# Browse keys discovered by cloud scans
keys = pq.keys.list(algorithm="RSA", quantum_vulnerable=True)
for k in keys.data:
    print(k.provider, k.region, k.key_id, k.algorithm)
```
```

## Configuration

| Argument      | Default                  | Notes                                  |
| ------------- | ------------------------ | -------------------------------------- |
| `api_key`     | `$POSTQ_API_KEY`         | `pq_live_…` from your dashboard        |
| `base_url`    | `https://api.postq.dev`  | Override for staging or self-hosted    |
| `timeout`     | `30.0`                   | Per-request timeout in seconds         |
| `max_retries` | `3`                      | Retries on 429/5xx with backoff        |

## Errors

All exceptions extend `PostQError`:

```python
from postq import PostQ, PostQAuthError, PostQRateLimitError

try:
    pq.scans.list()
except PostQAuthError:
    print("bad API key")
except PostQRateLimitError:
    print("slow down")
```

| Exception                | When                                  |
| ------------------------ | ------------------------------------- |
| `PostQConfigError`       | Missing/invalid constructor input     |
| `PostQAuthError`         | 401 — bad, revoked, or expired key    |
| `PostQNotFoundError`     | 404                                   |
| `PostQRateLimitError`    | 429                                   |
| `PostQServerError`       | 5xx                                   |
| `PostQNetworkError`      | DNS, connection refused, timeout      |
| `PostQError`             | Base class                            |

## Requirements

- Python 3.9+
- Single dependency: [`requests`](https://pypi.org/project/requests/)

## License

MIT — see [LICENSE](../../LICENSE).
