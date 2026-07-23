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

# Fetch a full scan record (HNDL, certificate, TLS, normalized findings)
detail = pq.scans.get(result.id)
print(detail.hndl.severity if detail.hndl else None,
      detail.certificate.days_until_expiry if detail.certificate else None)

# Download the CycloneDX 1.6 CBOM for a scan
cbom = pq.scans.cbom(result.id)  # parsed dict

# Or ask the API to perform and persist a real scan
tls = pq.scans.run_url(target="example.com")
aws = pq.scans.run_cloud(
    provider="aws",
    target="123456789012",
    aws={"regions": ["us-east-1"]},
)
gcp = pq.scans.run_cloud(
    provider="gcp",
    target="projects/acme/locations/us-east1/keyRings/production",
    gcp={"keyRingName": "projects/acme/locations/us-east1/keyRings/production"},
)
```

## Migration control plane (0.7.0+)

```python
project = pq.migrations.create(
    name="EO 14412 migration",
    track="both",
    target_date="2030-12-31",
    include_risk=["CRITICAL", "HIGH"],
)
pq.migrations.update(project.id, status="active")
status = pq.migrations.eo_14412()
```

## Assets and keys (0.3.0+)

```python
# Browse your cryptographic inventory
assets = pq.assets.list(provider="aws", risk="HIGH", limit=50)
for a in assets.data:
    print(a.name, a.algorithm, a.risk)

# Or stream every asset
for a in pq.assets.iter_all(environment="production"):
    ...

# Browse keys discovered by cloud scans
keys = pq.keys.list(algorithm="RSA", risk="High")
for k in keys.data:
    print(k.provider, k.region, k.external_id, k.algorithm)
```

## Hybrid signing and multicloud Vault

```python
pq.vault.put_settings(
    default_kek_provider="gcp-kms",
    gcp={
        "kekKeyName": "projects/acme/locations/global/keyRings/postq/cryptoKeys/vault-kek",
        "keyRingName": "projects/acme/locations/us-east1/keyRings/postq-signing",
        "protectionLevel": "HSM",
    },
)
key = pq.hybrid_keys.create(
    name="release-signing",
    algorithm="mldsa65+ecdsa-p256",
    kek_provider="gcp-kms",
    key_provider="gcp-kms",
)
signature = pq.sign(key_id=key.id, payload="release manifest")
assert pq.verify(
    public_key=key.public_key,
    payload="release manifest",
    signature=signature.signature,
).ok
```

## Configuration

| Argument      | Default                  | Notes                                  |
| ------------- | ------------------------ | -------------------------------------- |
| `api_key`     | `$POSTQ_API_KEY`         | `pq_live_…` from your dashboard        |
| `base_url`    | `https://api.postq.dev`  | Override for staging or self-hosted    |
| `timeout`     | `30.0`                   | Per-request timeout in seconds         |
| `max_retries` | `3`                      | Idempotent-request retries on 429/5xx  |

POST operations are never automatically replayed because they can create keys,
signatures, scans, policies, or Ledger entries.

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
