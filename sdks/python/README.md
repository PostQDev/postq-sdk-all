# postq-sdk

Official PostQ SDK for Python — quantum-safe cryptography for your applications.

## Installation

```bash
pip install postq-sdk
```

## Quick start

```python
from postq import PostQ

pq = PostQ(api_key="pq_live_sk_...")

# Sign a message with hybrid cryptography
sig = pq.sign(
    payload=b"Hello Quantum World",
    algorithm="dilithium3+ed25519",
    key_id="vault://signing/production",
)

print(sig.algorithm)
# → "dilithium3+ed25519"

# Verify the hybrid signature
result = pq.verify(
    payload=b"Hello Quantum World",
    signature=sig.signature,
    key_id="vault://signing/production",
)

print(result.valid)
# → True
```

## API

### `PostQ(api_key, environment="production", base_url=...)`

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `api_key` | `str` | ✅ | — | PostQ API key |
| `environment` | `str` | ❌ | `"production"` | Target environment |
| `base_url` | `str` | ❌ | `https://api.postq.dev/v1` | Override base URL |

### `pq.sign(payload, algorithm, key_id, context=None)`

Create a hybrid signature. Returns a `SignResponse`.

### `pq.verify(payload, signature, key_id)`

Verify a hybrid signature. Returns a `VerifyResponse`.

### `pq.list_keys()`

List all managed keys. Returns a `ListKeysResponse`.

### `pq.scan(targets, depth="full", include=None)`

Trigger a quantum risk scan. Returns a `ScanResponse`.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
