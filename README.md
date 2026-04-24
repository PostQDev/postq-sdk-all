# postq-sdk-all

Official PostQ SDKs for JavaScript/TypeScript, Python, and .NET — quantum-safe cryptography for your applications.

PostQ provides a REST API and SDKs for integrating quantum-safe cryptography into your applications, supporting hybrid signing (classical + post-quantum), key management, cryptographic scanning, and policy enforcement.

All API endpoints are available at `https://api.postq.dev/v1` and require authentication via Bearer token.

---

## SDKs

| Language | Package | Directory |
|---|---|---|
| JavaScript / TypeScript | `@postq/sdk` | [`sdks/js/`](sdks/js/) |
| Python | `postq-sdk` | [`sdks/python/`](sdks/python/) |
| .NET | `PostQ.Sdk` | [`sdks/dotnet/`](sdks/dotnet/) |

---

## JavaScript / TypeScript

### Installation

```bash
npm install @postq/sdk
```

### Usage

```typescript
import { PostQ } from "@postq/sdk";

const pq = new PostQ({
  apiKey: process.env.POSTQ_API_KEY!,
  environment: "production",
});

// Sign a message with hybrid cryptography
const signature = await pq.sign({
  payload: Buffer.from("Hello Quantum World"),
  algorithm: "dilithium3+ed25519",
  keyId: "vault://signing/production",
});

console.log(signature.algorithm);
// → "dilithium3+ed25519"

// Verify the hybrid signature
const result = await pq.verify({
  payload: Buffer.from("Hello Quantum World"),
  signature: signature.signature,
  keyId: "vault://signing/production",
});

console.log(result.valid);
// → true

// List managed keys
const { keys } = await pq.listKeys();
keys.forEach(k => console.log(k.id, k.pq_ready));

// Run a quantum risk scan
const scan = await pq.scan({
  targets: ["kubernetes://production", "azure://subscription-id"],
  depth: "full",
  include: ["tls", "signing", "encryption"],
});

console.log(scan.summary?.risk_score);
// → 72
```

### Build & Test

```bash
cd sdks/js
npm install
npm run lint   # TypeScript type-check
npm test       # Jest test suite
npm run build  # Compile to dist/
```

---

## Python

### Installation

```bash
pip install postq-sdk
```

### Usage

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

# List managed keys
keys = pq.list_keys()
for key in keys.keys:
    print(key.id, key.pq_ready)

# Run a quantum risk scan
scan = pq.scan(
    targets=["kubernetes://production", "azure://subscription-id"],
    depth="full",
    include=["tls", "signing", "encryption"],
)

print(scan.summary.risk_score)
# → 72
```

### Build & Test

```bash
cd sdks/python
pip install -e ".[dev]"
python -m pytest
```

---

## .NET

### Installation

```bash
dotnet add package PostQ.Sdk
```

### Usage

```csharp
using PostQ;

var pq = new PostQClient(new PostQClientOptions
{
    ApiKey = Environment.GetEnvironmentVariable("POSTQ_API_KEY")!,
    Environment = "production",
});

// Sign a message with hybrid cryptography
var signature = await pq.SignAsync(new SignRequest
{
    Payload = System.Text.Encoding.UTF8.GetBytes("Hello Quantum World"),
    AlgorithmName = Algorithm.Dilithium3Ed25519,
    KeyId = "vault://signing/production",
});

Console.WriteLine(signature.AlgorithmName);
// → "dilithium3+ed25519"

// Verify the hybrid signature
var result = await pq.VerifyAsync(new VerifyRequest
{
    Payload = System.Text.Encoding.UTF8.GetBytes("Hello Quantum World"),
    Signature = signature.Signature,
    KeyId = "vault://signing/production",
});

Console.WriteLine(result.Valid);
// → True

// List managed keys
var keys = await pq.ListKeysAsync();
foreach (var key in keys.Keys)
    Console.WriteLine($"{key.Id} pq_ready={key.PqReady}");

// Run a quantum risk scan
var scan = await pq.ScanAsync(new ScanRequest
{
    Targets = ["kubernetes://production", "azure://subscription-id"],
    Depth = "full",
    Include = ["tls", "signing", "encryption"],
});

Console.WriteLine(scan.Summary?.RiskScore);
// → 72
```

### Build & Test

```bash
cd sdks/dotnet
dotnet build
dotnet test
```

---

## Supported Algorithms

| Algorithm | Classical | Post-Quantum | NIST Level |
|---|---|---|---|
| `dilithium3+ed25519` | Ed25519 | ML-DSA-65 | 3 |
| `dilithium5+p384` | ECDSA P-384 | ML-DSA-87 | 5 |
| `falcon512+ed25519` | Ed25519 | Falcon-512 | 1 |

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/sign` | `POST` | Create a hybrid signature |
| `/v1/verify` | `POST` | Verify a hybrid signature |
| `/v1/keys` | `GET` | List managed cryptographic keys |
| `/v1/scan` | `POST` | Trigger a quantum risk scan |

All requests must include an `Authorization: Bearer <api-key>` header. You can generate API keys from the PostQ dashboard under **Settings → API Keys**.

> ⚠️ **Security**: Never expose API keys in client-side code. Use environment variables and server-side API calls only.

---

## License

MIT
