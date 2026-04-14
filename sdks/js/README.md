# @postq/sdk

Official PostQ SDK for JavaScript/TypeScript — quantum-safe cryptography for your applications.

## Installation

```bash
npm install @postq/sdk
```

## Quick start

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
```

## API

### `new PostQ(options)`

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `apiKey` | `string` | ✅ | — | PostQ API key |
| `environment` | `"production" \| "staging" \| "development"` | ❌ | `"production"` | Target environment |
| `baseUrl` | `string` | ❌ | `https://api.postq.io/v1` | Override base URL |

### `pq.sign(input)`

Create a hybrid signature combining a classical and a post-quantum algorithm.

### `pq.verify(input)`

Verify a hybrid signature. Returns validity of both components independently.

### `pq.listKeys()`

List all cryptographic keys managed by PostQ.

### `pq.scan(input)`

Trigger a quantum risk scan across specified infrastructure targets.

## Development

```bash
npm install
npm run lint   # TypeScript type-check
npm test       # Run Jest tests
npm run build  # Compile TypeScript to dist/
```

## License

MIT
