# PostQ.Sdk

Official PostQ SDK for .NET — quantum-safe cryptography for your applications.

## Installation

```bash
dotnet add package PostQ.Sdk
```

## Quick start

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
```

## API

### `PostQClient(PostQClientOptions options, HttpClient? httpClient = null)`

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `ApiKey` | `string` | ✅ | — | PostQ API key |
| `Environment` | `string` | ❌ | `"production"` | Target environment |
| `BaseUrl` | `string` | ❌ | `https://api.postq.io/v1` | Override base URL |

Pass a custom `HttpClient` for testing or to configure timeouts, proxies, etc.

### `SignAsync(SignRequest, CancellationToken?)`

Create a hybrid signature. Returns `SignResponse`.

### `VerifyAsync(VerifyRequest, CancellationToken?)`

Verify a hybrid signature. Returns `VerifyResponse`.

### `ListKeysAsync(CancellationToken?)`

List all managed keys. Returns `ListKeysResponse`.

### `ScanAsync(ScanRequest, CancellationToken?)`

Trigger a quantum risk scan. Returns `ScanResponse`.

## Development

```bash
dotnet build
dotnet test
```

## License

MIT
