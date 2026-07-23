# PostQ.Sdk

Official PostQ SDK for .NET. Submit quantum-risk scans and read results from the [PostQ API](https://api.postq.dev).

```bash
dotnet add package PostQ.Sdk
```

## Quickstart

```csharp
using PostQ;

using var pq = new PostQClient(new PostQClientOptions
{
    ApiKey = Environment.GetEnvironmentVariable("POSTQ_API_KEY")!,
});

// Submit a scan
var result = await pq.Scans.SubmitAsync(new ScanSubmitInput
{
    Type = "url",
    Target = "example.com",
    RiskScore = 85,
    RiskLevel = "High",
    Findings = new[]
    {
        new Finding { Severity = "high", Title = "RSA-2048 public key" },
    },
});
Console.WriteLine(result.Url); // https://app.postq.dev/scans/...

// List recent scans
var page = await pq.Scans.ListAsync(limit: 10);
foreach (var scan in page.Data)
{
    Console.WriteLine($"{scan.Target}\t{scan.RiskLevel}");
}

// Iterate every scan with automatic pagination
await foreach (var scan in pq.Scans.IterAllAsync())
{
    // ...
}

// Fetch a full scan record (HNDL, certificate, TLS, normalized findings)
ScanDetail detail = await pq.Scans.GetAsync(result.Id);
Console.WriteLine($"{detail.Hndl?.Severity} cert expires in {detail.Certificate?.DaysUntilExpiry} days");

// Download the CycloneDX 1.6 CBOM for a scan
JsonElement cbom = await pq.Scans.GetCbomAsync(result.Id);

// Or ask the API to perform and persist a real scan
var tls = await pq.Scans.RunUrlAsync(new UrlScanInput { Target = "example.com" });
var aws = await pq.Scans.RunCloudAsync(new CloudScanInput
{
    Provider = "aws",
    Target = "123456789012",
    Aws = new CloudScanAwsOptions { Regions = new[] { "us-east-1" } },
});
var gcp = await pq.Scans.RunCloudAsync(new CloudScanInput
{
    Provider = "gcp",
    Target = "projects/acme/locations/us-east1/keyRings/production",
    Gcp = new CloudScanGcpOptions { KeyRingName = "projects/acme/locations/us-east1/keyRings/production" },
});
```

## Migration control plane (0.7.0+)

```csharp
var project = await pq.Migrations.CreateAsync(new MigrationCreateInput
{
    Name = "EO 14412 migration",
    Track = "both",
    TargetDate = "2030-12-31",
    IncludeRisk = new[] { "CRITICAL", "HIGH" },
});
await pq.Migrations.UpdateAsync(project.Id, new MigrationUpdateInput { Status = "active" });
var status = await pq.Migrations.Eo14412Async();
```

## Assets and keys (0.3.0+)

```csharp
// Browse your cryptographic inventory
var assets = await pq.Assets.ListAsync(new AssetListOptions
{
    Provider = "aws",
    Risk = "HIGH",
    Limit = 50,
});
foreach (var a in assets.Data)
{
    Console.WriteLine($"{a.Name}\t{a.Algorithm}\t{a.Risk}");
}

// Or stream every asset
await foreach (var a in pq.Assets.IterAllAsync(new AssetListOptions { Environment = "production" }))
{
    // ...
}

// Browse keys discovered by cloud scans
var keys = await pq.Keys.ListAsync(new KeyListOptions { Algorithm = "RSA", Risk = "High" });
foreach (var k in keys.Data)
{
    Console.WriteLine($"{k.Provider}\t{k.Region}\t{k.ExternalId}\t{k.Algorithm}");
}
```

## Hybrid signing and multicloud Vault

```csharp
await pq.Vault.PutSettingsAsync(new VaultSettingsInput
{
    DefaultKekProvider = "gcp-kms",
    Gcp = new Dictionary<string, object?>
    {
        ["kekKeyName"] = "projects/acme/locations/global/keyRings/postq/cryptoKeys/vault-kek",
        ["keyRingName"] = "projects/acme/locations/us-east1/keyRings/postq-signing",
        ["protectionLevel"] = "HSM",
    },
});
var key = await pq.HybridKeys.CreateAsync(new HybridKeyCreateInput
{
    Name = "release-signing",
    Algorithm = "mldsa65+ecdsa-p256",
    KekProvider = "gcp-kms",
    KeyProvider = "gcp-kms",
});
var signature = await pq.SignAsync(new HybridSignInput
{
    KeyId = key.Id,
    Payload = System.Text.Encoding.UTF8.GetBytes("release manifest"),
});
```

## Configuration

| Property   | Default                  | Notes                                  |
| ---------- | ------------------------ | -------------------------------------- |
| `ApiKey`   | _required_               | `pq_live_…` from your dashboard        |
| `BaseUrl`  | `https://api.postq.dev`  | Override for staging or self-hosted    |
| `Timeout`  | `TimeSpan.FromSeconds(30)` | Per-request timeout                  |

You can also pass your own `HttpClient` (useful for `IHttpClientFactory` integration):

```csharp
var pq = new PostQClient(options, httpClient);
```

## Errors

All exceptions extend `PostQException`:

```csharp
try
{
    await pq.Scans.ListAsync();
}
catch (PostQAuthException) { /* 401 */ }
catch (PostQRateLimitException) { /* 429 */ }
catch (PostQException ex) { /* fallback — ex.Status, ex.Code */ }
```

| Type                       | When                                  |
| -------------------------- | ------------------------------------- |
| `PostQConfigException`     | Missing/invalid constructor input     |
| `PostQAuthException`       | 401                                   |
| `PostQNotFoundException`   | 404                                   |
| `PostQRateLimitException`  | 429                                   |
| `PostQServerException`     | 5xx                                   |
| `PostQNetworkException`    | DNS, connection refused, timeout      |
| `PostQException`           | Base class                            |

## Requirements

- .NET 8.0+
- Zero runtime dependencies (uses `System.Net.Http` and `System.Text.Json`).

## License

MIT — see [LICENSE](../../LICENSE).
