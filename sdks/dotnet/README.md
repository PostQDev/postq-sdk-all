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
