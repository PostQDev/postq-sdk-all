using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQ;

/// <summary>
/// PostQ SDK client for .NET. Submit quantum-risk scans and read results.
/// </summary>
/// <example>
/// <code>
/// using PostQ;
///
/// using var pq = new PostQClient(new PostQClientOptions { ApiKey = "pq_live_…" });
///
/// var result = await pq.Scans.SubmitAsync(new ScanSubmitInput
/// {
///     Type = "url",
///     Target = "example.com",
///     RiskScore = 85,
///     RiskLevel = "High",
/// });
/// Console.WriteLine(result.Url);
/// </code>
/// </example>
public sealed class PostQClient : IDisposable
{
    private static readonly string SdkVersion =
        typeof(PostQClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _baseUrl;
    private bool _disposed;

    /// <summary>Operations under <c>/v1/scans</c>.</summary>
    public ScansResource Scans { get; }

    /// <summary>Construct a new client.</summary>
    /// <param name="options">Required configuration. Must include an API key.</param>
    /// <param name="httpClient">
    ///   Optional <see cref="HttpClient"/>. When provided, the caller owns its
    ///   lifecycle and the client will not dispose it.
    /// </param>
    /// <exception cref="PostQConfigException">When ApiKey is missing or empty.</exception>
    public PostQClient(PostQClientOptions options, HttpClient? httpClient = null)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(options.ApiKey))
            throw new PostQConfigException("ApiKey is required.");

        _baseUrl = options.BaseUrl.TrimEnd('/');
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient();
        _http.Timeout = options.Timeout;
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", options.ApiKey.Trim());
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("postq-sdk-dotnet", SdkVersion));

        Scans = new ScansResource(this);
    }

    /// <summary>Hit <c>GET /health</c>. Throws if the API is down.</summary>
    public async Task<JsonElement> HealthAsync(CancellationToken ct = default)
    {
        return await SendAsync<JsonElement>(HttpMethod.Get, "/health", null, null, ct)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        if (_ownsHttp) _http.Dispose();
        _disposed = true;
    }

    // ── internal ────────────────────────────────────────────────────────────

    internal async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        IDictionary<string, string?>? query,
        CancellationToken ct)
    {
        var url = _baseUrl + path;
        if (query is { Count: > 0 })
        {
            var qs = string.Join(
                "&",
                query.Where(kv => kv.Value is not null)
                    .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}"));
            if (qs.Length > 0) url += "?" + qs;
        }

        using var req = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            req.Content = new StringContent(
                JsonSerializer.Serialize(body, JsonOptions),
                Encoding.UTF8,
                "application/json");
        }

        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new PostQNetworkException($"{method} {path} timed out: {ex.Message}");
        }
        catch (HttpRequestException ex)
        {
            throw new PostQNetworkException($"{method} {path}: {ex.Message}");
        }

        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!resp.IsSuccessStatusCode)
        {
            var (msg, code) = ParseError(text, (int)resp.StatusCode);
            throw resp.StatusCode switch
            {
                HttpStatusCode.Unauthorized => new PostQAuthException(msg, code),
                HttpStatusCode.NotFound => new PostQNotFoundException(msg, code),
                HttpStatusCode.TooManyRequests => new PostQRateLimitException(msg, code),
                _ when (int)resp.StatusCode >= 500 =>
                    new PostQServerException(msg, (int)resp.StatusCode, code),
                _ => new PostQException(msg, (int)resp.StatusCode, code),
            };
        }

        if (string.IsNullOrEmpty(text))
        {
            return default!;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<T>(text, JsonOptions);
            return parsed!;
        }
        catch (JsonException ex)
        {
            throw new PostQException(
                $"Could not parse response from {method} {path}: {ex.Message}",
                (int)resp.StatusCode);
        }
    }

    private static (string msg, string? code) ParseError(string text, int status)
    {
        if (string.IsNullOrEmpty(text)) return ($"HTTP {status}", null);
        try
        {
            var body = JsonSerializer.Deserialize<ErrorBody>(text, JsonOptions);
            if (body is null) return ($"HTTP {status}", null);
            return (body.Error ?? body.Message ?? $"HTTP {status}", body.Code);
        }
        catch (JsonException)
        {
            return (text.Length > 200 ? text[..200] : text, null);
        }
    }
}

/// <summary>Operations under <c>/v1/scans</c>.</summary>
public sealed class ScansResource
{
    private readonly PostQClient _client;

    internal ScansResource(PostQClient client) => _client = client;

    /// <summary><c>POST /v1/scans</c> — submit a scan from your scanner/agent.</summary>
    public async Task<ScanSubmitResult> SubmitAsync(
        ScanSubmitInput input,
        CancellationToken ct = default)
    {
        var body = new
        {
            type = input.Type,
            target = input.Target,
            source = input.Source,
            riskScore = input.RiskScore,
            riskLevel = input.RiskLevel,
            findings = input.Findings.Select(f => new
            {
                severity = f.Severity,
                title = f.Title,
                description = f.Description,
                location = f.Location,
                algorithm = f.Algorithm,
                remediation = f.Remediation,
                vulnerable = f.Vulnerable,
            }).ToArray(),
            metadata = input.Metadata ?? new Dictionary<string, string>(),
            agent = input.Agent ?? new AgentInfo(),
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<ScanSubmitResult>>(HttpMethod.Post, "/v1/scans", body, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQException("API returned no data for POST /v1/scans");
        }
        return envelope.Data;
    }

    /// <summary><c>GET /v1/scans</c> — one page of recent scans for your org.</summary>
    public async Task<ScanListResult> ListAsync(
        int limit = 20,
        string? cursor = null,
        CancellationToken ct = default)
    {
        var query = new Dictionary<string, string?>
        {
            ["limit"] = limit.ToString(),
            ["cursor"] = cursor,
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<List<ScanListItem>>>(HttpMethod.Get, "/v1/scans", null, query, ct)
            .ConfigureAwait(false);
        return new ScanListResult
        {
            Data = envelope?.Data ?? new List<ScanListItem>(),
            Pagination = envelope?.Pagination ?? new Pagination { Limit = limit },
        };
    }

    /// <summary>Async stream over every scan, walking the cursor automatically.</summary>
    public async IAsyncEnumerable<ScanListItem> IterAllAsync(
        int pageSize = 100,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        string? cursor = null;
        while (true)
        {
            var page = await ListAsync(pageSize, cursor, ct).ConfigureAwait(false);
            foreach (var item in page.Data) yield return item;
            if (string.IsNullOrEmpty(page.Pagination.NextCursor)) yield break;
            cursor = page.Pagination.NextCursor;
        }
    }
}
