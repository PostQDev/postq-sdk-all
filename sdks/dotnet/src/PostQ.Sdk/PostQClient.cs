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

    /// <summary>Operations under <c>/v1/assets</c>.</summary>
    public AssetsResource Assets { get; }

    /// <summary>Operations under <c>/v1/keys</c>.</summary>
    public KeysResource Keys { get; }

    /// <summary>Operations under <c>/v1/hybrid-keys</c>, <c>/v1/sign</c>, and <c>/v1/verify</c>.</summary>
    public HybridKeysResource HybridKeys { get; }

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
        Assets = new AssetsResource(this);
        Keys = new KeysResource(this);
        HybridKeys = new HybridKeysResource(this);
    }

    /// <summary>Hit <c>GET /health</c>. Throws if the API is down.</summary>
    public async Task<JsonElement> HealthAsync(CancellationToken ct = default)
    {
        return await SendAsync<JsonElement>(HttpMethod.Get, "/health", null, null, ct)
            .ConfigureAwait(false);
    }

    /// <summary><c>POST /v1/sign</c> — convenience wrapper around <see cref="HybridKeysResource.SignAsync"/>.</summary>
    public Task<HybridSignResult> SignAsync(HybridSignInput input, CancellationToken ct = default)
        => HybridKeys.SignAsync(input, ct);

    /// <summary><c>POST /v1/verify</c> — convenience wrapper around <see cref="HybridKeysResource.VerifyAsync"/>.</summary>
    public Task<HybridVerifyResult> VerifyAsync(HybridVerifyInput input, CancellationToken ct = default)
        => HybridKeys.VerifyAsync(input, ct);

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

    /// <summary><c>GET /v1/scans/{id}</c> — full scan record including HNDL, certificate, TLS, and findings.</summary>
    public async Task<ScanDetail> GetAsync(string scanId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(scanId)) throw new ArgumentException("scanId is required", nameof(scanId));
        var envelope = await _client
            .SendAsync<ApiEnvelope<ScanDetail>>(HttpMethod.Get, $"/v1/scans/{Uri.EscapeDataString(scanId)}", null, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQException($"API returned no data for GET /v1/scans/{scanId}");
        }
        return envelope.Data;
    }

    /// <summary><c>GET /v1/scans/{id}/cbom</c> — CycloneDX 1.6 CBOM document for the scan.</summary>
    public Task<System.Text.Json.JsonElement> GetCbomAsync(string scanId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(scanId)) throw new ArgumentException("scanId is required", nameof(scanId));
        return _client.SendAsync<System.Text.Json.JsonElement>(
            HttpMethod.Get, $"/v1/scans/{Uri.EscapeDataString(scanId)}/cbom", null, null, ct);
    }
}

/// <summary>Operations under <c>/v1/assets</c>.</summary>
public sealed class AssetsResource
{
    private readonly PostQClient _client;

    internal AssetsResource(PostQClient client) => _client = client;

    /// <summary><c>GET /v1/assets</c> — one page of discovered assets.</summary>
    public async Task<AssetListResult> ListAsync(
        AssetListOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new AssetListOptions();
        var query = new Dictionary<string, string?>
        {
            ["limit"] = opts.Limit.ToString(),
            ["cursor"] = opts.Cursor,
            ["provider"] = opts.Provider,
            ["type"] = opts.Type,
            ["risk"] = opts.Risk,
            ["environment"] = opts.Environment,
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<List<Asset>>>(HttpMethod.Get, "/v1/assets", null, query, ct)
            .ConfigureAwait(false);
        return new AssetListResult
        {
            Data = envelope?.Data ?? new List<Asset>(),
            Pagination = envelope?.Pagination ?? new Pagination { Limit = opts.Limit },
        };
    }

    /// <summary>Async stream over every asset, walking the cursor automatically.</summary>
    public async IAsyncEnumerable<Asset> IterAllAsync(
        AssetListOptions? options = null,
        int pageSize = 100,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        string? cursor = null;
        while (true)
        {
            var pageOpts = new AssetListOptions
            {
                Limit = pageSize,
                Cursor = cursor,
                Provider = options?.Provider,
                Type = options?.Type,
                Risk = options?.Risk,
                Environment = options?.Environment,
            };
            var page = await ListAsync(pageOpts, ct).ConfigureAwait(false);
            foreach (var item in page.Data) yield return item;
            if (string.IsNullOrEmpty(page.Pagination.NextCursor)) yield break;
            cursor = page.Pagination.NextCursor;
        }
    }
}

/// <summary>Operations under <c>/v1/keys</c>.</summary>
public sealed class KeysResource
{
    private readonly PostQClient _client;

    internal KeysResource(PostQClient client) => _client = client;

    /// <summary><c>GET /v1/keys</c> — one page of discovered cryptographic keys.</summary>
    public async Task<KeyListResult> ListAsync(
        KeyListOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new KeyListOptions();
        var query = new Dictionary<string, string?>
        {
            ["limit"] = opts.Limit.ToString(),
            ["cursor"] = opts.Cursor,
            ["provider"] = opts.Provider,
            ["algorithm"] = opts.Algorithm,
            ["risk"] = opts.Risk,
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<List<Key>>>(HttpMethod.Get, "/v1/keys", null, query, ct)
            .ConfigureAwait(false);
        return new KeyListResult
        {
            Data = envelope?.Data ?? new List<Key>(),
            Pagination = envelope?.Pagination ?? new Pagination { Limit = opts.Limit },
        };
    }

    /// <summary>Async stream over every key, walking the cursor automatically.</summary>
    public async IAsyncEnumerable<Key> IterAllAsync(
        KeyListOptions? options = null,
        int pageSize = 100,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        string? cursor = null;
        while (true)
        {
            var pageOpts = new KeyListOptions
            {
                Limit = pageSize,
                Cursor = cursor,
                Provider = options?.Provider,
                Algorithm = options?.Algorithm,
                Risk = options?.Risk,
            };
            var page = await ListAsync(pageOpts, ct).ConfigureAwait(false);
            foreach (var item in page.Data) yield return item;
            if (string.IsNullOrEmpty(page.Pagination.NextCursor)) yield break;
            cursor = page.Pagination.NextCursor;
        }
    }
}

/// <summary>
/// Operations under <c>/v1/hybrid-keys</c>, <c>/v1/sign</c>, and <c>/v1/verify</c>.
///
/// A <em>hybrid key</em> is a PostQ-managed signing key whose public component
/// is a composite of an Ed25519 public key and an ML-DSA public key. Every
/// signature produced by <see cref="SignAsync"/> only validates when BOTH
/// halves verify, so a future break in either Ed25519 OR ML-DSA does not
/// allow forgery on its own.
/// </summary>
public sealed class HybridKeysResource
{
    private readonly PostQClient _client;

    internal HybridKeysResource(PostQClient client) => _client = client;

    /// <summary><c>POST /v1/hybrid-keys</c> — create a new managed signing key.</summary>
    public async Task<HybridKeyWithPublic> CreateAsync(
        HybridKeyCreateInput input,
        CancellationToken ct = default)
    {
        var body = new
        {
            name = input.Name,
            algorithm = input.Algorithm,
            metadata = input.Metadata ?? new Dictionary<string, object?>(),
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<HybridKeyWithPublic>>(
                HttpMethod.Post, "/v1/hybrid-keys", body, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQException("API returned no data for POST /v1/hybrid-keys");
        }
        return envelope.Data;
    }

    /// <summary><c>GET /v1/hybrid-keys</c> — one page of managed signing keys.</summary>
    public async Task<HybridKeyListResult> ListAsync(
        HybridKeyListOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new HybridKeyListOptions();
        var query = new Dictionary<string, string?>
        {
            ["limit"] = opts.Limit.ToString(),
            ["cursor"] = opts.Cursor,
            ["algorithm"] = opts.Algorithm,
            ["includeRevoked"] = opts.IncludeRevoked ? "true" : null,
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<List<HybridKey>>>(
                HttpMethod.Get, "/v1/hybrid-keys", null, query, ct)
            .ConfigureAwait(false);
        return new HybridKeyListResult
        {
            Data = envelope?.Data ?? new List<HybridKey>(),
            Pagination = envelope?.Pagination ?? new Pagination { Limit = opts.Limit },
        };
    }

    /// <summary><c>GET /v1/hybrid-keys/:id</c> — fetch a single key including its public bytes.</summary>
    public async Task<HybridKeyWithPublic> GetAsync(string keyId, CancellationToken ct = default)
    {
        var envelope = await _client
            .SendAsync<ApiEnvelope<HybridKeyWithPublic>>(
                HttpMethod.Get, $"/v1/hybrid-keys/{Uri.EscapeDataString(keyId)}", null, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQNotFoundException("Key not found", null);
        }
        return envelope.Data;
    }

    /// <summary><c>DELETE /v1/hybrid-keys/:id</c> — revoke a key (existing signatures still verify).</summary>
    public async Task RevokeAsync(string keyId, CancellationToken ct = default)
    {
        await _client
            .SendAsync<ApiEnvelope<JsonElement>>(
                HttpMethod.Delete, $"/v1/hybrid-keys/{Uri.EscapeDataString(keyId)}", null, null, ct)
            .ConfigureAwait(false);
    }

    /// <summary><c>POST /v1/sign</c> — sign <paramref name="input"/>.Payload with the named hybrid key.</summary>
    public async Task<HybridSignResult> SignAsync(
        HybridSignInput input,
        CancellationToken ct = default)
    {
        var body = new
        {
            keyId = input.KeyId,
            payload = Convert.ToBase64String(input.Payload),
            metadata = input.Metadata ?? new Dictionary<string, object?>(),
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<HybridSignResult>>(
                HttpMethod.Post, "/v1/sign", body, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQException("API returned no data for POST /v1/sign");
        }
        return envelope.Data;
    }

    /// <summary><c>POST /v1/verify</c> — verify a composite signature.</summary>
    public async Task<HybridVerifyResult> VerifyAsync(
        HybridVerifyInput input,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(input.KeyId) && string.IsNullOrEmpty(input.PublicKey))
        {
            throw new PostQConfigException("VerifyAsync requires either KeyId or PublicKey.");
        }
        var body = new
        {
            keyId = input.KeyId,
            publicKey = input.PublicKey,
            payload = Convert.ToBase64String(input.Payload),
            signature = input.Signature,
        };
        var envelope = await _client
            .SendAsync<ApiEnvelope<HybridVerifyResult>>(
                HttpMethod.Post, "/v1/verify", body, null, ct)
            .ConfigureAwait(false);
        if (envelope?.Data is null)
        {
            throw new PostQException("API returned no data for POST /v1/verify");
        }
        return envelope.Data;
    }
}
