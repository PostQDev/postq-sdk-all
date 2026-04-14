using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PostQ;

/// <summary>
/// PostQ SDK client for .NET.
/// </summary>
/// <example>
/// <code>
/// using PostQ;
///
/// var pq = new PostQClient(new PostQClientOptions { ApiKey = "pq_live_sk_..." });
///
/// var signature = await pq.SignAsync(new SignRequest
/// {
///     Payload = Encoding.UTF8.GetBytes("Hello Quantum World"),
///     AlgorithmName = Algorithm.Dilithium3Ed25519,
///     KeyId = "vault://signing/production",
/// });
///
/// var result = await pq.VerifyAsync(new VerifyRequest
/// {
///     Payload = Encoding.UTF8.GetBytes("Hello Quantum World"),
///     Signature = signature.Signature,
///     KeyId = "vault://signing/production",
/// });
/// Console.WriteLine(result.Valid); // true
/// </code>
/// </example>
public sealed class PostQClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _environment;
    private readonly string _baseUrl;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Response models use explicit [JsonPropertyName] attributes; no policy needed for reading.
        PropertyNameCaseInsensitive = false,
    };

    /// <summary>
    /// Initialise the PostQ client with the provided options.
    /// </summary>
    /// <param name="options">Configuration options.</param>
    /// <param name="httpClient">
    ///   Optional <see cref="HttpClient"/> to use (allows injecting test fakes).
    ///   When <see langword="null"/> the client creates its own instance.
    /// </param>
    /// <exception cref="PostQConfigException">
    ///   Thrown when <see cref="PostQClientOptions.ApiKey"/> is null or blank.
    /// </exception>
    public PostQClient(PostQClientOptions options, HttpClient? httpClient = null)
    {
        if (string.IsNullOrWhiteSpace(options.ApiKey))
            throw new PostQConfigException(
                "ApiKey is required. Provide it via PostQClientOptions.");

        _environment = options.Environment;
        _baseUrl = options.BaseUrl.TrimEnd('/');
        _http = httpClient ?? new HttpClient();
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", options.ApiKey);
        _http.DefaultRequestHeaders.Add("X-PostQ-Environment", _environment);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>Create a hybrid signature combining a classical and a post-quantum algorithm.</summary>
    /// <param name="request">Signing parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The composite signature plus metadata.</returns>
    /// <exception cref="PostQException">Thrown when the API returns a non-2xx response.</exception>
    public async Task<SignResponse> SignAsync(
        SignRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = new
        {
            payload = Convert.ToBase64String(request.Payload),
            algorithm = request.AlgorithmName,
            key_id = request.KeyId,
            context = request.Context,
        };
        return await PostAsync<SignResponse>("/sign", body, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Verify a hybrid signature.</summary>
    /// <param name="request">Verification parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validity information for both signature components.</returns>
    /// <exception cref="PostQException">Thrown when the API returns a non-2xx response.</exception>
    public async Task<VerifyResponse> VerifyAsync(
        VerifyRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = new
        {
            payload = Convert.ToBase64String(request.Payload),
            signature = request.Signature,
            key_id = request.KeyId,
        };
        return await PostAsync<VerifyResponse>("/verify", body, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>List all cryptographic keys managed by PostQ.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of keys with algorithm and PQ-readiness metadata.</returns>
    /// <exception cref="PostQException">Thrown when the API returns a non-2xx response.</exception>
    public async Task<ListKeysResponse> ListKeysAsync(
        CancellationToken cancellationToken = default)
    {
        return await GetAsync<ListKeysResponse>("/keys", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Trigger a quantum risk scan across specified infrastructure targets.</summary>
    /// <param name="request">Scan parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Scan job identifier and results summary.</returns>
    /// <exception cref="PostQException">Thrown when the API returns a non-2xx response.</exception>
    public async Task<ScanResponse> ScanAsync(
        ScanRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = new
        {
            targets = request.Targets,
            depth = request.Depth,
            include = request.Include,
        };
        return await PostAsync<ScanResponse>("/scan", body, cancellationToken).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // IDisposable
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _http.Dispose();
        _disposed = true;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private async Task<T> GetAsync<T>(string path, CancellationToken ct)
    {
        HttpResponseMessage response;
        try
        {
            response = await _http.GetAsync($"{_baseUrl}{path}", ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new PostQException($"Network error while calling GET {path}: {ex.Message}", 0);
        }
        return await ParseResponseAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    private async Task<T> PostAsync<T>(string path, object body, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOptions);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsync($"{_baseUrl}{path}", content, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new PostQException($"Network error while calling POST {path}: {ex.Message}", 0);
        }
        return await ParseResponseAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    private static async Task<T> ParseResponseAsync<T>(
        HttpResponseMessage response,
        string path,
        CancellationToken ct)
    {
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(text);
        }
        catch (JsonException)
        {
            throw new PostQException(
                $"Unexpected non-JSON response: {text}",
                (int)response.StatusCode);
        }

        if (!response.IsSuccessStatusCode)
        {
            var root = doc.RootElement;
            string message = root.TryGetProperty("message", out var msgProp)
                ? msgProp.GetString() ?? $"Request failed with status {(int)response.StatusCode}"
                : $"Request failed with status {(int)response.StatusCode}";
            string? code = root.TryGetProperty("code", out var codeProp)
                ? codeProp.GetString()
                : null;
            throw new PostQException(message, (int)response.StatusCode, code);
        }

        return JsonSerializer.Deserialize<T>(text, JsonOptions)
            ?? throw new PostQException($"Empty response from {path}", (int)response.StatusCode);
    }
}
