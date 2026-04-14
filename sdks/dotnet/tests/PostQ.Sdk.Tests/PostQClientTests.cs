using System.Net;
using System.Text;
using System.Text.Json;
using RichardSzalay.MockHttp;

namespace PostQ.Tests;

public sealed class PostQClientTests
{
    // -------------------------------------------------------------------------
    // Fixture data
    // -------------------------------------------------------------------------

    private static readonly string SignResponseJson = JsonSerializer.Serialize(new
    {
        signature = "base64-combined-signature",
        classical_sig = "base64-ed25519-signature",
        pq_sig = "base64-dilithium3-signature",
        algorithm = "dilithium3+ed25519",
        key_id = "vault://signing/production",
        timestamp = "2026-04-05T12:00:00Z",
        policy_compliant = true,
    });

    private static readonly string VerifyResponseJson = JsonSerializer.Serialize(new
    {
        valid = true,
        classical_valid = true,
        pq_valid = true,
        algorithm = "dilithium3+ed25519",
        key_id = "vault://signing/production",
    });

    private static readonly string ListKeysResponseJson = JsonSerializer.Serialize(new
    {
        keys = new[]
        {
            new
            {
                id = "vault://signing/production",
                algorithm = "dilithium3+ed25519",
                created_at = "2026-01-15T08:00:00Z",
                status = "active",
                backend = "azure-key-vault",
                pq_ready = true,
            },
            new
            {
                id = "vault://signing/staging",
                algorithm = "ed25519",
                created_at = "2025-06-01T10:00:00Z",
                status = "active",
                backend = "hashicorp-vault",
                pq_ready = false,
            },
        },
    });

    private static readonly string ScanResponseJson = JsonSerializer.Serialize(new
    {
        scan_id = "scan_abc123",
        status = "completed",
        summary = new
        {
            total_endpoints = 4184,
            quantum_vulnerable = 3012,
            risk_score = 72,
            recommendation = "Begin hybrid migration for signing keys",
        },
    });

    private const string BaseUrl = "https://api.example.com/v1";

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static (PostQClient client, MockHttpMessageHandler mock) BuildClient(
        string method,
        string path,
        string responseBody,
        HttpStatusCode status = HttpStatusCode.OK)
    {
        var mockHttp = new MockHttpMessageHandler();
        mockHttp
            .When(HttpMethod.Parse(method), $"{BaseUrl}{path}")
            .Respond(status, "application/json", responseBody);

        var httpClient = mockHttp.ToHttpClient();
        var client = new PostQClient(
            new PostQClientOptions { ApiKey = "pq_live_sk_test", BaseUrl = BaseUrl },
            httpClient);
        return (client, mockHttp);
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    [Fact]
    public void Constructor_ThrowsPostQConfigException_WhenApiKeyIsEmpty()
    {
        Assert.Throws<PostQConfigException>(() =>
            new PostQClient(new PostQClientOptions { ApiKey = "" }));
    }

    [Fact]
    public void Constructor_ThrowsPostQConfigException_WhenApiKeyIsWhitespace()
    {
        Assert.Throws<PostQConfigException>(() =>
            new PostQClient(new PostQClientOptions { ApiKey = "   " }));
    }

    [Fact]
    public void Constructor_DoesNotThrow_WhenApiKeyIsValid()
    {
        using var _ = new PostQClient(new PostQClientOptions { ApiKey = "pq_live_sk_test" });
    }

    // -------------------------------------------------------------------------
    // SignAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task SignAsync_ReturnsSignResponse_OnSuccess()
    {
        var (client, mock) = BuildClient("POST", "/sign", SignResponseJson);
        using (client)
        {
            var result = await client.SignAsync(new SignRequest
            {
                Payload = Encoding.UTF8.GetBytes("Hello Quantum World"),
                AlgorithmName = Algorithm.Dilithium3Ed25519,
                KeyId = "vault://signing/production",
            });

            Assert.Equal("base64-combined-signature", result.Signature);
            Assert.Equal("dilithium3+ed25519", result.AlgorithmName);
            Assert.True(result.PolicyCompliant);
        }
        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task SignAsync_SerializesPayloadAsBase64()
    {
        string? capturedBody = null;
        var mockHttp = new MockHttpMessageHandler();
        mockHttp
            .When(HttpMethod.Post, $"{BaseUrl}/sign")
            .Respond(async req =>
            {
                capturedBody = await req.Content!.ReadAsStringAsync();
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(SignResponseJson, Encoding.UTF8, "application/json"),
                };
            });

        using var client = new PostQClient(
            new PostQClientOptions { ApiKey = "pq_live_sk_test", BaseUrl = BaseUrl },
            mockHttp.ToHttpClient());

        await client.SignAsync(new SignRequest
        {
            Payload = Encoding.UTF8.GetBytes("Hello Quantum World"),
            AlgorithmName = Algorithm.Dilithium3Ed25519,
            KeyId = "vault://signing/production",
        });

        Assert.NotNull(capturedBody);
        using var doc = JsonDocument.Parse(capturedBody!);
        var payload = doc.RootElement.GetProperty("payload").GetString();
        Assert.Equal("Hello Quantum World", Encoding.UTF8.GetString(Convert.FromBase64String(payload!)));
    }

    [Fact]
    public async Task SignAsync_ThrowsPostQException_On401()
    {
        var (client, _) = BuildClient("POST", "/sign",
            """{"code":"UNAUTHORIZED","message":"Invalid API key"}""",
            HttpStatusCode.Unauthorized);
        using (client)
        {
            var ex = await Assert.ThrowsAsync<PostQException>(() =>
                client.SignAsync(new SignRequest
                {
                    Payload = [0x01],
                    AlgorithmName = Algorithm.Dilithium3Ed25519,
                    KeyId = "k1",
                }));

            Assert.Equal(401, ex.StatusCode);
            Assert.Equal("UNAUTHORIZED", ex.Code);
        }
    }

    // -------------------------------------------------------------------------
    // VerifyAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task VerifyAsync_ReturnsVerifyResponse_OnSuccess()
    {
        var (client, mock) = BuildClient("POST", "/verify", VerifyResponseJson);
        using (client)
        {
            var result = await client.VerifyAsync(new VerifyRequest
            {
                Payload = Encoding.UTF8.GetBytes("Hello Quantum World"),
                Signature = "base64-combined-signature",
                KeyId = "vault://signing/production",
            });

            Assert.True(result.Valid);
            Assert.True(result.ClassicalValid);
            Assert.True(result.PqValid);
            Assert.Equal("dilithium3+ed25519", result.AlgorithmName);
        }
        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task VerifyAsync_ThrowsPostQException_On422()
    {
        var (client, _) = BuildClient("POST", "/verify",
            """{"code":"INVALID_SIGNATURE","message":"Signature mismatch"}""",
            HttpStatusCode.UnprocessableEntity);
        using (client)
        {
            var ex = await Assert.ThrowsAsync<PostQException>(() =>
                client.VerifyAsync(new VerifyRequest
                {
                    Payload = [0x01],
                    Signature = "bad-sig",
                    KeyId = "k1",
                }));

            Assert.Equal(422, ex.StatusCode);
        }
    }

    // -------------------------------------------------------------------------
    // ListKeysAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ListKeysAsync_ReturnsKeys_OnSuccess()
    {
        var (client, mock) = BuildClient("GET", "/keys", ListKeysResponseJson);
        using (client)
        {
            var result = await client.ListKeysAsync();

            Assert.Equal(2, result.Keys.Count);
            Assert.True(result.Keys[0].PqReady);
            Assert.False(result.Keys[1].PqReady);
            Assert.Equal("vault://signing/production", result.Keys[0].Id);
        }
        mock.VerifyNoOutstandingExpectation();
    }

    // -------------------------------------------------------------------------
    // ScanAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ScanAsync_ReturnsScanResponse_OnSuccess()
    {
        var (client, mock) = BuildClient("POST", "/scan", ScanResponseJson);
        using (client)
        {
            var result = await client.ScanAsync(new ScanRequest
            {
                Targets = ["kubernetes://production", "azure://subscription-id"],
                Depth = "full",
                Include = ["tls", "signing", "encryption"],
            });

            Assert.Equal("scan_abc123", result.ScanId);
            Assert.Equal("completed", result.Status);
            Assert.NotNull(result.Summary);
            Assert.Equal(72, result.Summary.RiskScore);
            Assert.Equal(4184, result.Summary.TotalEndpoints);
        }
        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task ScanAsync_UsesDefaultDepthAndInclude()
    {
        string? capturedBody = null;
        var mockHttp = new MockHttpMessageHandler();
        mockHttp
            .When(HttpMethod.Post, $"{BaseUrl}/scan")
            .Respond(async req =>
            {
                capturedBody = await req.Content!.ReadAsStringAsync();
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(ScanResponseJson, Encoding.UTF8, "application/json"),
                };
            });

        using var client = new PostQClient(
            new PostQClientOptions { ApiKey = "pq_live_sk_test", BaseUrl = BaseUrl },
            mockHttp.ToHttpClient());

        await client.ScanAsync(new ScanRequest { Targets = ["kubernetes://production"] });

        Assert.NotNull(capturedBody);
        using var doc = JsonDocument.Parse(capturedBody!);
        Assert.Equal("full", doc.RootElement.GetProperty("depth").GetString());
        var include = doc.RootElement.GetProperty("include")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Contains("tls", include);
        Assert.Contains("signing", include);
        Assert.Contains("encryption", include);
    }
}
