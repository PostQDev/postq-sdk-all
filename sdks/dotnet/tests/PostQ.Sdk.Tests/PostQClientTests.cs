using System.Net;
using System.Text.Json;
using PostQ;
using RichardSzalay.MockHttp;

namespace PostQ.Sdk.Tests;

public class PostQClientTests
{
    private const string Base = "https://api.example.com";

    private static (PostQClient client, MockHttpMessageHandler mock) Build(string apiKey = "pq_live_test")
    {
        var mock = new MockHttpMessageHandler();
        var http = new HttpClient(mock);
        var client = new PostQClient(
            new PostQClientOptions { ApiKey = apiKey, BaseUrl = Base },
            http);
        return (client, mock);
    }

    // ── constructor ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_Throws_When_ApiKey_Missing()
    {
        Assert.Throws<PostQConfigException>(() =>
            new PostQClient(new PostQClientOptions { ApiKey = "" }));
    }

    [Fact]
    public void Constructor_Throws_When_ApiKey_Whitespace()
    {
        Assert.Throws<PostQConfigException>(() =>
            new PostQClient(new PostQClientOptions { ApiKey = "   " }));
    }

    // ── submit ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Submit_Posts_And_Returns_Result()
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Post, $"{Base}/v1/scans")
            .Respond(HttpStatusCode.Created, "application/json",
                """{"success":true,"data":{"id":"abc-123","createdAt":"2026-04-23T12:00:00Z","url":"https://app.postq.dev/scans/abc-123"}}""");

        var result = await client.Scans.SubmitAsync(new ScanSubmitInput
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

        Assert.Equal("abc-123", result.Id);
        Assert.EndsWith("/scans/abc-123", result.Url);
    }

    [Fact]
    public async Task Submit_Sends_Authorization_Header()
    {
        var (client, mock) = Build("pq_live_xyz");
        mock.Expect(HttpMethod.Post, $"{Base}/v1/scans")
            .WithHeaders("Authorization", "Bearer pq_live_xyz")
            .Respond(HttpStatusCode.Created, "application/json",
                """{"success":true,"data":{"id":"x","createdAt":"x","url":"x"}}""");

        await client.Scans.SubmitAsync(new ScanSubmitInput
        {
            Type = "url", Target = "a.com", RiskScore = 0, RiskLevel = "Safe",
        });

        mock.VerifyNoOutstandingExpectation();
    }

    // ── list ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_Returns_Items_And_Pagination()
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Get, $"{Base}/v1/scans*")
            .Respond("application/json",
                """{"success":true,"data":[{"id":"s1","type":"url","target":"a.com","source":"cli","riskScore":50,"riskLevel":"Medium","findingsCount":2,"createdAt":"2026-04-22T00:00:00Z","url":"https://app.postq.dev/scans/s1"}],"pagination":{"limit":20,"nextCursor":null}}""");

        var page = await client.Scans.ListAsync(limit: 20);

        Assert.Single(page.Data);
        Assert.Equal("s1", page.Data[0].Id);
        Assert.Equal("Medium", page.Data[0].RiskLevel);
        Assert.Null(page.Pagination.NextCursor);
    }

    [Fact]
    public async Task IterAll_Walks_Cursor()
    {
        var (client, mock) = Build();

        mock.Expect(HttpMethod.Get, $"{Base}/v1/scans?limit=1")
            .Respond("application/json",
                """{"success":true,"data":[{"id":"s1","type":"url","target":"a.com","source":"cli","riskScore":10,"riskLevel":"Low","findingsCount":1,"createdAt":"2026-04-22T01:00:00Z","url":"https://app.postq.dev/scans/s1"}],"pagination":{"limit":1,"nextCursor":"2026-04-22T01:00:00Z"}}""");

        mock.Expect(HttpMethod.Get, $"{Base}/v1/scans?limit=1&cursor=2026-04-22T01%3A00%3A00Z")
            .Respond("application/json",
                """{"success":true,"data":[{"id":"s2","type":"url","target":"b.com","source":"cli","riskScore":0,"riskLevel":"Safe","findingsCount":0,"createdAt":"2026-04-22T00:00:00Z","url":"https://app.postq.dev/scans/s2"}],"pagination":{"limit":1,"nextCursor":null}}""");

        var ids = new List<string>();
        await foreach (var item in client.Scans.IterAllAsync(pageSize: 1))
        {
            ids.Add(item.Id);
        }

        Assert.Equal(new[] { "s1", "s2" }, ids);
        mock.VerifyNoOutstandingExpectation();
    }

    // ── error mapping ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, typeof(PostQAuthException))]
    [InlineData(HttpStatusCode.NotFound, typeof(PostQNotFoundException))]
    [InlineData(HttpStatusCode.TooManyRequests, typeof(PostQRateLimitException))]
    [InlineData(HttpStatusCode.InternalServerError, typeof(PostQServerException))]
    [InlineData(HttpStatusCode.ServiceUnavailable, typeof(PostQServerException))]
    [InlineData(HttpStatusCode.BadRequest, typeof(PostQException))]
    public async Task Status_Maps_To_Exception(HttpStatusCode status, Type exceptionType)
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Get, $"{Base}/v1/scans*")
            .Respond(status, "application/json",
                $$"""{"success":false,"error":"failed {{(int)status}}"}""");

        var ex = await Assert.ThrowsAnyAsync<PostQException>(() => client.Scans.ListAsync());
        Assert.IsType(exceptionType, ex);
        Assert.Equal((int)status, ex.Status);
    }

    // ── health ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Health_Returns_Json()
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Get, $"{Base}/health")
            .Respond("application/json", """{"status":"ok"}""");

        var result = await client.HealthAsync();
        Assert.Equal("ok", result.GetProperty("status").GetString());
    }

    [Fact]
    public async Task RunCloud_Posts_And_Parses_Result()
    {
        var (client, mock) = Build();
        mock.Expect(HttpMethod.Post, $"{Base}/v1/scans/cloud")
            .WithPartialContent("\"provider\":\"aws\"")
            .Respond(HttpStatusCode.Created, "application/json",
                """{"success":true,"data":{"id":"cloud-1","createdAt":"2026-07-16T00:00:00Z","provider":"aws","target":"123456789012","mode":"live","riskScore":80,"riskLevel":"Critical","findingsCount":4,"resourcesCount":10,"summary":{"totalEndpoints":10,"quantumVulnerable":4,"hybridEnabled":0,"pqReady":6},"url":"https://app.postq.dev/scans/cloud-1"}}""");

        var result = await client.Scans.RunCloudAsync(new CloudScanInput
        {
            Provider = "aws",
            Target = "123456789012",
            Aws = new CloudScanAwsOptions { Regions = new[] { "us-east-1" } },
        });

        Assert.Equal("aws", result.Provider);
        Assert.Equal(4, result.Summary.QuantumVulnerable);
        mock.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task Policies_Parse_Enforcement_Model()
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Get, $"{Base}/v1/policies")
            .Respond("application/json",
                """{"success":true,"data":[{"id":"policy-1","name":"production hybrid","description":"Require hybrid","action":"enforce","enabled":true,"environments":["production"],"rule":{"matchOperation":"sign","algorithmIn":null,"algorithmNotIn":null,"requireHybrid":true,"minPqLevel":3},"createdAt":"2026-07-16T00:00:00Z","updatedAt":"2026-07-16T00:00:00Z"}]}""");

        var policies = await client.Policies.ListAsync();
        Assert.Equal("enforce", policies[0].Action);
        Assert.True(policies[0].Rule.RequireHybrid);
        Assert.Equal(3, policies[0].Rule.MinPqLevel);
    }

    [Fact]
    public async Task Ledger_Parses_Hash_Chain_And_Seal()
    {
        var (client, mock) = Build();
        mock.When(HttpMethod.Get, $"{Base}/v1/ledger/entries*")
            .Respond("application/json",
                """{"success":true,"data":[{"id":"entry-1","seq":0,"prevHashHex":"00","entryHashHex":"11","payload":{"name":"release"},"eventType":"custom.event","subjectId":null,"actorId":null,"createdAt":"2026-07-16T00:00:00Z"}],"pagination":{"limit":100,"nextCursor":null}}""");
        mock.When(HttpMethod.Post, $"{Base}/v1/ledger/seal")
            .Respond("application/json",
                """{"success":true,"data":{"treeSize":1,"merkleRootHex":"aa","signatureBase64":"c2ln","signingKeyId":"key-1","createdAt":"2026-07-16T00:00:00Z","fresh":true}}""");

        var entries = await client.Ledger.EntriesAsync();
        Assert.Equal("11", entries.Data[0].EntryHashHex);
        var seal = await client.Ledger.SealAsync();
        Assert.True(seal.Fresh);
        Assert.Equal(1, seal.TreeSize);
    }

    [Fact]
    public async Task Vault_Put_Uses_DefaultProvider_And_Save_Result()
    {
        var (client, mock) = Build();
        mock.Expect(HttpMethod.Put, $"{Base}/v1/vault/settings")
            .WithPartialContent("\"defaultKekProvider\":\"gcp-kms\"")
            .Respond("application/json",
                """{"success":true,"data":{"savedAt":"2026-07-16T00:00:00Z"}}""");

        var result = await client.Vault.PutSettingsAsync(new VaultSettingsInput
        {
            DefaultKekProvider = "gcp-kms",
            Gcp = new Dictionary<string, object?>
            {
                ["kekKeyName"] = "projects/acme/locations/global/keyRings/postq/cryptoKeys/kek",
            },
        });

        Assert.Equal("2026-07-16T00:00:00Z", result.SavedAt);
        mock.VerifyNoOutstandingExpectation();
    }
}
