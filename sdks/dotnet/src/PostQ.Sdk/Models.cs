using System.Text.Json.Serialization;

namespace PostQ;

/// <summary>Configuration options for <see cref="PostQClient"/>.</summary>
public sealed class PostQClientOptions
{
    /// <summary>PostQ API key (e.g. <c>pq_live_…</c>). Required.</summary>
    public required string ApiKey { get; init; }

    /// <summary>Base URL of the PostQ API. Defaults to <c>https://api.postq.dev</c>.</summary>
    public string BaseUrl { get; init; } = "https://api.postq.dev";

    /// <summary>Request timeout. Defaults to 30 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>A single quantum-vulnerability finding attached to a scan submission.</summary>
public sealed class Finding
{
    /// <summary>Severity: critical | high | medium | low | info.</summary>
    public required string Severity { get; init; }
    /// <summary>Short title.</summary>
    public required string Title { get; init; }
    /// <summary>Long-form description.</summary>
    public string Description { get; init; } = "";
    /// <summary>Optional location (e.g. URL, file path).</summary>
    public string Location { get; init; } = "";
    /// <summary>Algorithm name (e.g. <c>RSA-2048</c>).</summary>
    public string? Algorithm { get; init; }
    /// <summary>Suggested fix.</summary>
    public string Remediation { get; init; } = "";
    /// <summary>Whether this finding represents a vulnerability. Defaults to <see langword="true"/>.</summary>
    public bool Vulnerable { get; init; } = true;
}

/// <summary>Optional metadata about the agent/tool that produced the scan.</summary>
public sealed class AgentInfo
{
    /// <summary>Agent name.</summary>
    public string? Name { get; init; }
    /// <summary>Agent version.</summary>
    public string? Version { get; init; }
    /// <summary>Hostname.</summary>
    public string? Hostname { get; init; }
    /// <summary>Operating system.</summary>
    public string? Os { get; init; }
}

/// <summary>Input for <see cref="ScansResource.SubmitAsync"/>.</summary>
public sealed class ScanSubmitInput
{
    /// <summary>Scan type: url | github | aws | azure | kubernetes | bulk.</summary>
    public required string Type { get; init; }
    /// <summary>The thing that was scanned (hostname, repo, etc.).</summary>
    public required string Target { get; init; }
    /// <summary>Aggregate risk score 0–100.</summary>
    public required int RiskScore { get; init; }
    /// <summary>Risk level: Critical | High | Medium | Low | Safe.</summary>
    public required string RiskLevel { get; init; }
    /// <summary>List of findings discovered during the scan.</summary>
    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();
    /// <summary>Where the scan was submitted from. Defaults to <c>"sdk"</c>.</summary>
    public string Source { get; init; } = "sdk";
    /// <summary>Arbitrary string metadata.</summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
    /// <summary>Optional agent info.</summary>
    public AgentInfo? Agent { get; init; }
}

/// <summary>Returned by <see cref="ScansResource.SubmitAsync"/>.</summary>
public sealed class ScanSubmitResult
{
    /// <summary>Scan ID assigned by the API.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>ISO 8601 timestamp.</summary>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <summary>Direct URL to the scan in the PostQ dashboard.</summary>
    [JsonPropertyName("url")] public required string Url { get; init; }
}

/// <summary>A single row returned by <see cref="ScansResource.ListAsync"/>.</summary>
public sealed class ScanListItem
{
    /// <summary>Scan ID.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>Scan type.</summary>
    [JsonPropertyName("type")] public required string Type { get; init; }
    /// <summary>Target.</summary>
    [JsonPropertyName("target")] public required string Target { get; init; }
    /// <summary>Source (cli, helm, etc.).</summary>
    [JsonPropertyName("source")] public required string Source { get; init; }
    /// <summary>Risk score.</summary>
    [JsonPropertyName("riskScore")] public required int RiskScore { get; init; }
    /// <summary>Risk level.</summary>
    [JsonPropertyName("riskLevel")] public required string RiskLevel { get; init; }
    /// <summary>Number of findings.</summary>
    [JsonPropertyName("findingsCount")] public required int FindingsCount { get; init; }
    /// <summary>ISO 8601 timestamp.</summary>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <summary>Dashboard URL.</summary>
    [JsonPropertyName("url")] public required string Url { get; init; }
}

/// <summary>Pagination metadata for <see cref="ScanListResult"/>.</summary>
public sealed class Pagination
{
    /// <summary>Page size used.</summary>
    [JsonPropertyName("limit")] public int Limit { get; init; }
    /// <summary>Cursor for the next page, or <see langword="null"/> if no more results.</summary>
    [JsonPropertyName("nextCursor")] public string? NextCursor { get; init; }
}

/// <summary>Response from <see cref="ScansResource.ListAsync"/>.</summary>
public sealed class ScanListResult
{
    /// <summary>Scans on this page.</summary>
    public required IReadOnlyList<ScanListItem> Data { get; init; }
    /// <summary>Pagination metadata.</summary>
    public required Pagination Pagination { get; init; }
}

// ── internal envelope shapes (not exported) ──────────────────────────────────

internal sealed class ApiEnvelope<T>
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("data")] public T? Data { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("code")] public string? Code { get; init; }
    [JsonPropertyName("pagination")] public Pagination? Pagination { get; init; }
}

internal sealed class ErrorBody
{
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("message")] public string? Message { get; init; }
    [JsonPropertyName("code")] public string? Code { get; init; }
}

/* ────────────────────────────── Assets ────────────────────────────── */

/// <summary>A discovered cryptographic asset returned by <see cref="AssetsResource.ListAsync"/>.</summary>
public sealed class Asset
{
    /// <summary>Asset ID.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>Provider this asset lives in.</summary>
    [JsonPropertyName("provider")] public string? Provider { get; init; }
    /// <summary>Provider-native ID (ARN, resource id, hostname).</summary>
    [JsonPropertyName("externalId")] public string? ExternalId { get; init; }
    /// <summary>Friendly display name.</summary>
    [JsonPropertyName("name")] public required string Name { get; init; }
    /// <summary>One of ENDPOINT | CERTIFICATE | KEY | DATA_STORE.</summary>
    [JsonPropertyName("type")] public required string Type { get; init; }
    /// <summary>Algorithm name (e.g. RSA-2048).</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <summary>One of CRITICAL | HIGH | MEDIUM | LOW | NONE.</summary>
    [JsonPropertyName("risk")] public required string Risk { get; init; }
    /// <summary>Environment / namespace label.</summary>
    [JsonPropertyName("environment")] public required string Environment { get; init; }
    /// <summary>Cloud region or cluster name.</summary>
    [JsonPropertyName("region")] public string? Region { get; init; }
    /// <summary>ISO 8601 timestamp of the last scan that touched this asset.</summary>
    [JsonPropertyName("lastScanned")] public string? LastScanned { get; init; }
    /// <summary>True when the asset uses a quantum-resistant primitive.</summary>
    [JsonPropertyName("pqReady")] public bool PqReady { get; init; }
    /// <summary>ID of the scan that last updated this asset.</summary>
    [JsonPropertyName("scanId")] public string? ScanId { get; init; }
    /// <summary>Free-form provider-specific metadata.</summary>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
    /// <summary>ISO 8601 timestamp.</summary>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <summary>ISO 8601 timestamp.</summary>
    [JsonPropertyName("updatedAt")] public required string UpdatedAt { get; init; }
}

/// <summary>Filters for <see cref="AssetsResource.ListAsync"/>.</summary>
public sealed class AssetListOptions
{
    /// <summary>Page size (1–100). Defaults to 20.</summary>
    public int Limit { get; init; } = 20;
    /// <summary>Cursor returned by a previous call.</summary>
    public string? Cursor { get; init; }
    /// <summary>aws | azure | gcp | kubernetes | github | url | other.</summary>
    public string? Provider { get; init; }
    /// <summary>ENDPOINT | CERTIFICATE | KEY | DATA_STORE.</summary>
    public string? Type { get; init; }
    /// <summary>CRITICAL | HIGH | MEDIUM | LOW | NONE.</summary>
    public string? Risk { get; init; }
    /// <summary>Environment or namespace.</summary>
    public string? Environment { get; init; }
}

/// <summary>Response from <see cref="AssetsResource.ListAsync"/>.</summary>
public sealed class AssetListResult
{
    /// <summary>Assets on this page.</summary>
    public required IReadOnlyList<Asset> Data { get; init; }
    /// <summary>Pagination metadata.</summary>
    public required Pagination Pagination { get; init; }
}

/* ──────────────────────────────── Keys ─────────────────────────────── */

/// <summary>A discovered managed cryptographic key returned by <see cref="KeysResource.ListAsync"/>.</summary>
public sealed class Key
{
    /// <summary>Key ID.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>aws | azure | gcp | kubernetes | vault | other.</summary>
    [JsonPropertyName("provider")] public required string Provider { get; init; }
    /// <summary>Provider-native ID (e.g. KMS KeyId / ARN).</summary>
    [JsonPropertyName("externalId")] public required string ExternalId { get; init; }
    /// <summary>Cloud region.</summary>
    [JsonPropertyName("region")] public string? Region { get; init; }
    /// <summary>Algorithm spec (e.g. RSA_2048, ECC_NIST_P256).</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <summary>Key size in bits, when known.</summary>
    [JsonPropertyName("keySize")] public int? KeySize { get; init; }
    /// <summary>Intended usage (ENCRYPT_DECRYPT, SIGN_VERIFY, …).</summary>
    [JsonPropertyName("keyUsage")] public string? KeyUsage { get; init; }
    /// <summary>True when this key is considered quantum-safe.</summary>
    [JsonPropertyName("pqSafe")] public bool PqSafe { get; init; }
    /// <summary>Critical | High | Medium | Low | Safe.</summary>
    [JsonPropertyName("risk")] public required string Risk { get; init; }
    /// <summary>ID of the scan that last updated this key.</summary>
    [JsonPropertyName("scanId")] public string? ScanId { get; init; }
    /// <summary>Free-form provider-specific metadata.</summary>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
    /// <summary>ISO 8601 timestamp the key was first observed.</summary>
    [JsonPropertyName("firstSeen")] public required string FirstSeen { get; init; }
    /// <summary>ISO 8601 timestamp the key was last observed.</summary>
    [JsonPropertyName("lastSeen")] public required string LastSeen { get; init; }
}

/// <summary>Filters for <see cref="KeysResource.ListAsync"/>.</summary>
public sealed class KeyListOptions
{
    /// <summary>Page size (1–100). Defaults to 20.</summary>
    public int Limit { get; init; } = 20;
    /// <summary>Cursor returned by a previous call.</summary>
    public string? Cursor { get; init; }
    /// <summary>aws | azure | gcp | kubernetes | vault | other.</summary>
    public string? Provider { get; init; }
    /// <summary>Exact algorithm string match.</summary>
    public string? Algorithm { get; init; }
    /// <summary>Critical | High | Medium | Low | Safe.</summary>
    public string? Risk { get; init; }
}

/// <summary>Response from <see cref="KeysResource.ListAsync"/>.</summary>
public sealed class KeyListResult
{
    /// <summary>Keys on this page.</summary>
    public required IReadOnlyList<Key> Data { get; init; }
    /// <summary>Pagination metadata.</summary>
    public required Pagination Pagination { get; init; }
}
