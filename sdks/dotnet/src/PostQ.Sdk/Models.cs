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

/// <summary>"Harvest now, decrypt later" risk assessment for a scan target.</summary>
public sealed class HndlAssessment
{
    /// <summary>Numeric HNDL exposure score (0–100).</summary>
    [JsonPropertyName("score")] public int Score { get; init; }
    /// <summary>Severity bucket (LOW | MEDIUM | HIGH | CRITICAL).</summary>
    [JsonPropertyName("severity")] public string? Severity { get; init; }
    /// <summary>Years of overlap between data lifetime and CRQC arrival.</summary>
    [JsonPropertyName("exposureWindowYears")] public double? ExposureWindowYears { get; init; }
    /// <summary>Estimated year a cryptographically relevant quantum computer arrives.</summary>
    [JsonPropertyName("crqcBreakYear")] public int? CrqcBreakYear { get; init; }
    /// <summary>Assumed lifetime of the protected data, in years.</summary>
    [JsonPropertyName("dataLifetimeYears")] public int? DataLifetimeYears { get; init; }
    /// <summary>True if the target uses a post-quantum-safe primitive.</summary>
    [JsonPropertyName("pqSafe")] public bool? PqSafe { get; init; }
    /// <summary>Human-readable explanation of the score.</summary>
    [JsonPropertyName("rationale")] public string? Rationale { get; init; }
    /// <summary>Suggested remediation summary.</summary>
    [JsonPropertyName("recommendation")] public string? Recommendation { get; init; }
}

/// <summary>Certificate metadata captured during a URL scan.</summary>
public sealed class CertificateInfo
{
    /// <summary>Certificate subject DN.</summary>
    [JsonPropertyName("subject")] public string? Subject { get; init; }
    /// <summary>Certificate issuer DN.</summary>
    [JsonPropertyName("issuer")] public string? Issuer { get; init; }
    /// <summary>NotBefore (ISO 8601).</summary>
    [JsonPropertyName("validFrom")] public string? ValidFrom { get; init; }
    /// <summary>NotAfter (ISO 8601).</summary>
    [JsonPropertyName("validTo")] public string? ValidTo { get; init; }
    /// <summary>Certificate signature algorithm.</summary>
    [JsonPropertyName("signatureAlgorithm")] public string? SignatureAlgorithm { get; init; }
    /// <summary>Public-key algorithm.</summary>
    [JsonPropertyName("publicKeyAlgorithm")] public string? PublicKeyAlgorithm { get; init; }
    /// <summary>Public-key size in bits.</summary>
    [JsonPropertyName("keySize")] public int? KeySize { get; init; }
    /// <summary>Days remaining before the certificate expires.</summary>
    [JsonPropertyName("daysUntilExpiry")] public int? DaysUntilExpiry { get; init; }
}

/// <summary>TLS handshake details captured during a URL scan.</summary>
public sealed class TlsInfo
{
    /// <summary>Negotiated TLS version (e.g. TLS 1.3).</summary>
    [JsonPropertyName("version")] public string? Version { get; init; }
    /// <summary>Negotiated cipher suite.</summary>
    [JsonPropertyName("cipherSuite")] public string? CipherSuite { get; init; }
    /// <summary>Key-exchange group / algorithm.</summary>
    [JsonPropertyName("keyExchange")] public string? KeyExchange { get; init; }
    /// <summary>True if a post-quantum hybrid key exchange was negotiated.</summary>
    [JsonPropertyName("pqHybrid")] public bool? PqHybrid { get; init; }
}

/// <summary>A normalized finding row attached to a <see cref="ScanDetail"/>.</summary>
public sealed class ScanFindingRow
{
    /// <summary>Severity bucket (CRITICAL | HIGH | MEDIUM | LOW | INFO).</summary>
    [JsonPropertyName("severity")] public required string Severity { get; init; }
    /// <summary>Finding title.</summary>
    [JsonPropertyName("title")] public required string Title { get; init; }
    /// <summary>Long description.</summary>
    [JsonPropertyName("description")] public string? Description { get; init; }
    /// <summary>Where the finding was observed (file path, URL, etc.).</summary>
    [JsonPropertyName("location")] public string? Location { get; init; }
    /// <summary>Detected cryptographic algorithm, if applicable.</summary>
    [JsonPropertyName("algorithm")] public string? Algorithm { get; init; }
    /// <summary>Suggested remediation.</summary>
    [JsonPropertyName("remediation")] public string? Remediation { get; init; }
    /// <summary>True if the finding is exploitable / actionable.</summary>
    [JsonPropertyName("vulnerable")] public bool? Vulnerable { get; init; }
    /// <summary>Free-form metadata payload.</summary>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
}

/// <summary>Full scan record returned by <see cref="ScansResource.GetAsync"/>.</summary>
public sealed class ScanDetail
{
    /// <summary>Scan ID.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>Scan type (url | repo | kubernetes | aws-kms | ...).</summary>
    [JsonPropertyName("type")] public required string Type { get; init; }
    /// <summary>Scan target (URL, repo slug, cluster name, etc.).</summary>
    [JsonPropertyName("target")] public required string Target { get; init; }
    /// <summary>Source channel (cli | helm | dashboard | api).</summary>
    [JsonPropertyName("source")] public string? Source { get; init; }
    /// <summary>Aggregated risk score (0–100).</summary>
    [JsonPropertyName("riskScore")] public int RiskScore { get; init; }
    /// <summary>Aggregated risk level.</summary>
    [JsonPropertyName("riskLevel")] public string? RiskLevel { get; init; }
    /// <summary>Total number of findings attached to this scan.</summary>
    [JsonPropertyName("findingsCount")] public int FindingsCount { get; init; }
    /// <summary>Scan mode (e.g. quick | deep).</summary>
    [JsonPropertyName("mode")] public string? Mode { get; init; }
    /// <summary>ISO 8601 timestamp.</summary>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <summary>Direct dashboard URL for the scan.</summary>
    [JsonPropertyName("url")] public string? Url { get; init; }
    /// <summary>Agent metadata reported at submission time.</summary>
    [JsonPropertyName("agent")] public System.Text.Json.JsonElement Agent { get; init; }
    /// <summary>Normalized finding rows for this scan.</summary>
    [JsonPropertyName("findings")] public IReadOnlyList<ScanFindingRow> Findings { get; init; } = Array.Empty<ScanFindingRow>();
    /// <summary>Harvest-now-decrypt-later assessment, if computed.</summary>
    [JsonPropertyName("hndl")] public HndlAssessment? Hndl { get; init; }
    /// <summary>Certificate details for URL scans.</summary>
    [JsonPropertyName("certificate")] public CertificateInfo? Certificate { get; init; }
    /// <summary>TLS handshake details for URL scans.</summary>
    [JsonPropertyName("tls")] public TlsInfo? Tls { get; init; }
    /// <summary>Scanner-specific summary blob.</summary>
    [JsonPropertyName("summary")] public System.Text.Json.JsonElement Summary { get; init; }
    /// <summary>Free-form scan metadata.</summary>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
    /// <summary>Relative URL to the CycloneDX CBOM document for this scan.</summary>
    [JsonPropertyName("cbomUrl")] public string? CbomUrl { get; init; }
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

/* ─────────────────────────── Hybrid Signing ─────────────────────────── */

/// <summary>A managed signing key owned by your PostQ org.</summary>
public sealed class HybridKey
{
    /// <summary>Key ID.</summary>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <summary>Human-readable name supplied at creation.</summary>
    [JsonPropertyName("name")] public required string Name { get; init; }
    /// <summary>e.g. <c>mldsa65+ed25519</c>.</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <summary>ISO 8601 timestamp the key was created.</summary>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <summary>ISO 8601 timestamp the key was revoked, or null.</summary>
    [JsonPropertyName("revokedAt")] public string? RevokedAt { get; init; }
    /// <summary>ISO 8601 timestamp of last sign/verify, or null.</summary>
    [JsonPropertyName("lastUsedAt")] public string? LastUsedAt { get; init; }
    /// <summary>Free-form metadata.</summary>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
}

/// <summary>A hybrid key returned with its composite public key (JSON string).</summary>
public sealed class HybridKeyWithPublic
{
    /// <inheritdoc cref="HybridKey.Id"/>
    [JsonPropertyName("id")] public required string Id { get; init; }
    /// <inheritdoc cref="HybridKey.Name"/>
    [JsonPropertyName("name")] public required string Name { get; init; }
    /// <inheritdoc cref="HybridKey.Algorithm"/>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <inheritdoc cref="HybridKey.CreatedAt"/>
    [JsonPropertyName("createdAt")] public required string CreatedAt { get; init; }
    /// <inheritdoc cref="HybridKey.RevokedAt"/>
    [JsonPropertyName("revokedAt")] public string? RevokedAt { get; init; }
    /// <inheritdoc cref="HybridKey.LastUsedAt"/>
    [JsonPropertyName("lastUsedAt")] public string? LastUsedAt { get; init; }
    /// <summary>Composite public key as JSON: <c>{"v":1,"alg":...,"classical":...,"pq":...}</c>.</summary>
    [JsonPropertyName("publicKey")] public required string PublicKey { get; init; }
    /// <inheritdoc cref="HybridKey.Metadata"/>
    [JsonPropertyName("metadata")] public System.Text.Json.JsonElement Metadata { get; init; }
}

/// <summary>Input for <see cref="HybridKeysResource.CreateAsync"/>.</summary>
public sealed class HybridKeyCreateInput
{
    /// <summary>Required. Human-readable label.</summary>
    public required string Name { get; init; }
    /// <summary>Defaults to <c>mldsa65+ed25519</c>.</summary>
    public string Algorithm { get; init; } = "mldsa65+ed25519";
    /// <summary>Free-form metadata stored alongside the key.</summary>
    public Dictionary<string, object?>? Metadata { get; init; }
}

/// <summary>Filters for <see cref="HybridKeysResource.ListAsync"/>.</summary>
public sealed class HybridKeyListOptions
{
    /// <summary>Page size (1–100). Defaults to 20.</summary>
    public int Limit { get; init; } = 20;
    /// <summary>Cursor returned by a previous call.</summary>
    public string? Cursor { get; init; }
    /// <summary>Exact algorithm match.</summary>
    public string? Algorithm { get; init; }
    /// <summary>If true, includes revoked keys.</summary>
    public bool IncludeRevoked { get; init; }
}

/// <summary>Response from <see cref="HybridKeysResource.ListAsync"/>.</summary>
public sealed class HybridKeyListResult
{
    /// <summary>Keys on this page.</summary>
    public required IReadOnlyList<HybridKey> Data { get; init; }
    /// <summary>Pagination metadata.</summary>
    public required Pagination Pagination { get; init; }
}

/// <summary>Input for <see cref="PostQClient.SignAsync"/>.</summary>
public sealed class HybridSignInput
{
    /// <summary>The signing key to use.</summary>
    public required string KeyId { get; init; }
    /// <summary>Raw bytes to sign. The SDK base64-encodes this for the wire.</summary>
    public required byte[] Payload { get; init; }
    /// <summary>Free-form metadata stored on the audit row.</summary>
    public Dictionary<string, object?>? Metadata { get; init; }
}

/// <summary>Returned by <see cref="PostQClient.SignAsync"/>.</summary>
public sealed class HybridSignResult
{
    /// <summary>The key used for signing.</summary>
    [JsonPropertyName("keyId")] public required string KeyId { get; init; }
    /// <summary>Algorithm used.</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <summary>Base64 composite signature. Pass back to <see cref="PostQClient.VerifyAsync"/>.</summary>
    [JsonPropertyName("signature")] public required string Signature { get; init; }
    /// <summary>Composite public key JSON string.</summary>
    [JsonPropertyName("publicKey")] public required string PublicKey { get; init; }
    /// <summary>Hex-encoded SHA-256 of the signed payload.</summary>
    [JsonPropertyName("payloadSha256")] public required string PayloadSha256 { get; init; }
    /// <summary>Length of the signed payload in bytes.</summary>
    [JsonPropertyName("payloadSize")] public int PayloadSize { get; init; }
}

/// <summary>Input for <see cref="PostQClient.VerifyAsync"/>.</summary>
public sealed class HybridVerifyInput
{
    /// <summary>Original payload bytes. The SDK base64-encodes this for the wire.</summary>
    public required byte[] Payload { get; init; }
    /// <summary>Base64 composite signature returned by <see cref="HybridSignResult.Signature"/>.</summary>
    public required string Signature { get; init; }
    /// <summary>One of <see cref="KeyId"/> or <see cref="PublicKey"/> is required.</summary>
    public string? KeyId { get; init; }
    /// <summary>Composite public key JSON for offline verification.</summary>
    public string? PublicKey { get; init; }
}

/// <summary>Returned by <see cref="PostQClient.VerifyAsync"/>.</summary>
public sealed class HybridVerifyResult
{
    /// <summary>True iff BOTH the classical and PQ halves verified.</summary>
    [JsonPropertyName("ok")] public bool Ok { get; init; }
    /// <summary>Algorithm declared in the signature envelope.</summary>
    [JsonPropertyName("algorithm")] public required string Algorithm { get; init; }
    /// <summary>Whether the Ed25519 half verified.</summary>
    [JsonPropertyName("classicalOk")] public bool ClassicalOk { get; init; }
    /// <summary>Whether the ML-DSA half verified.</summary>
    [JsonPropertyName("pqOk")] public bool PqOk { get; init; }
}
