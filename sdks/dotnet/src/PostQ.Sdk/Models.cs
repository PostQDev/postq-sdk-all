using System.Text.Json.Serialization;

namespace PostQ;

/// <summary>Supported hybrid signature algorithms.</summary>
public static class Algorithm
{
    /// <summary>ML-DSA-65 (Dilithium 3) combined with Ed25519. NIST Level 3.</summary>
    public const string Dilithium3Ed25519 = "dilithium3+ed25519";

    /// <summary>ML-DSA-87 (Dilithium 5) combined with ECDSA P-384. NIST Level 5.</summary>
    public const string Dilithium5P384 = "dilithium5+p384";

    /// <summary>Falcon-512 combined with Ed25519. NIST Level 1.</summary>
    public const string Falcon512Ed25519 = "falcon512+ed25519";
}

/// <summary>Options for constructing a <see cref="PostQClient"/>.</summary>
public sealed class PostQClientOptions
{
    /// <summary>PostQ API key (e.g. <c>pq_live_sk_...</c>).</summary>
    public required string ApiKey { get; init; }

    /// <summary>Target environment. Defaults to <c>"production"</c>.</summary>
    public string Environment { get; init; } = "production";

    /// <summary>Override the base URL. Useful for testing against a local server.</summary>
    public string BaseUrl { get; init; } = "https://api.postq.io/v1";
}

/// <summary>Request body for POST /v1/sign.</summary>
public sealed class SignRequest
{
    /// <summary>Raw bytes to sign.</summary>
    public required byte[] Payload { get; init; }

    /// <summary>Hybrid algorithm to use (e.g. <see cref="Algorithm.Dilithium3Ed25519"/>).</summary>
    public required string AlgorithmName { get; init; }

    /// <summary>Key identifier (e.g. <c>vault://signing/production</c>).</summary>
    public required string KeyId { get; init; }

    /// <summary>Optional metadata attached to the signing context.</summary>
    public Dictionary<string, string>? Context { get; init; }
}

/// <summary>Response from POST /v1/sign.</summary>
public sealed class SignResponse
{
    /// <summary>Combined (hybrid) signature, base64-encoded.</summary>
    [JsonPropertyName("signature")]
    public required string Signature { get; init; }

    /// <summary>Classical component signature, base64-encoded.</summary>
    [JsonPropertyName("classical_sig")]
    public required string ClassicalSig { get; init; }

    /// <summary>Post-quantum component signature, base64-encoded.</summary>
    [JsonPropertyName("pq_sig")]
    public required string PqSig { get; init; }

    /// <summary>Algorithm used.</summary>
    [JsonPropertyName("algorithm")]
    public required string AlgorithmName { get; init; }

    /// <summary>Key identifier used.</summary>
    [JsonPropertyName("key_id")]
    public required string KeyId { get; init; }

    /// <summary>ISO 8601 timestamp of the signing operation.</summary>
    [JsonPropertyName("timestamp")]
    public required string Timestamp { get; init; }

    /// <summary>Whether the signing complies with the active policy.</summary>
    [JsonPropertyName("policy_compliant")]
    public required bool PolicyCompliant { get; init; }
}

/// <summary>Request body for POST /v1/verify.</summary>
public sealed class VerifyRequest
{
    /// <summary>Raw bytes that were signed.</summary>
    public required byte[] Payload { get; init; }

    /// <summary>Combined (hybrid) signature to verify, base64-encoded.</summary>
    public required string Signature { get; init; }

    /// <summary>Key identifier used when signing.</summary>
    public required string KeyId { get; init; }
}

/// <summary>Response from POST /v1/verify.</summary>
public sealed class VerifyResponse
{
    /// <summary>Overall validity (both components valid).</summary>
    [JsonPropertyName("valid")]
    public required bool Valid { get; init; }

    /// <summary>Classical component validity.</summary>
    [JsonPropertyName("classical_valid")]
    public required bool ClassicalValid { get; init; }

    /// <summary>Post-quantum component validity.</summary>
    [JsonPropertyName("pq_valid")]
    public required bool PqValid { get; init; }

    /// <summary>Algorithm detected.</summary>
    [JsonPropertyName("algorithm")]
    public required string AlgorithmName { get; init; }

    /// <summary>Key identifier used.</summary>
    [JsonPropertyName("key_id")]
    public required string KeyId { get; init; }
}

/// <summary>A single managed cryptographic key.</summary>
public sealed class Key
{
    /// <summary>Key identifier.</summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>Algorithm the key uses.</summary>
    [JsonPropertyName("algorithm")]
    public required string AlgorithmName { get; init; }

    /// <summary>ISO 8601 creation timestamp.</summary>
    [JsonPropertyName("created_at")]
    public required string CreatedAt { get; init; }

    /// <summary>Operational status (active, inactive, expired).</summary>
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    /// <summary>Storage backend.</summary>
    [JsonPropertyName("backend")]
    public required string Backend { get; init; }

    /// <summary>Whether the key uses a post-quantum algorithm.</summary>
    [JsonPropertyName("pq_ready")]
    public required bool PqReady { get; init; }
}

/// <summary>Response from GET /v1/keys.</summary>
public sealed class ListKeysResponse
{
    /// <summary>All managed keys.</summary>
    [JsonPropertyName("keys")]
    public required IReadOnlyList<Key> Keys { get; init; }
}

/// <summary>Request body for POST /v1/scan.</summary>
public sealed class ScanRequest
{
    /// <summary>Targets to scan (e.g. <c>kubernetes://production</c>).</summary>
    public required IReadOnlyList<string> Targets { get; init; }

    /// <summary>Scan depth (<c>"quick"</c> or <c>"full"</c>). Defaults to <c>"full"</c>.</summary>
    public string Depth { get; init; } = "full";

    /// <summary>Cryptographic categories to scan. Defaults to all categories.</summary>
    public IReadOnlyList<string> Include { get; init; } = ["tls", "signing", "encryption"];
}

/// <summary>Summary statistics from a completed scan.</summary>
public sealed class ScanSummary
{
    /// <summary>Total number of endpoints assessed.</summary>
    [JsonPropertyName("total_endpoints")]
    public required int TotalEndpoints { get; init; }

    /// <summary>Number of endpoints using quantum-vulnerable algorithms.</summary>
    [JsonPropertyName("quantum_vulnerable")]
    public required int QuantumVulnerable { get; init; }

    /// <summary>Aggregate risk score (0–100).</summary>
    [JsonPropertyName("risk_score")]
    public required int RiskScore { get; init; }

    /// <summary>Human-readable recommendation.</summary>
    [JsonPropertyName("recommendation")]
    public required string Recommendation { get; init; }
}

/// <summary>Response from POST /v1/scan.</summary>
public sealed class ScanResponse
{
    /// <summary>Unique identifier for the scan job.</summary>
    [JsonPropertyName("scan_id")]
    public required string ScanId { get; init; }

    /// <summary>Scan status (pending, running, completed, failed).</summary>
    [JsonPropertyName("status")]
    public required string Status { get; init; }

    /// <summary>Summary results. Present when <see cref="Status"/> is <c>"completed"</c>.</summary>
    [JsonPropertyName("summary")]
    public ScanSummary? Summary { get; init; }
}
