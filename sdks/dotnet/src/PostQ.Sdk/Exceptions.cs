namespace PostQ;

/// <summary>Base exception for all PostQ SDK failures.</summary>
public class PostQException : Exception
{
    /// <summary>HTTP status code (0 for network errors, null for config errors).</summary>
    public int? Status { get; }

    /// <summary>API error code, if the server returned one.</summary>
    public string? Code { get; }

    /// <inheritdoc cref="PostQException"/>
    public PostQException(string message, int? status = null, string? code = null)
        : base(message)
    {
        Status = status;
        Code = code;
    }
}

/// <summary>Bad or missing configuration (e.g. no API key).</summary>
public sealed class PostQConfigException : PostQException
{
    /// <inheritdoc cref="PostQConfigException"/>
    public PostQConfigException(string message) : base(message) { }
}

/// <summary>401 — bad, missing, revoked, or expired API key.</summary>
public sealed class PostQAuthException : PostQException
{
    /// <inheritdoc cref="PostQAuthException"/>
    public PostQAuthException(string message, string? code = null)
        : base(message, 401, code) { }
}

/// <summary>404 — resource not found.</summary>
public sealed class PostQNotFoundException : PostQException
{
    /// <inheritdoc cref="PostQNotFoundException"/>
    public PostQNotFoundException(string message, string? code = null)
        : base(message, 404, code) { }
}

/// <summary>429 — rate limit exceeded.</summary>
public sealed class PostQRateLimitException : PostQException
{
    /// <inheritdoc cref="PostQRateLimitException"/>
    public PostQRateLimitException(string message, string? code = null)
        : base(message, 429, code) { }
}

/// <summary>5xx — server error.</summary>
public sealed class PostQServerException : PostQException
{
    /// <inheritdoc cref="PostQServerException"/>
    public PostQServerException(string message, int status, string? code = null)
        : base(message, status, code) { }
}

/// <summary>Connection refused, DNS failure, or timeout.</summary>
public sealed class PostQNetworkException : PostQException
{
    /// <inheritdoc cref="PostQNetworkException"/>
    public PostQNetworkException(string message) : base(message, 0) { }
}
