namespace PostQ;

/// <summary>Thrown when the PostQ API returns a non-2xx response.</summary>
public sealed class PostQException : Exception
{
    /// <summary>HTTP status code returned by the API.</summary>
    public int StatusCode { get; }

    /// <summary>Machine-readable error code from the API, if available.</summary>
    public string? Code { get; }

    /// <inheritdoc cref="PostQException"/>
    public PostQException(string message, int statusCode, string? code = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
    }
}

/// <summary>Thrown when the SDK is misconfigured (e.g. missing API key).</summary>
public sealed class PostQConfigException : Exception
{
    /// <inheritdoc cref="PostQConfigException"/>
    public PostQConfigException(string message) : base(message) { }
}
