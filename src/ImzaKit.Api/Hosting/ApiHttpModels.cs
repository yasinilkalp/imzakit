namespace ImzaKit.Api.Hosting;

public sealed class ApiHttpRequest
{
    public required string Method { get; init; }
    public required string Path { get; init; }
    public IReadOnlyDictionary<string, string> Headers { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public string Body { get; init; } = "";
    public bool HasMutualTlsClientCertificate { get; init; }
    public byte[]? ClientCertificateDer { get; init; }
}

public sealed class ApiHttpResponse
{
    public required int StatusCode { get; init; }
    public required string Body { get; init; }
    public string ContentType { get; init; } = "application/json";
    public string CorrelationId { get; init; } = "";
}

public sealed record ApiCallerIdentity(bool Authenticated, string TenantId, string ApplicationId);

public interface IApiCallerResolver
{
    ApiCallerIdentity Resolve(ApiHttpRequest request);
}

public sealed class StaticApiCallerResolver(ApiCallerIdentity identity) : IApiCallerResolver
{
    public ApiCallerIdentity Resolve(ApiHttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return identity;
    }
}
