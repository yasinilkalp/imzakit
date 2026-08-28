namespace ImzaKit.Core.Net;

public sealed record ExternalResourceFetchRequest(
    Uri Uri,
    string Method,
    byte[] Body,
    string? ContentType,
    IReadOnlyList<string> AllowedResponseContentTypes,
    int MaxResponseBytes,
    TimeSpan Timeout,
    int MaxRedirects,
    IReadOnlyDictionary<string, string>? Headers = null);

public sealed record ExternalResourceFetchResult(byte[] Body, string ContentType);

public interface IExternalResourceFetcher
{
    Task<ExternalResourceFetchResult> FetchAsync(
        ExternalResourceFetchRequest request,
        CancellationToken cancellationToken);
}
