using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Api.Hosting;

public enum KestrelClientCertificateMode
{
    NoCertificate,
    AllowCertificate,
    RequireCertificate
}

public sealed record KestrelMutualTlsPolicy(
    bool HttpsOnly,
    KestrelClientCertificateMode ClientCertificateMode,
    bool AllowUntrustedDeviceCertificates)
{
    public const string AgentCallbackPath = "/v1/agent-callbacks/signature-results";

    public static KestrelMutualTlsPolicy Create() =>
        new(
            HttpsOnly: true,
            ClientCertificateMode: KestrelClientCertificateMode.AllowCertificate,
            AllowUntrustedDeviceCertificates: true);

    public static bool IsCallbackPath(string path) =>
        string.Equals(path, AgentCallbackPath, StringComparison.Ordinal);
}

public static class MutualTlsRequestMapper
{
    public static ApiHttpRequest Bind(
        string method,
        string path,
        IReadOnlyDictionary<string, string> headers,
        string body,
        X509Certificate2? clientCertificate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(headers);
        byte[]? der = clientCertificate?.Export(X509ContentType.Cert);
        return new ApiHttpRequest
        {
            Method = method,
            Path = path,
            Headers = headers,
            Body = body,
            HasMutualTlsClientCertificate = der is { Length: > 0 },
            ClientCertificateDer = der
        };
    }
}
