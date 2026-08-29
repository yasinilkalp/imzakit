using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ImzaKit.Agent.RemoteSigning;
using ImzaKit.Core.Net;

namespace ImzaKit.Agent.Tests.RemoteSigning;

public sealed class RemoteSigningClientTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("dtbs"u8.ToArray()));
    private static readonly byte[] Signature = [0x30, 0x31, 0x02, 0x01];
    private static readonly byte[] Certificate = [0x30, 0x03, 0x02, 0x01, 0x00];
    private static readonly Uri Endpoint = new("https://csp.example/v1/sign");

    [Fact]
    public void CredentialStringDoesNotContainSecret()
    {
        RemoteSigningCredential basic = RemoteSigningCredential.Basic("csp-user", "super-secret-password");
        RemoteSigningCredential bearer = RemoteSigningCredential.Bearer("live-token-value");

        Assert.DoesNotContain("super-secret-password", basic.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("live-token-value", bearer.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("Basic ", basic.AuthorizationHeader, StringComparison.Ordinal);
        Assert.Equal("Bearer live-token-value", bearer.AuthorizationHeader);
    }

    [Fact]
    public async Task EnvironmentStoreReadsBearerFromSecretVariables()
    {
        Dictionary<string, string> variables = new(StringComparer.OrdinalIgnoreCase)
        {
            ["IMZAKIT_REMOTE_PRIMARY_BEARER"] = "vault-token"
        };
        EnvironmentRemoteSigningCredentialStore store = new(name =>
            variables.TryGetValue(name, out string? value) ? value : null);

        RemoteSigningCredential? credential = await store.GetAsync("primary", CancellationToken.None);
        RemoteSigningCredential? missing = await store.GetAsync("public", CancellationToken.None);

        Assert.Equal("Bearer vault-token", credential!.AuthorizationHeader);
        Assert.Null(missing);
    }

    [Fact]
    public async Task SignPostsDigestWithoutPrivateKeyOrPin()
    {
        RecordingFetcher fetcher = SucceedingFetcher();
        RemoteSigningClient client = new(fetcher, StoreWithBearer("vault-token"));

        RemoteSigningResult result = await client.SignAsync(
            new RemoteSigningRequest(Endpoint, "primary", Digest),
            CancellationToken.None);

        Assert.Equal(RemoteSigningStatus.Succeeded, result.Status);
        Assert.Equal(Signature, result.SignatureValue);
        Assert.Equal(Certificate, result.CertificateDer);
        Assert.NotNull(fetcher.Last);
        Assert.Equal("POST", fetcher.Last.Method, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("application/json", fetcher.Last.ContentType);
        Assert.Equal("Bearer vault-token", fetcher.Last.Headers!["Authorization"]);
        string body = Encoding.UTF8.GetString(fetcher.Last.Body);
        using JsonDocument json = JsonDocument.Parse(body);
        Assert.Equal(Digest, json.RootElement.GetProperty("dataToBeSignedSha256").GetString());
        Assert.Equal("RSA-SHA256", json.RootElement.GetProperty("algorithm").GetString());
        Assert.Equal(2, json.RootElement.EnumerateObject().Count());
        Assert.DoesNotContain("pin", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKey", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("vault-token", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingCredentialDoesNotCallFetcher()
    {
        RecordingFetcher fetcher = SucceedingFetcher();
        RemoteSigningClient client = new(fetcher, new EnvironmentRemoteSigningCredentialStore(_ => null));

        RemoteSigningResult result = await client.SignAsync(
            new RemoteSigningRequest(Endpoint, "primary", Digest),
            CancellationToken.None);

        Assert.Equal(RemoteSigningStatus.CredentialMissing, result.Status);
        Assert.Null(fetcher.Last);
        Assert.Equal(RemoteSigningProblemCodes.CredentialMissing, result.ProblemCode);
    }

    [Fact]
    public async Task TransientHttpIsUnavailable()
    {
        RecordingFetcher fetcher = new(_ => throw new InvalidOperationException("IMZAKIT.NET.TRANSIENT_HTTP"));
        RemoteSigningClient client = new(fetcher, StoreWithBearer("token"));

        RemoteSigningResult result = await client.SignAsync(
            new RemoteSigningRequest(Endpoint, "primary", Digest),
            CancellationToken.None);

        Assert.Equal(RemoteSigningStatus.Unavailable, result.Status);
        Assert.Equal(RemoteSigningProblemCodes.Unavailable, result.ProblemCode);
    }

    [Fact]
    public async Task InvalidDigestIsUnprocessableWithoutFetch()
    {
        RecordingFetcher fetcher = SucceedingFetcher();
        RemoteSigningClient client = new(fetcher, StoreWithBearer("token"));

        RemoteSigningResult result = await client.SignAsync(
            new RemoteSigningRequest(Endpoint, "primary", "not-a-digest"),
            CancellationToken.None);

        Assert.Equal(RemoteSigningStatus.Unprocessable, result.Status);
        Assert.Null(fetcher.Last);
    }

    private static RecordingFetcher SucceedingFetcher() =>
        new(_ => new ExternalResourceFetchResult(
            Encoding.UTF8.GetBytes(
                $$"""{"signatureValueBase64":"{{Convert.ToBase64String(Signature)}}","certificateDerBase64":"{{Convert.ToBase64String(Certificate)}}"}"""),
            "application/json"));

    private static EnvironmentRemoteSigningCredentialStore StoreWithBearer(string token) =>
        new(name => string.Equals(name, "IMZAKIT_REMOTE_PRIMARY_BEARER", StringComparison.OrdinalIgnoreCase)
            ? token
            : null);

    private sealed class RecordingFetcher(Func<ExternalResourceFetchRequest, ExternalResourceFetchResult> handler)
        : IExternalResourceFetcher
    {
        public ExternalResourceFetchRequest? Last { get; private set; }

        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Last = request;
            return Task.FromResult(handler(request));
        }
    }
}
