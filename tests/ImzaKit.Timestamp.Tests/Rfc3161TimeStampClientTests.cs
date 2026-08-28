using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using ImzaKit.Core.Net;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.Timestamp.Tests;

public sealed class Rfc3161TimeStampClientTests
{
    [Fact]
    public async Task RequestAcceptsGrantedTokenWithTimeStampingEku()
    {
        using TestTsaResponder tsa = new();
        byte[] imprint = SHA256.HashData("pades-signature-value"u8);
        ScriptedFetcher fetcher = new((uri, body) => tsa.Grant(body));
        Rfc3161TimeStampResult result = await new Rfc3161TimeStampClient(fetcher)
            .RequestAsync(imprint, [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))], CancellationToken.None);

        Assert.NotEmpty(result.TokenDer);
        Assert.Equal(32, result.Nonce.Length);
    }

    [Fact]
    public async Task RequestFailsOverTransientHttpToSecondAuthority()
    {
        using TestTsaResponder tsa = new();
        byte[] imprint = SHA256.HashData("pades-signature-value"u8);
        int calls = 0;
        ScriptedFetcher fetcher = new((uri, body) =>
        {
            calls++;
            if (uri.Host == "tsa-1.example")
            {
                throw new InvalidOperationException("IMZAKIT.NET.TRANSIENT_HTTP");
            }

            return tsa.Grant(body);
        });

        Rfc3161TimeStampResult result = await new Rfc3161TimeStampClient(fetcher).RequestAsync(
            imprint,
            [
                new TimeStampAuthority("primary", new Uri("https://tsa-1.example/rfc3161")),
                new TimeStampAuthority("backup", new Uri("https://tsa-2.example/rfc3161"))
            ],
            CancellationToken.None);

        Assert.Equal(2, calls);
        Assert.NotEmpty(result.TokenDer);
    }

    [Fact]
    public async Task RequestDoesNotFailOverPermanentHttpError()
    {
        ScriptedFetcher fetcher = new((_, _) => throw new InvalidOperationException("IMZAKIT.NET.HTTP_ERROR"));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new Rfc3161TimeStampClient(fetcher).RequestAsync(
                SHA256.HashData("pades-signature-value"u8),
                [
                    new TimeStampAuthority("primary", new Uri("https://tsa-1.example/rfc3161")),
                    new TimeStampAuthority("backup", new Uri("https://tsa-2.example/rfc3161"))
                ],
                CancellationToken.None));

        Assert.Equal("IMZAKIT.TS.REJECTED", error.Message);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task RequestRejectsPkiFailureWithoutToken()
    {
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Reject(body));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new Rfc3161TimeStampClient(fetcher).RequestAsync(
                SHA256.HashData("pades-signature-value"u8),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None));

        Assert.Equal("IMZAKIT.TS.REJECTED", error.Message);
    }

    [Fact]
    public async Task RequestRejectsTokenThatDoesNotMatchRequestNonce()
    {
        using TestTsaResponder tsa = new();
        TimeStampRequestGenerator generator = new();
        generator.SetCertReq(true);
        TimeStampRequest foreign = generator.Generate(
            TspAlgorithms.Sha256,
            SHA256.HashData("other-imprint"u8),
            BigInteger.Two);
        ScriptedFetcher fetcher = new((_, _) => tsa.Grant(foreign.GetEncoded()));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new Rfc3161TimeStampClient(fetcher).RequestAsync(
                SHA256.HashData("pades-signature-value"u8),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None));

        Assert.Equal("IMZAKIT.TS.INVALID_TOKEN", error.Message);
    }

    [Fact]
    public async Task RequestAttachesAuthorizationFromCredentialStoreNotAuthority()
    {
        using TestTsaResponder tsa = new();
        TsaCredential credential = TsaCredential.Basic("tsa-user", "tsa-secret");
        ScriptedFetcher fetcher = new((_, _) => tsa.Grant(SHA256.HashData("ignored"u8)));
        fetcher.Respond = (request, body) =>
        {
            Assert.Equal("Basic " + Convert.ToBase64String("tsa-user:tsa-secret"u8), request.Headers!["Authorization"]);
            Assert.DoesNotContain("tsa-secret", request.Uri.ToString(), StringComparison.Ordinal);
            return tsa.Grant(body);
        };

        Rfc3161TimeStampResult result = await new Rfc3161TimeStampClient(fetcher, new StaticStore(credential))
            .RequestAsync(
                SHA256.HashData("pades-signature-value"u8),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None);

        Assert.NotEmpty(result.TokenDer);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task RequestOmitsAuthorizationWhenStoreHasNoCredential()
    {
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, _) => tsa.Grant(SHA256.HashData("ignored"u8)));
        fetcher.Respond = (request, body) =>
        {
            Assert.True(request.Headers is null || request.Headers.Count == 0);
            return tsa.Grant(body);
        };

        await new Rfc3161TimeStampClient(fetcher, new StaticStore(null)).RequestAsync(
            SHA256.HashData("pades-signature-value"u8),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);

        Assert.Equal(1, fetcher.Calls);
    }

    private sealed class ScriptedFetcher : IExternalResourceFetcher
    {
        public ScriptedFetcher(Func<Uri, byte[], byte[]> respond)
        {
            Respond = (request, body) => respond(request.Uri, body);
        }

        public Func<ExternalResourceFetchRequest, byte[], byte[]> Respond { get; set; }

        public int Calls { get; private set; }

        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            byte[] body = Respond(request, request.Body);
            return Task.FromResult(new ExternalResourceFetchResult(body, "application/timestamp-reply"));
        }
    }

    private sealed class StaticStore(TsaCredential? credential) : ITsaCredentialStore
    {
        public ValueTask<TsaCredential?> GetAsync(string authorityName, CancellationToken cancellationToken) =>
            ValueTask.FromResult(credential);
    }
}
