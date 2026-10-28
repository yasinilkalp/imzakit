using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using ImzaKit.Core.Net;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.Timestamp.Tests;

public sealed class Rfc3161TimeStampTokenVerifierTests
{
    private static readonly byte[] Data = "pades-signature-value"u8.ToArray();

    [Fact]
    public void TokenVerifiesOverTheDataItWasIssuedFor()
    {
        using TestTsaResponder tsa = new();

        Rfc3161TimeStampTokenVerification result = Rfc3161TimeStampTokenVerifier.Verify(IssueToken(tsa, Data), Data);

        Assert.True(result.IsValid, result.FailureCode);
        Assert.NotNull(result.GenerationTimeUtc);
    }

    [Fact]
    public void TokenOverOtherDataFailsImprintCheck()
    {
        using TestTsaResponder tsa = new();

        Rfc3161TimeStampTokenVerification result = Rfc3161TimeStampTokenVerifier.Verify(
            IssueToken(tsa, Data), "other-signature-value"u8);

        Assert.False(result.IsValid);
        Assert.Equal("IMZAKIT.TS.IMPRINT_MISMATCH", result.FailureCode);
    }

    [Fact]
    public void TokenWithTamperedTsaSignatureIsRejected()
    {
        using TestTsaResponder tsa = new();
        byte[] token = IssueToken(tsa, Data);
        token[^1] ^= 0x01;

        Rfc3161TimeStampTokenVerification result = Rfc3161TimeStampTokenVerifier.Verify(token, Data);

        Assert.False(result.IsValid);
        Assert.Equal("IMZAKIT.TS.INVALID_TOKEN", result.FailureCode);
    }

    [Fact]
    public void MalformedTokenIsRejected()
    {
        Rfc3161TimeStampTokenVerification result = Rfc3161TimeStampTokenVerifier.Verify([0x30, 0x03, 0x02, 0x01, 0x00], Data);

        Assert.False(result.IsValid);
        Assert.Equal("IMZAKIT.TS.TOKEN_MALFORMED", result.FailureCode);
    }

    [Fact]
    public async Task ClientRejectsGrantedResponseWhoseTokenSignatureWasTampered()
    {
        using TestTsaResponder tsa = new();
        TamperingFetcher fetcher = new(body =>
        {
            byte[] response = tsa.Grant(body);
            response[^1] ^= 0x01;
            return response;
        });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new Rfc3161TimeStampClient(fetcher).RequestAsync(
                SHA256.HashData(Data),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None));

        Assert.Equal("IMZAKIT.TS.INVALID_TOKEN", error.Message);
    }

    private static byte[] IssueToken(TestTsaResponder tsa, byte[] data)
    {
        TimeStampRequestGenerator generator = new();
        generator.SetCertReq(true);
        TimeStampRequest request = generator.Generate(TspAlgorithms.Sha256, SHA256.HashData(data), BigInteger.One);
        return new TimeStampResponse(tsa.Grant(request.GetEncoded())).TimeStampToken.GetEncoded();
    }

    private sealed class TamperingFetcher(Func<byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(respond(request.Body), "application/timestamp-reply"));
    }
}
