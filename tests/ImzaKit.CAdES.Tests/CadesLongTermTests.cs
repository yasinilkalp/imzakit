using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.CAdES;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.CAdES.Tests;

public sealed class CadesLongTermTests
{
    [Fact]
    public async Task BaselineLtAddsCertificateAndRevocationValues()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES B-LT");
        byte[] content = "cades-lt-payload"u8.ToArray();
        byte[] timestamped = await Timestamp(rsa, certificate, content);
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        byte[] crl = [0x30, 0x03, 0x02, 0x01, 0x01];

        byte[] longTerm = CadesExtender.ExtendBaselineLt(
            timestamped,
            new CadesLongTermEvidence([certificateDer], certificateRevocationLists: [crl]));

        CadesValidationReport report = CadesValidator.ValidateDetached(longTerm, content);

        Assert.Equal(CadesStatus.Passed, report.Status);
        CadesSignerReport signer = Assert.Single(report.Signers);
        Assert.Equal(CadesBaselineLevel.BLT, signer.SignatureLevel);
        Assert.Equal(CadesStatus.Passed, signer.CryptographicStatus);
    }

    [Fact]
    public void BaselineLtRejectsCmsWithoutSignatureTimestamp()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES LT reject");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        byte[] cms = Sign(rsa, certificate, "cades-lt-reject"u8.ToArray());

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            CadesExtender.ExtendBaselineLt(
                cms,
                new CadesLongTermEvidence([certificateDer])));

        Assert.Contains("B-T", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BaselineLtaAddsArchiveTimestampAfterLongTerm()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES B-LTA");
        byte[] content = "cades-lta-payload"u8.ToArray();
        byte[] timestamped = await Timestamp(rsa, certificate, content);
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        byte[] longTerm = CadesExtender.ExtendBaselineLt(
            timestamped,
            new CadesLongTermEvidence([certificateDer]));
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] archived = await CadesExtender.ExtendBaselineLta(
            longTerm,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);

        CadesValidationReport report = CadesValidator.ValidateDetached(archived, content);

        Assert.Equal(CadesStatus.Passed, report.Status);
        Assert.Equal(CadesBaselineLevel.BLTA, Assert.Single(report.Signers).SignatureLevel);
    }

    [Fact]
    public async Task BaselineLtaRejectsCmsWithoutLongTermAttributes()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES LTA reject");
        byte[] timestamped = await Timestamp(rsa, certificate, "cades-lta-reject"u8.ToArray());
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CadesExtender.ExtendBaselineLta(
                timestamped,
                new Rfc3161TimeStampClient(fetcher),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None));

        Assert.Contains("B-LT", error.Message, StringComparison.Ordinal);
    }

    private static async Task<byte[]> Timestamp(RSA rsa, X509Certificate2 certificate, byte[] content)
    {
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        return await CadesExtender.ExtendBaselineT(
            Sign(rsa, certificate, content),
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);
    }

    private static byte[] Sign(RSA rsa, X509Certificate2 certificate, byte[] content)
    {
        SignaturePreparation preparation = Prepare(certificate, content);
        return CadesDetachedSigner.SignDetached(
            preparation,
            Complete(rsa, preparation),
            certificate.Export(X509ContentType.Cert));
    }

    private static SignaturePreparation Prepare(X509Certificate2 certificate, byte[] content)
    {
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        return new CmsSignaturePreparer(new DefaultDigestCalculator()).PrepareDetached(
            Guid.NewGuid(),
            Convert.ToHexString(SHA256.HashData(content)),
            content,
            certificateDer,
            Convert.ToHexString(SHA256.HashData(certificateDer)),
            prepareVersion: 1);
    }

    private static SignatureCompletion Complete(RSA rsa, SignaturePreparation preparation)
    {
        byte[] signature = rsa.SignData(
            preparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signature);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(respond(request.Uri, request.Body), "application/timestamp-reply"));
    }
}
