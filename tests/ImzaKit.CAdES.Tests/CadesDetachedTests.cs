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

public sealed class CadesDetachedTests
{
    [Fact]
    public void DetachedBaselineBRoundTripPassesEachSigner()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES B-B");
        byte[] content = "cades-detached-payload"u8.ToArray();
        byte[] cms = Sign(rsa, certificate, content);

        CadesValidationReport report = CadesValidator.ValidateDetached(cms, content);

        Assert.Equal(CadesStatus.Passed, report.Status);
        CadesSignerReport signer = Assert.Single(report.Signers);
        Assert.Equal(CadesStatus.Passed, signer.CryptographicStatus);
        Assert.Equal(CadesBaselineLevel.BB, signer.SignatureLevel);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(certificate.Export(X509ContentType.Cert))),
            signer.SignerCertificateSha256);
    }

    [Fact]
    public void TamperedContentFailsEverySigner()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES Tamper");
        byte[] content = "cades-detached-payload"u8.ToArray();
        byte[] cms = Sign(rsa, certificate, content);

        CadesValidationReport report = CadesValidator.ValidateDetached(cms, "other-payload"u8.ToArray());

        Assert.Equal(CadesStatus.Failed, report.Status);
        Assert.Equal(CadesStatus.Failed, Assert.Single(report.Signers).CryptographicStatus);
    }

    [Fact]
    public void MultipleSignerInfosAreValidatedSeparately()
    {
        using RSA firstKey = RSA.Create(2048);
        using RSA secondKey = RSA.Create(2048);
        using X509Certificate2 first = CreateCertificate(firstKey, "CN=ImzaKit CAdES First");
        using X509Certificate2 second = CreateCertificate(secondKey, "CN=ImzaKit CAdES Second");
        byte[] content = "cades-cosign-payload"u8.ToArray();
        byte[] firstCms = Sign(firstKey, first, content);
        SignaturePreparation secondPreparation = Prepare(second, content);
        byte[] both = CadesDetachedSigner.AddSigner(
            firstCms,
            secondPreparation,
            Complete(secondKey, secondPreparation),
            second.Export(X509ContentType.Cert));
        SignaturePreparation brokenPreparation = Prepare(second, content);
        byte[] secondBroken = CadesDetachedSigner.AddSigner(
            firstCms,
            brokenPreparation,
            SignatureCompletion.Create(
                brokenPreparation.OperationId,
                brokenPreparation.PrepareVersion,
                brokenPreparation.CertificateFingerprintSha256,
                new byte[256]),
            second.Export(X509ContentType.Cert));

        CadesValidationReport valid = CadesValidator.ValidateDetached(both, content);
        CadesValidationReport mixed = CadesValidator.ValidateDetached(secondBroken, content);

        Assert.Equal(2, valid.Signers.Count);
        Assert.Equal(CadesStatus.Passed, valid.Status);
        Assert.All(valid.Signers, signer => Assert.Equal(CadesStatus.Passed, signer.CryptographicStatus));
        Assert.Equal(CadesStatus.Failed, mixed.Status);
        Assert.Contains(mixed.Signers, signer => signer.CryptographicStatus == CadesStatus.Passed);
        Assert.Contains(mixed.Signers, signer => signer.CryptographicStatus == CadesStatus.Failed);
        Assert.NotEqual(valid.Signers[0].SignerCertificateSha256, valid.Signers[1].SignerCertificateSha256);
    }

    [Fact]
    public async Task BaselineTAddsSignatureTimestampUnsignedAttribute()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit CAdES B-T");
        using TestTsaResponder tsa = new();
        byte[] content = "cades-timestamp-payload"u8.ToArray();
        byte[] signed = Sign(rsa, certificate, content);
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        byte[] timestamped = await CadesExtender.ExtendBaselineT(
            signed,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);

        CadesValidationReport report = CadesValidator.ValidateDetached(timestamped, content);

        Assert.Equal(CadesStatus.Passed, report.Status);
        Assert.Equal(CadesBaselineLevel.BT, Assert.Single(report.Signers).SignatureLevel);
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
