using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class PadesSignatureLevelTests
{
    [Fact]
    public void BaselineBIsReportedAsBB()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify B-B");
        byte[] pdf = SignBaselineB(rsa, certificate.Export(X509ContentType.Cert));

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(PadesBaselineLevel.BB, report.SignatureLevel);
    }

    [Fact]
    public async Task BaselineTIsReportedAsBT()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify B-T");
        using TestTsaResponder tsa = new();
        byte[] pdf = await SignBaselineT(rsa, certificate.Export(X509ContentType.Cert), tsa);

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(PadesBaselineLevel.BT, report.SignatureLevel);
    }

    [Fact]
    public async Task BaselineLtPassesByteRangeAndIsReportedAsBLT()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify B-LT");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        byte[] signed = await SignBaselineT(rsa, certificateDer, tsa);
        byte[] pdf = PadesSignatureCompleter.EmbedBaselineLt(
            signed,
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(PadesBaselineLevel.BLT, report.SignatureLevel);
        Assert.Contains("/Type /DSS", Encoding.ASCII.GetString(pdf), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BaselineLtaVerifiesCadesAndIsReportedAsBLTA()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify B-LTA");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        byte[] signed = await SignBaselineT(rsa, certificateDer, tsa);
        byte[] longTerm = PadesSignatureCompleter.EmbedBaselineLt(
            signed,
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        byte[] pdf = await PadesSignatureCompleter.CompleteBaselineLta(
            longTerm,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("archive", new Uri("https://tsa.example/rfc3161"))],
            tokenCapacity: 8192,
            CancellationToken.None);

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(PadesBaselineLevel.BLTA, report.SignatureLevel);
        Assert.Contains("/Type /DocTimeStamp", Encoding.ASCII.GetString(pdf), StringComparison.Ordinal);
    }

    [Fact]
    public void DssWithoutSignatureTimestampRemainsBB()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Verify DSS only");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        byte[] signed = SignBaselineB(rsa, certificateDer);
        byte[] pdf = PadesSignatureCompleter.EmbedBaselineLt(
            signed,
            new PadesValidationMaterial([certificateDer]));

        PadesValidationReport report = PadesValidator.Validate(pdf);

        Assert.Equal(ValidationStatus.Passed, report.ByteRangeStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(PadesBaselineLevel.BB, report.SignatureLevel);
        Assert.Contains("/Type /DSS", Encoding.ASCII.GetString(pdf), StringComparison.Ordinal);
    }

    private static byte[] SignBaselineB(RSA rsa, byte[] certificateDer)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "VERIFY-LEVEL",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return PadesSignatureCompleter.Complete(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer);
    }

    private static async Task<byte[]> SignBaselineT(RSA rsa, byte[] certificateDer, TestTsaResponder tsa)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "VERIFY-LEVEL",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        return await PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static byte[] CreateOnePagePdf()
    {
        StringBuilder builder = new("%PDF-1.4\n");
        int catalogOffset = builder.Length;
        builder.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        int pagesOffset = builder.Length;
        builder.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        int pageOffset = builder.Length;
        builder.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        int xrefOffset = builder.Length;
        builder.Append("xref\n0 4\n0000000000 65535 f \n")
            .Append(catalogOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pagesOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pageOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
            .Append(xrefOffset.ToString(CultureInfo.InvariantCulture)).Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(
                respond(request.Uri, request.Body),
                "application/timestamp-reply"));
    }
}
