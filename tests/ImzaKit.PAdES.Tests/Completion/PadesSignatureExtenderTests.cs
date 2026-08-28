using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Completion;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.PAdES.Tests.Completion;

public sealed class PadesSignatureExtenderTests
{
    [Fact]
    public async Task ExtendBaselineBToTAddsSignatureTimestampInPlace()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit extend B-T");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineB(rsa, certificateDer);
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] extended = await PadesSignatureExtender.ExtendAsync(
            signedPdf,
            "B-T",
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))]);

        Assert.Equal(signedPdf.Length, extended.Length);
        Assert.Equal("B-T", PadesSignatureExtender.DetectLevel(extended));
        AssertCmsStillValid(extended, preparation);
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public async Task ExtendBaselineTToLtWritesDssWithoutNewTimestamp()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit extend B-LT");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, PadesSignaturePreparation preparation) = await SignBaselineT(rsa, certificateDer, tsa);

        byte[] extended = await PadesSignatureExtender.ExtendAsync(
            signedPdf,
            "B-LT",
            material: new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));

        Assert.Equal("B-LT", PadesSignatureExtender.DetectLevel(extended));
        Assert.Contains("/Type /DSS", Encoding.ASCII.GetString(extended), StringComparison.Ordinal);
        AssertCmsStillValid(extended, preparation);
    }

    [Fact]
    public async Task ExtendBaselineBToLtaAppliesTimestampDssAndDocumentTimestamp()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit extend B-LTA");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineB(rsa, certificateDer);
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] extended = await PadesSignatureExtender.ExtendAsync(
            signedPdf,
            "B-LTA",
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));

        Assert.Equal("B-LTA", PadesSignatureExtender.DetectLevel(extended));
        AssertCmsStillValid(extended, preparation);
        Assert.Equal(2, fetcher.Calls);
    }

    [Fact]
    public async Task SameOrLowerLevelIsRejected()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit extend reject");
        (byte[] signedPdf, _) = SignBaselineB(rsa, certificate.Export(X509ContentType.Cert));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => PadesSignatureExtender.ExtendAsync(signedPdf, "B-B"));

        Assert.Contains("Unsupported PAdES level transition", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BaselineLtWithoutMaterialIsRejected()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit extend no material");
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, _) = await SignBaselineT(rsa, certificate.Export(X509ContentType.Cert), tsa);

        ArgumentException error = await Assert.ThrowsAsync<ArgumentException>(
            () => PadesSignatureExtender.ExtendAsync(signedPdf, "B-LT"));

        Assert.Contains("Validation material", error.Message, StringComparison.Ordinal);
    }

    private static (byte[] SignedPdf, PadesSignaturePreparation Preparation) SignBaselineB(
        RSA rsa,
        byte[] certificateDer)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "EXTEND-PDF",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        byte[] signedPdf = PadesSignatureCompleter.Complete(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer);
        return (signedPdf, preparation);
    }

    private static async Task<(byte[] SignedPdf, PadesSignaturePreparation Preparation)> SignBaselineT(
        RSA rsa,
        byte[] certificateDer,
        TestTsaResponder tsa)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "EXTEND-PDF",
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
        byte[] signedPdf = await PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            SignatureCompletion.Create(operationId, 1, fingerprint, signature),
            certificateDer,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);
        return (signedPdf, preparation);
    }

    private static void AssertCmsStillValid(byte[] pdf, PadesSignaturePreparation preparation)
    {
        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            pdf,
            preparation.Placeholder.ContentsOffset + 1,
            preparation.Placeholder.ContentsLength - 2));
        SignedCms signedCms = new(
            new ContentInfo(preparation.Placeholder.GetSignableBytes()),
            detached: true);
        int cmsLength = ReadDerValueLength(paddedCms);
        signedCms.Decode(paddedCms.AsSpan(0, cmsLength));
        signedCms.CheckSignature(verifySignatureOnly: true);
        Assert.True(CmsSignedDataCompleter.HasSignatureTimeStamp(paddedCms.AsSpan(0, cmsLength)));
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

    private static int ReadDerValueLength(ReadOnlySpan<byte> encoded)
    {
        int lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return 2 + lengthByte;
        }

        int lengthByteCount = lengthByte & 0x7F;
        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        return 2 + lengthByteCount + contentLength;
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public int Calls { get; private set; }

        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new ExternalResourceFetchResult(
                respond(request.Uri, request.Body),
                "application/timestamp-reply"));
        }
    }
}
