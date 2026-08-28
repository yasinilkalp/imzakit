using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Storage;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.DependencyInjection;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Revocation.Online;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class PadesDocumentExtensionWorkflowTests
{
    [Fact]
    public void ExtendStoresBaselineTResultForMatchingDigest()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa);
        byte[] signedPdf = SignBaselineB(rsa, certificate.Export(X509ContentType.Cert));
        EncryptedDocumentStore store = new(new MemoryBlobStore(), RandomNumberGenerator.GetBytes(32));
        DocumentObject stored = store.Put("tenant-1", signedPdf, "application/pdf");
        using TestTsaResponder tsa = new();
        PadesDocumentExtensionWorkflow workflow = new(
            store,
            new Rfc3161TimeStampClient(new ScriptedFetcher((_, body) => tsa.Grant(body))),
            new OnlineRevocationClient(
                new ScriptedFetcher((_, _) => []),
                new MemoryRevocationEvidenceCache(),
                new BouncyCastleRevocationEvidenceParser()));

        SignatureExtensionOutcome outcome = workflow.Extend(new SignatureExtensionRequest(
            "tenant-1",
            stored.ObjectKey,
            stored.Sha256,
            stored.Size,
            "B-T",
            "TurkiyeNes",
            [new SignatureExtensionAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            [],
            [],
            []));

        Assert.Equal(SignatureExtensionStatus.Succeeded, outcome.Status);
        Assert.Equal("B-B", outcome.Result!.FromLevel);
        Assert.Equal("B-T", outcome.Result.ToLevel);
        Assert.True(store.TryGet("tenant-1", outcome.Result.ResultObjectKey, out byte[] extended));
        Assert.Equal("B-T", PadesSignatureExtender.DetectLevel(extended));
        Assert.NotEqual(stored.ObjectKey, outcome.Result.ResultObjectKey);
    }

    [Fact]
    public void DigestMismatchIsReportedWithoutWriting()
    {
        EncryptedDocumentStore store = new(new MemoryBlobStore(), RandomNumberGenerator.GetBytes(32));
        DocumentObject stored = store.Put("tenant-1", "%PDF-1.4"u8.ToArray(), "application/pdf");
        PadesDocumentExtensionWorkflow workflow = new(
            store,
            new Rfc3161TimeStampClient(new ScriptedFetcher((_, _) => [])),
            new OnlineRevocationClient(
                new ScriptedFetcher((_, _) => []),
                new MemoryRevocationEvidenceCache(),
                new BouncyCastleRevocationEvidenceParser()));

        SignatureExtensionOutcome outcome = workflow.Extend(new SignatureExtensionRequest(
            "tenant-1",
            stored.ObjectKey,
            new string('0', 64),
            stored.Size,
            "B-T",
            "TurkiyeNes",
            [new SignatureExtensionAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            [],
            [],
            []));

        Assert.Equal(SignatureExtensionStatus.DigestMismatch, outcome.Status);
    }

    private static byte[] SignBaselineB(RSA rsa, byte[] certificateDer)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.NewGuid();
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "EXTEND-API",
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

    private static X509Certificate2 CreateCertificate(RSA rsa)
    {
        CertificateRequest request = new("CN=ImzaKit API extend", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
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
