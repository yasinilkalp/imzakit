using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Net;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Incremental;
using ImzaKit.PAdES.Lta;
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using UglyToad.PdfPig;

namespace ImzaKit.PAdES.Tests.Lta;

public sealed class PadesBaselineLtaTests
{
    [Fact]
    public async Task CompleteBaselineLtaWritesDocTimeStampOverDssRevision()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit PAdES B-LTA");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineT(rsa, certificateDer, tsa);
        byte[] longTermPdf = PadesSignatureCompleter.EmbedBaselineLt(
            signedPdf,
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] archivePdf = await PadesSignatureCompleter.CompleteBaselineLta(
            longTermPdf,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("archive", new Uri("https://tsa.example/rfc3161"))],
            tokenCapacity: 8192,
            CancellationToken.None);

        Assert.Equal(longTermPdf, archivePdf[..longTermPdf.Length]);
        string document = Encoding.ASCII.GetString(archivePdf);
        Assert.Contains("/Type /DocTimeStamp", document, StringComparison.Ordinal);
        Assert.Contains("/SubFilter /ETSI.RFC3161", document, StringComparison.Ordinal);
        Assert.Contains("/T (DocTimeStamp1)", document, StringComparison.Ordinal);
        Assert.Equal(4, CountToken(document, "startxref"));
        using PdfDocument pdf = PdfDocument.Open(archivePdf, new ParsingOptions { UseLenientParsing = false });
        Assert.Equal(1, pdf.NumberOfPages);
        AssertCmsStillValid(archivePdf, preparation);

        PdfSignaturePlaceholder placeholder = PdfDocumentTimestampWriter.Prepare(longTermPdf, 8192);
        byte[] padded = Convert.FromHexString(Encoding.ASCII.GetString(
            archivePdf,
            placeholder.ContentsOffset + 1,
            placeholder.ContentsLength - 2));
        int tokenLength = ReadDerValueLength(padded);
        TimeStampToken token = new(new CmsSignedData(padded[..tokenLength]));
        Assert.Equal(SHA256.HashData(placeholder.GetSignableBytes()), token.TimeStampInfo.GetMessageImprintDigest());
        Assert.Equal(1, fetcher.Calls);
    }

    [Fact]
    public void PrepareDocumentTimestampRejectsPdfWithoutDss()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit PAdES B-LTA no DSS");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, _) = SignBaselineT(rsa, certificateDer, tsa);

        NotSupportedException error = Assert.Throws<NotSupportedException>(
            () => PdfDocumentTimestampWriter.Prepare(signedPdf, 128));

        Assert.Contains("DSS", error.Message, StringComparison.Ordinal);
    }

    private static (byte[] SignedPdf, PadesSignaturePreparation Preparation) SignBaselineT(
        RSA rsa,
        byte[] certificateDer,
        TestTsaResponder tsa)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("c9e5f3a2-6d14-4e3a-9b8c-43f0a2d6e123");
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "ORIGINAL-PDF-SHA256",
                CreateOnePagePdf(),
                cmsCapacity: 8192,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] signatureValue = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, signatureValue);
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        byte[] signedPdf = PadesSignatureCompleter.CompleteBaselineT(
            preparation,
            completion,
            certificateDer,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None).GetAwaiter().GetResult();
        return (signedPdf, preparation);
    }

    private static void AssertCmsStillValid(byte[] pdf, PadesSignaturePreparation preparation)
    {
        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            pdf,
            preparation.Placeholder.ContentsOffset + 1,
            preparation.Placeholder.ContentsLength - 2));
        int cmsLength = ReadDerValueLength(paddedCms);
        SignedCms signedCms = new(
            new ContentInfo(preparation.Placeholder.GetSignableBytes()),
            detached: true);
        signedCms.Decode(paddedCms[..cmsLength]);
        signedCms.CheckSignature(verifySignatureOnly: true);
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
        builder.Append("xref\n0 4\n")
            .Append("0000000000 65535 f \n")
            .Append(catalogOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pagesOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pageOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
            .Append(xrefOffset.ToString(CultureInfo.InvariantCulture))
            .Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static int CountToken(string source, string token)
    {
        int count = 0;
        int searchIndex = 0;
        while ((searchIndex = source.IndexOf(token, searchIndex, StringComparison.Ordinal)) >= 0)
        {
            count++;
            searchIndex += token.Length;
        }

        return count;
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
