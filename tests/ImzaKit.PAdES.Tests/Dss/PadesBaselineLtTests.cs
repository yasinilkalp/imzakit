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
using ImzaKit.PAdES.Preparation;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using UglyToad.PdfPig;

namespace ImzaKit.PAdES.Tests.Dss;

public sealed class PadesBaselineLtTests
{
    [Fact]
    public void EmbedBaselineLtPreservesSignedBytesAndWritesDssWithSignerAndTsaCerts()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit PAdES B-LT");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineT(rsa, certificateDer, tsa);
        byte[] ocsp = [0x30, 0x03, 0x02, 0x01, 0x05];
        byte[] crl = [0x30, 0x03, 0x02, 0x01, 0x06];
        PadesValidationMaterial material = new(
            [certificateDer, tsa.CertificateDer],
            [ocsp],
            [crl]);

        byte[] longTermPdf = PadesSignatureCompleter.EmbedBaselineLt(signedPdf, material);

        Assert.Equal(signedPdf, longTermPdf[..signedPdf.Length]);
        string document = Encoding.ASCII.GetString(longTermPdf);
        Assert.Contains("/Type /DSS", document, StringComparison.Ordinal);
        Assert.Contains("/Certs [", document, StringComparison.Ordinal);
        Assert.Contains("/OCSPs [", document, StringComparison.Ordinal);
        Assert.Contains("/CRLs [", document, StringComparison.Ordinal);
        Assert.Contains("/VRI ", document, StringComparison.Ordinal);
        Assert.Contains("/" + VriKey(signedPdf, preparation), document, StringComparison.Ordinal);
        Assert.Equal(3, CountToken(document, "startxref"));
        using PdfDocument pdf = PdfDocument.Open(longTermPdf, new ParsingOptions { UseLenientParsing = false });
        Assert.Equal(1, pdf.NumberOfPages);
        AssertCmsStillValid(longTermPdf, preparation);
    }

    [Fact]
    public void CompleteBaselineTThenLtKeepsDetachedCmsValid()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit PAdES B-LT TSA");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineT(rsa, certificateDer, tsa);

        byte[] longTermPdf = PadesSignatureCompleter.EmbedBaselineLt(
            signedPdf,
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer]));

        AssertCmsStillValid(longTermPdf, preparation);
    }

    [Fact]
    public void ValidationMaterialRejectsEmptyCertificateSet()
    {
        Assert.Throws<ArgumentException>(() => new PadesValidationMaterial([]));
    }

    [Fact]
    public void EmbedBaselineLtMergesAdditionalOcspIntoExistingDss()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit PAdES DSS merge");
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        using TestTsaResponder tsa = new();
        (byte[] signedPdf, PadesSignaturePreparation preparation) = SignBaselineT(rsa, certificateDer, tsa);
        byte[] firstOcsp = [0x30, 0x03, 0x02, 0x01, 0x05];
        byte[] secondOcsp = [0x30, 0x03, 0x02, 0x01, 0x07];
        byte[] first = PadesSignatureCompleter.EmbedBaselineLt(
            signedPdf,
            new PadesValidationMaterial([certificateDer, tsa.CertificateDer], [firstOcsp]));

        byte[] merged = PadesSignatureCompleter.EmbedBaselineLt(
            first,
            new PadesValidationMaterial([certificateDer], [secondOcsp]));

        Assert.Equal(first, merged[..first.Length]);
        string document = Encoding.ASCII.GetString(merged);
        Assert.Contains(Convert.ToHexString(firstOcsp), Convert.ToHexString(merged), StringComparison.Ordinal);
        Assert.Contains(Convert.ToHexString(secondOcsp), Convert.ToHexString(merged), StringComparison.Ordinal);
        Assert.Equal(4, CountToken(document, "startxref"));
        AssertCmsStillValid(merged, preparation);
    }

    private static (byte[] SignedPdf, PadesSignaturePreparation Preparation) SignBaselineT(
        RSA rsa,
        byte[] certificateDer,
        TestTsaResponder tsa)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("b8d4e2f1-5c03-4d29-8a7b-32e9f1c5d012");
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

    private static string VriKey(byte[] signedPdf, PadesSignaturePreparation preparation)
    {
        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            signedPdf,
            preparation.Placeholder.ContentsOffset + 1,
            preparation.Placeholder.ContentsLength - 2));
        int cmsLength = ReadDerValueLength(paddedCms);
#pragma warning disable CA5350
        return Convert.ToHexString(SHA1.HashData(paddedCms.AsSpan(0, cmsLength)));
#pragma warning restore CA5350
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
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(respond(request.Uri, request.Body), "application/timestamp-reply"));
    }
}
