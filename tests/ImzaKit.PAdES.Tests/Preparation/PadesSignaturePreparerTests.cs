using System.Globalization;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Cms.Completion;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Appearance;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Incremental;
using ImzaKit.PAdES.Preparation;

namespace ImzaKit.PAdES.Tests.Preparation;

public sealed class PadesSignaturePreparerTests
{
    [Fact]
    public void PrepareBindsCmsSignedAttributesToPdfByteRangeContent()
    {
        Guid operationId = Guid.Parse("6589a5df-3ea5-497b-b494-1cf6a0c9013a");
        byte[] certificateDer = [0x30, 0x03, 0x02, 0x01, 0x01];
        CmsSignaturePreparer cmsPreparer = new(new DefaultDigestCalculator());
        PadesSignaturePreparer preparer = new(cmsPreparer);

        PadesSignaturePreparation result = preparer.Prepare(
            operationId,
            "ORIGINAL-PDF-SHA256",
            CreateMinimalPdf(),
            cmsCapacity: 128,
            certificateDer,
            "CERTIFICATE-SHA256",
            prepareVersion: 3);

        byte[] signablePdf = result.Placeholder.GetSignableBytes();
        byte[] expectedSignedAttributes = cmsPreparer.PrepareDetached(
            operationId,
            "ORIGINAL-PDF-SHA256",
            signablePdf,
            certificateDer,
            "CERTIFICATE-SHA256",
            prepareVersion: 3).DataToBeSigned.ToArray();

        Assert.Equal(expectedSignedAttributes, result.SignaturePreparation.DataToBeSigned.ToArray());
        Assert.Equal(operationId, result.SignaturePreparation.OperationId);
        Assert.Equal(3, result.SignaturePreparation.PrepareVersion);
    }

    [Fact]
    public void CompleteEmbedsCmsBuiltFromMatchingExternalSignature()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit PAdES Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("fedf0b2e-7d2c-4630-a87c-13c0a70ad953");
        PadesSignaturePreparer preparer = new(new CmsSignaturePreparer(new DefaultDigestCalculator()));
        PadesSignaturePreparation preparation = preparer.Prepare(
            operationId,
            "ORIGINAL-PDF-SHA256",
            CreateMinimalPdf(),
            cmsCapacity: 4096,
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] signatureValue = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, signatureValue);
        byte[] expectedCms = CmsSignedDataCompleter.CompleteDetached(
            preparation.SignaturePreparation,
            completion,
            certificateDer);

        byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificateDer);

        string embeddedHex = Encoding.ASCII.GetString(
            signedPdf,
            preparation.Placeholder.ContentsOffset + 1,
            expectedCms.Length * 2);
        Assert.Equal(Convert.ToHexString(expectedCms), embeddedHex);
    }

    [Fact]
    public void CompleteKeepsCmsBindingWhenVisibleAppearanceIsPresent()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit Visible PAdES", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("9c1b0c3e-4a2f-4d8a-9e11-77aa12bb01c4");
        PadesSignatureAppearance appearance = PadesSignatureAppearance.Visible(
            1, 72, 680, 240, 740, "Signed by ImzaKit");
        PadesSignaturePreparer preparer = new(new CmsSignaturePreparer(new DefaultDigestCalculator()));
        PadesSignaturePreparation preparation = preparer.Prepare(
            operationId,
            "ORIGINAL-PDF-SHA256",
            CreateOnePagePdf(),
            cmsCapacity: 4096,
            certificateDer,
            fingerprint,
            prepareVersion: 1,
            appearance);
        byte[] signatureValue = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, signatureValue);
        byte[] expectedCms = CmsSignedDataCompleter.CompleteDetached(
            preparation.SignaturePreparation,
            completion,
            certificateDer);

        byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificateDer);

        string pdf = Encoding.ASCII.GetString(signedPdf);
        string embeddedHex = Encoding.ASCII.GetString(
            signedPdf,
            preparation.Placeholder.ContentsOffset + 1,
            expectedCms.Length * 2);
        Assert.Equal(Convert.ToHexString(expectedCms), embeddedHex);
        Assert.Contains("/Subtype /Widget", pdf, StringComparison.Ordinal);
        Assert.Contains("(Signed by ImzaKit)", pdf, StringComparison.Ordinal);
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
            .Append(xrefOffset.ToString(CultureInfo.InvariantCulture))
            .Append("\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static byte[] CreateMinimalPdf() => Encoding.ASCII.GetBytes(
        "%PDF-1.4\n" +
        "1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
        "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n" +
        "trailer\n<< /Size 2 /Root 1 0 R >>\n" +
        "startxref\n45\n%%EOF\n");
}
