using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.PAdES.Completion;
using ImzaKit.PAdES.Incremental;
using ImzaKit.PAdES.Preparation;
using UglyToad.PdfPig;

namespace ImzaKit.PAdES.Tests.Interop;

public sealed class PadesIndependentRoundtripTests
{
    [Fact]
    public void IncrementalOutputOpensWithIndependentPdfReader()
    {
        byte[] original = CreateOnePagePdf();
        byte[] incrementalPdf = PdfIncrementalSignatureWriter.Prepare(original, cmsCapacity: 128).DocumentBytes;

        using PdfDocument document = PdfDocument.Open(
            incrementalPdf,
            new ParsingOptions { UseLenientParsing = false });

        Assert.Equal(1, document.NumberOfPages);
    }

    [Fact]
    public void CompletedPdfContainsCmsValidForItsByteRangeContent()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit Interop", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        Guid operationId = Guid.Parse("22ff0570-e478-43e3-8071-d82c862e7bb4");
        PadesSignaturePreparation preparation = new PadesSignaturePreparer(
            new CmsSignaturePreparer(new DefaultDigestCalculator())).Prepare(
                operationId,
                "ORIGINAL-PDF-SHA256",
                CreateOnePagePdf(),
                cmsCapacity: 4096,
                certificateDer,
                fingerprint,
                prepareVersion: 1);
        byte[] externalSignature = rsa.SignData(
            preparation.SignaturePreparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(operationId, 1, fingerprint, externalSignature);

        byte[] signedPdf = PadesSignatureCompleter.Complete(preparation, completion, certificateDer);

        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            signedPdf,
            preparation.Placeholder.ContentsOffset + 1,
            preparation.Placeholder.ContentsLength - 2));
        int cmsLength = ReadDerValueLength(paddedCms);
        SignedCms signedCms = new(
            new ContentInfo(preparation.Placeholder.GetSignableBytes()),
            detached: true);
        signedCms.Decode(paddedCms[..cmsLength]);
        signedCms.CheckSignature(verifySignatureOnly: true);
        Assert.Single(signedCms.SignerInfos);
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
}
