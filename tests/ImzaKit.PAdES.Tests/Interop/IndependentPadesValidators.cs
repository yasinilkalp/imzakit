using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Org.BouncyCastle.Cms;
using PdfSharp.Pdf.IO;
using UglyToad.PdfPig;

namespace ImzaKit.PAdES.Tests.Interop;

internal sealed record IndependentPadesVerdict(bool PdfOpens, bool CmsSignatureValid);

internal interface IIndependentPadesValidator
{
    string Name { get; }

    IndependentPadesVerdict Validate(GoldenPadesFixture fixture);
}

internal sealed class PdfPigSignedCmsValidator : IIndependentPadesValidator
{
    public string Name => "PdfPig+SignedCms";

    public IndependentPadesVerdict Validate(GoldenPadesFixture fixture)
    {
        using UglyToad.PdfPig.PdfDocument document = UglyToad.PdfPig.PdfDocument.Open(
            fixture.SignedPdf,
            new ParsingOptions { UseLenientParsing = false });
        bool pdfOpens = document.NumberOfPages == 1;

        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            fixture.SignedPdf,
            fixture.Preparation.Placeholder.ContentsOffset + 1,
            fixture.Preparation.Placeholder.ContentsLength - 2));
        int cmsLength = ReadDerValueLength(paddedCms);
        SignedCms signedCms = new(new ContentInfo(fixture.Preparation.Placeholder.GetSignableBytes()), detached: true);
        signedCms.Decode(paddedCms.AsSpan(0, cmsLength));
        signedCms.CheckSignature(verifySignatureOnly: true);
        return new IndependentPadesVerdict(pdfOpens, signedCms.SignerInfos.Count == 1);
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

internal sealed class PdfSharpBouncyCastleValidator : IIndependentPadesValidator
{
    public string Name => "PDFsharp+BouncyCastle";

    public IndependentPadesVerdict Validate(GoldenPadesFixture fixture)
    {
        using MemoryStream stream = new(fixture.SignedPdf, writable: false);
        using PdfSharp.Pdf.PdfDocument document = PdfReader.Open(stream, PdfDocumentOpenMode.Import);
        bool pdfOpens = document.Pages.Count == 1;

        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(
            fixture.SignedPdf,
            fixture.Preparation.Placeholder.ContentsOffset + 1,
            fixture.Preparation.Placeholder.ContentsLength - 2));
        byte[] cmsBytes = paddedCms[..ReadDerValueLength(paddedCms)];
        CmsSignedData signedData = new(
            new CmsProcessableByteArray(fixture.Preparation.Placeholder.GetSignableBytes()),
            cmsBytes);
        SignerInformation signer = signedData.GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        Org.BouncyCastle.X509.X509Certificate certificate = signedData.GetCertificates()
            .EnumerateMatches(signer.SignerID)
            .Cast<Org.BouncyCastle.X509.X509Certificate>()
            .Single();
        return new IndependentPadesVerdict(pdfOpens, signer.Verify(certificate.GetPublicKey()));
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
