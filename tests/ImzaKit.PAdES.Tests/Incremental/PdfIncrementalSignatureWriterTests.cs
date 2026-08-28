using System.Globalization;
using System.Text;
using ImzaKit.PAdES.Appearance;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Tests.Incremental;

public sealed class PdfIncrementalSignatureWriterTests
{
    [Fact]
    public void PreparePreservesEveryOriginalByte()
    {
        byte[] original = CreateMinimalPdf();

        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(original, cmsCapacity: 8);

        Assert.Equal(original, result.DocumentBytes[..original.Length]);
        Assert.True(result.DocumentBytes.Length > original.Length);
    }

    [Fact]
    public void PrepareLinksNewTrailerToPreviousCrossReference()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("/Prev 45 >>", document, StringComparison.Ordinal);
    }

    [Fact]
    public void PrepareConnectsSignatureToCatalogThroughAcroFormField()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("/AcroForm 3 0 R", document, StringComparison.Ordinal);
        Assert.Contains("3 0 obj\n<< /Fields [4 0 R] /SigFlags 3 >>\nendobj", document, StringComparison.Ordinal);
        Assert.Contains("4 0 obj\n<< /FT /Sig /T (Signature1) /V 2 0 R >>\nendobj", document, StringComparison.Ordinal);
    }

    [Fact]
    public void PrepareExcludesOnlyReservedContentsFromByteRange()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);

        Assert.Equal(18, result.ContentsLength);
        Assert.Equal("<0000000000000000>", Encoding.ASCII.GetString(
            result.DocumentBytes, result.ContentsOffset, result.ContentsLength));
        Assert.Equal(
            [0L, result.ContentsOffset, result.ContentsOffset + result.ContentsLength,
                result.DocumentBytes.Length - result.ContentsOffset - result.ContentsLength],
            result.ByteRange);
    }

    [Fact]
    public void EmbedSignatureRejectsCmsLargerThanReservedCapacity()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => result.EmbedSignature(new byte[9]));

        Assert.Contains("capacity", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EmbedSignatureWritesUppercaseHexAndKeepsPadding()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);

        byte[] signedDocument = result.EmbedSignature([0x01, 0xAB, 0xFF]);

        Assert.Equal("<01ABFF0000000000>", Encoding.ASCII.GetString(
            signedDocument, result.ContentsOffset, result.ContentsLength));
    }

    [Fact]
    public void GetSignableBytesConcatenatesBothByteRangeSegments()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateMinimalPdf(), cmsCapacity: 8);
        byte[] document = result.DocumentBytes;
        byte[] expected =
        [
            .. document[..result.ContentsOffset],
            .. document[(result.ContentsOffset + result.ContentsLength)..],
        ];

        byte[] signableBytes = result.GetSignableBytes();

        Assert.Equal(expected, signableBytes);
    }

    [Fact]
    public void PrepareAppendsSecondSignatureRevisionWithoutRewritingFirstSignatureBytes()
    {
        byte[] original = CreateMinimalPdf();
        PdfSignaturePlaceholder first = PdfIncrementalSignatureWriter.Prepare(original, cmsCapacity: 8);
        byte[] onceSigned = first.EmbedSignature([0x01, 0xAB]);

        PdfSignaturePlaceholder second = PdfIncrementalSignatureWriter.Prepare(onceSigned, cmsCapacity: 8);

        Assert.Equal(onceSigned, second.DocumentBytes[..onceSigned.Length]);
        string document = Encoding.ASCII.GetString(second.DocumentBytes);
        Assert.Contains("/T (Signature1)", document, StringComparison.Ordinal);
        Assert.Contains("/T (Signature2)", document, StringComparison.Ordinal);
        Assert.Contains("/Fields [4 0 R 6 0 R]", document, StringComparison.Ordinal);
    }

    [Fact]
    public void PrepareVisibleSignatureReadsNestedPdfACatalogAndPageDictionaries()
    {
        PadesSignatureAppearance appearance = PadesSignatureAppearance.Visible(
            1, 72, 680, 240, 740, "E-Imzali");

        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(
            CreatePdfALikeOnePagePdf(),
            cmsCapacity: 8,
            appearance);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("/Pages 2 0 R", document, StringComparison.Ordinal);
        Assert.Contains("/Annots [7 0 R]", document, StringComparison.Ordinal);
        Assert.Contains("/Subtype /Widget", document, StringComparison.Ordinal);
        Assert.Contains("(E-Imzali)", document, StringComparison.Ordinal);
    }

    private static byte[] CreatePdfALikeOnePagePdf()
    {
        StringBuilder builder = new("%PDF-1.4\n");
        int catalogOffset = builder.Length;
        builder.Append(
            "1 0 obj\n" +
            "<< /Type /Catalog /OutputIntents [<< /Type /OutputIntent /S /GTS_PDFA1 /DestOutputProfile 4 0 R >>] " +
            "/Pages 2 0 R /ViewerPreferences << /DisplayDocTitle true >> >>\nendobj\n");
        int pagesOffset = builder.Length;
        builder.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        int pageOffset = builder.Length;
        builder.Append(
            "3 0 obj\n" +
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
            "/Resources << /ProcSet [/PDF] /ExtGState << /G4 4 0 R >> >> >>\nendobj\n");
        int extStateOffset = builder.Length;
        builder.Append("4 0 obj\n<< /Type /ExtGState /CA 1 >>\nendobj\n");
        int xrefOffset = builder.Length;
        builder.Append("xref\n0 5\n0000000000 65535 f \n")
            .Append(catalogOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pagesOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(pageOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append(extStateOffset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n")
            .Append("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n")
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
