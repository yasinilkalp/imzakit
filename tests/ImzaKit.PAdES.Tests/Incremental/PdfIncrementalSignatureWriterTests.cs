using System.Text;
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

    private static byte[] CreateMinimalPdf() => Encoding.ASCII.GetBytes(
        "%PDF-1.4\n" +
        "1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
        "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n" +
        "trailer\n<< /Size 2 /Root 1 0 R >>\n" +
        "startxref\n45\n%%EOF\n");
}
