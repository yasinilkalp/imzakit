using System.Globalization;
using System.Text;
using ImzaKit.PAdES.Appearance;
using ImzaKit.PAdES.Incremental;

namespace ImzaKit.PAdES.Tests.Appearance;

public sealed class PadesSignatureAppearanceTests
{
    [Fact]
    public void PrepareWithoutAppearanceKeepsAnInvisibleSignatureField()
    {
        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(CreateOnePagePdf(), cmsCapacity: 8);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("<< /FT /Sig /T (Signature1) /V 4 0 R >>", document, StringComparison.Ordinal);
        Assert.DoesNotContain("/Subtype /Widget", document, StringComparison.Ordinal);
        Assert.DoesNotContain("/AP <<", document, StringComparison.Ordinal);
    }

    [Fact]
    public void PrepareVisibleAppearanceAttachesWidgetTextDateAndPageAnnotation()
    {
        DateTimeOffset displayedAt = new(2026, 8, 23, 20, 15, 0, TimeSpan.Zero);
        PadesSignatureAppearance appearance = PadesSignatureAppearance.Visible(
            pageNumber: 1,
            lowerLeftX: 72,
            lowerLeftY: 680,
            upperRightX: 240,
            upperRightY: 740,
            text: "Signed by ImzaKit",
            displayedAt);

        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(
            CreateOnePagePdf(),
            cmsCapacity: 8,
            appearance);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("/Rect [72 680 240 740]", document, StringComparison.Ordinal);
        Assert.Contains("/Subtype /Widget", document, StringComparison.Ordinal);
        Assert.Contains("/P 3 0 R", document, StringComparison.Ordinal);
        Assert.Contains("/Annots [6 0 R]", document, StringComparison.Ordinal);
        Assert.Contains("/AP << /N 7 0 R >>", document, StringComparison.Ordinal);
        Assert.Contains("(Signed by ImzaKit)", document, StringComparison.Ordinal);
        Assert.Contains("(2026-08-23 20:15 UTC)", document, StringComparison.Ordinal);
        Assert.Contains("/Subtype /Form", document, StringComparison.Ordinal);
        Assert.DoesNotContain("cryptographic evidence", document, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PrepareVisibleAppearanceEmbedsOptionalJpegWithoutReplacingCmsContents()
    {
        byte[] jpeg = CreateMinimalJpeg();
        PadesSignatureAppearance appearance = PadesSignatureAppearance.Visible(
            1, 36, 36, 180, 90, "Visible seal", imageBytes: jpeg);

        PdfSignaturePlaceholder result = PdfIncrementalSignatureWriter.Prepare(
            CreateOnePagePdf(), 8, appearance);

        string document = Encoding.ASCII.GetString(result.DocumentBytes);
        Assert.Contains("/Subtype /Image", document, StringComparison.Ordinal);
        Assert.Contains("/Filter /DCTDecode", document, StringComparison.Ordinal);
        Assert.Contains("<0000000000000000>", Encoding.ASCII.GetString(
            result.DocumentBytes, result.ContentsOffset, result.ContentsLength), StringComparison.Ordinal);
        Assert.Equal(CreateOnePagePdf(), result.DocumentBytes[..CreateOnePagePdf().Length]);
    }

    [Fact]
    public void PrepareVisibleAppearanceRejectsMissingPage()
    {
        PadesSignatureAppearance appearance = PadesSignatureAppearance.Visible(
            2, 0, 0, 100, 40, "Missing page");

        NotSupportedException exception = Assert.Throws<NotSupportedException>(
            () => PdfIncrementalSignatureWriter.Prepare(CreateOnePagePdf(), 8, appearance));

        Assert.Contains("page", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void VisibleAppearanceRejectsNonJpegImage()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => PadesSignatureAppearance.Visible(1, 0, 0, 10, 10, "x", imageBytes: [0x89, 0x50, 0x4E, 0x47]));

        Assert.Contains("JPEG", exception.Message, StringComparison.Ordinal);
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

    private static byte[] CreateMinimalJpeg() =>
    [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
        0x3F, 0x00, 0x7F, 0xFF, 0xD9,
    ];
}
