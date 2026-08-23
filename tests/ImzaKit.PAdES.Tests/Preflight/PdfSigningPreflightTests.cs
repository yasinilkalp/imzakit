using System.Text;
using ImzaKit.PAdES.Preflight;

namespace ImzaKit.PAdES.Tests.Preflight;

public sealed class PdfSigningPreflightTests
{
    [Fact]
    public void ValidateRejectsPdfLargerThanConfiguredLimit()
    {
        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(Pdf("%PDF-1.4\n12345"), new PdfPreflightLimits(8, 10, 2)));

        Assert.Equal(PdfPreflightErrorCode.PdfTooLarge, exception.Code);
    }

    [Theory]
    [InlineData("%PDF-1.3", PdfPreflightErrorCode.UnsupportedVersion)]
    [InlineData("%PDF-2.0", PdfPreflightErrorCode.UnsupportedVersion)]
    [InlineData("%PDF-1.7\ntrailer << /Encrypt 8 0 R >>", PdfPreflightErrorCode.Encrypted)]
    [InlineData("%PDF-1.7\n<< /Type /XRef >>", PdfPreflightErrorCode.XrefStream)]
    [InlineData("%PDF-1.7\n<< /Type /ObjStm >>", PdfPreflightErrorCode.ObjectStream)]
    [InlineData("%PDF-1.7\ntrailer << /XRefStm 42 >>", PdfPreflightErrorCode.HybridReference)]
    [InlineData("%PDF-1.7\n<< /Type /Catalog /AcroForm 4 0 R >>", PdfPreflightErrorCode.ExistingAcroForm)]
    public void ValidateRejectsUnsupportedPdfFeature(string source, PdfPreflightErrorCode expected)
    {
        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(Pdf(source), PdfPreflightLimits.Default));

        Assert.Equal(expected, exception.Code);
    }

    [Fact]
    public void ValidateRejectsObjectCountAboveLimit()
    {
        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(
                Pdf("%PDF-1.4\ntrailer << /Size 11 >>"),
                new PdfPreflightLimits(1024, 10, 2)));

        Assert.Equal(PdfPreflightErrorCode.TooManyObjects, exception.Code);
    }

    [Fact]
    public void ValidateRejectsRevisionCountAboveLimit()
    {
        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(
                Pdf("%PDF-1.4\nstartxref\n10\n%%EOF\nstartxref\n20\n%%EOF"),
                new PdfPreflightLimits(1024, 10, 1)));

        Assert.Equal(PdfPreflightErrorCode.TooManyRevisions, exception.Code);
    }

    [Fact]
    public void ValidateAcceptsClassicUnencryptedPdfWithinLimits()
    {
        PdfSigningPreflight.Validate(
            Pdf("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Size 2 >>\nstartxref\n10\n%%EOF"),
            PdfPreflightLimits.Default);
    }

    [Fact]
    public void ValidateRejectsDocMdpNoChangesPolicy()
    {
        byte[] pdf = Pdf("%PDF-1.7\n/TransformMethod /DocMDP /TransformParams << /P 1 >>");

        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(pdf, PdfPreflightLimits.Default));

        Assert.Equal(PdfPreflightErrorCode.CertificationForbidsChanges, exception.Code);
    }

    [Theory]
    [InlineData("/Action /All /Fields []")]
    [InlineData("/Action /Include /Fields [(Signature1)]")]
    [InlineData("/Action /Exclude /Fields [(OtherField)]")]
    public void ValidateRejectsFieldMdpPolicyLockingTargetField(string fieldPolicy)
    {
        byte[] pdf = Pdf($"%PDF-1.7\n/TransformMethod /FieldMDP /TransformParams << {fieldPolicy} >>");

        PdfPreflightException exception = Assert.Throws<PdfPreflightException>(
            () => PdfSigningPreflight.Validate(pdf, PdfPreflightLimits.Default));

        Assert.Equal(PdfPreflightErrorCode.TargetFieldLocked, exception.Code);
    }

    private static byte[] Pdf(string value) => Encoding.ASCII.GetBytes(value);
}
