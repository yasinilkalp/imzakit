using System.Text;
using ImzaKit.PAdES.Policy;

namespace ImzaKit.PAdES.Tests.Policy;

public sealed class PdfModificationPolicyEvaluatorTests
{
    [Fact]
    public void NoPolicyHasNoViolations()
    {
        byte[] pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n%%EOF\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(pdf, pdf.Length);

        Assert.Empty(result.Violations);
        Assert.Equal(PdfCertificationChangeLevel.None, result.Policy.CertificationPermission);
        Assert.Equal(PdfFieldLockAction.None, result.Policy.FieldLockAction);
    }

    [Fact]
    public void DocMdpNoChangesAllowsDssAndDocumentTimestampTails()
    {
        byte[] covered = Covered("/TransformMethod /DocMDP /TransformParams << /P 1 >>");
        byte[] dssTail = Encoding.ASCII.GetBytes(
            "10 0 obj\n<< /Type /DSS /Certs [11 0 R] >>\nendobj\nstartxref\n0\n%%EOF\n");
        byte[] timestampTail = Encoding.ASCII.GetBytes(
            "12 0 obj\n<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 >>\nendobj\n" +
            "13 0 obj\n<< /FT /Sig /T (DocTimeStamp1) /V 12 0 R >>\nendobj\n");

        Assert.Empty(PdfModificationPolicyEvaluator.Evaluate(Concat(covered, dssTail), covered.Length).Violations);
        Assert.Empty(PdfModificationPolicyEvaluator.Evaluate(Concat(covered, timestampTail), covered.Length).Violations);
    }

    [Fact]
    public void DocMdpNoChangesRejectsExtraPageAndApprovalSignature()
    {
        byte[] covered = Covered("/TransformMethod /DocMDP /TransformParams << /P 1 >>");
        byte[] pageTail = Encoding.ASCII.GetBytes("9 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");
        byte[] signatureTail = Encoding.ASCII.GetBytes(
            "9 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached >>\nendobj\n");

        PdfModificationPolicyEvaluation page = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, pageTail), covered.Length);
        PdfModificationPolicyEvaluation signature = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, signatureTail), covered.Length);

        Assert.Contains(page.Violations, violation => violation.Code == "DocMdpViolation");
        Assert.Contains(signature.Violations, violation => violation.Code == "DocMdpViolation");
    }

    [Fact]
    public void DocMdpFormFillAllowsApprovalSignatureInTail()
    {
        byte[] covered = Covered("/TransformMethod /DocMDP /TransformParams << /P 2 >>");
        byte[] signatureTail = Encoding.ASCII.GetBytes(
            "9 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached >>\nendobj\n" +
            "10 0 obj\n<< /FT /Sig /T (Signature2) /V 9 0 R >>\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, signatureTail), covered.Length);

        Assert.Empty(result.Violations);
        Assert.Equal(PdfCertificationChangeLevel.FormFillAndSign, result.Policy.CertificationPermission);
    }

    [Fact]
    public void FieldMdpIncludeReportsLockedFieldChangeAndIgnoresOtherFields()
    {
        byte[] covered = Covered(
            "/TransformMethod /FieldMDP /TransformParams << /Action /Include /Fields [(Amount)] >>");
        byte[] amountTail = Encoding.ASCII.GetBytes(
            "9 0 obj\n<< /FT /Tx /T (Amount) /V (100) >>\nendobj\n");
        byte[] otherTail = Encoding.ASCII.GetBytes(
            "9 0 obj\n<< /FT /Tx /T (Note) /V (ok) >>\nendobj\n");

        PdfModificationPolicyEvaluation locked = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, amountTail), covered.Length);
        PdfModificationPolicyEvaluation other = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, otherTail), covered.Length);

        Assert.Contains(
            locked.Violations,
            violation => violation.Code == "FieldMdpViolation" && violation.FieldName == "Amount");
        Assert.Empty(other.Violations);
    }

    [Fact]
    public void FieldMdpAllReportsNonPreservationFieldInTail()
    {
        byte[] covered = Covered(
            "/TransformMethod /FieldMDP /TransformParams << /Action /All /Fields [] >>");
        byte[] tail = Encoding.ASCII.GetBytes(
            "9 0 obj\n<< /FT /Tx /T (Name) /V (Ada) >>\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Contains(
            result.Violations,
            violation => violation.Code == "FieldMdpViolation" && violation.FieldName == "Name");
    }

    [Fact]
    public void ApprovalSignatureDetectsReplacedContentStream()
    {
        byte[] covered = SignedDocument();
        byte[] tail = Encoding.ASCII.GetBytes(
            "4 0 obj\n<< /Length 25 >>\nstream\nBT (PAID IN FULL) Tj ET\n\nendstream\nendobj\n" +
            "trailer\n<< /Size 6 /Root 1 0 R >>\n%%EOF\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        PdfModificationPolicyViolation violation = Assert.Single(result.Violations);
        Assert.Equal("ContentModifiedAfterSigning", violation.Code);
        Assert.Contains("object 4", violation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ApprovalSignatureAllowsSecondSignatureWidgetAndMetadataUpdates()
    {
        byte[] covered = SignedDocument();
        byte[] tail = Encoding.ASCII.GetBytes(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [8 0 R] >>\nendobj\n" +
            "5 0 obj\n<< /Fields [6 0 R 8 0 R] /SigFlags 3 >>\nendobj\n" +
            "7 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached >>\nendobj\n" +
            "8 0 obj\n<< /FT /Sig /Type /Annot /Subtype /Widget /Rect [0 0 10 10] /T (Signature2) /V 7 0 R >>\nendobj\n" +
            "9 0 obj\n<< /Producer (Other tool) /ModDate (D:20261029) >>\nendobj\n" +
            "trailer\n<< /Size 10 /Root 1 0 R /Info 9 0 R >>\n%%EOF\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Empty(result.Violations);
        Assert.True(result.IsComplete);
    }

    [Fact]
    public void CommentedDssMarkerDoesNotHideContentChangeUnderNoChanges()
    {
        byte[] covered = SignedDocument("/TransformMethod /DocMDP /TransformParams << /P 1 >>");
        byte[] tail = Encoding.ASCII.GetBytes(
            "% /Type /DSS\n4 0 obj\n<< /Length 9 >>\nstream\nBT (x) ET\nendstream\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Contains(result.Violations, violation => violation.Code == "DocMdpViolation");
    }

    [Fact]
    public void CompactDocMdpSyntaxIsRecognised()
    {
        byte[] pdf = Covered("/Reference [<</Type/SigRef/TransformMethod/DocMDP/TransformParams<</Type/TransformParams/P 1/V/1.2>>>>]");

        Assert.Equal(PdfCertificationChangeLevel.NoChanges, PdfModificationPolicyInspector.Inspect(pdf).CertificationPermission);
    }

    [Fact]
    public void DocMdpWithoutParametersDefaultsToFormFillAndSign()
    {
        byte[] pdf = Covered("/Reference [<< /Type /SigRef /TransformMethod /DocMDP >>]");

        Assert.Equal(PdfCertificationChangeLevel.FormFillAndSign, PdfModificationPolicyInspector.Inspect(pdf).CertificationPermission);
    }

    [Theory]
    [InlineData("2", true)]
    [InlineData("3", false)]
    public void NewPageAnnotationIsForbiddenOnlyBelowAnnotateLevel(string permission, bool forbidden)
    {
        byte[] covered = SignedDocument($"/TransformMethod /DocMDP /TransformParams << /P {permission} >>");
        byte[] tail = Encoding.ASCII.GetBytes(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [10 0 R] >>\nendobj\n" +
            "10 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Approved) >>\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Equal(forbidden, result.Violations.Any(violation => violation.Code == "DocMdpViolation"));
    }

    [Fact]
    public void ChangesInsideObjectStreamsAreInspected()
    {
        byte[] covered = SignedDocument();
        byte[] tail = ObjectStream(
            11,
            (3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>"));

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Contains(result.Violations, violation => violation.Code == "ContentModifiedAfterSigning");
        Assert.True(result.IsComplete);
    }

    [Fact]
    public void UndecodableObjectStreamMakesAnalysisIncomplete()
    {
        byte[] covered = SignedDocument();
        byte[] tail = Encoding.ASCII.GetBytes(
            "11 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length 6 >>\nstream\ngarbag\nendstream\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Empty(result.Violations);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void DeletedObjectAndReplacedCatalogAreContentChanges()
    {
        byte[] covered = SignedDocument();
        byte[] deleted = Encoding.ASCII.GetBytes("xref\n4 1\n0000000000 00001 f \ntrailer\n<< /Size 8 /Root 1 0 R >>\n");
        byte[] replacedRoot = Encoding.ASCII.GetBytes(
            "12 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Size 13 /Root 12 0 R >>\n");

        Assert.Contains(
            PdfModificationPolicyEvaluator.Evaluate(Concat(covered, deleted), covered.Length).Violations,
            violation => violation.Message.Contains("deleted", StringComparison.Ordinal));
        Assert.Contains(
            PdfModificationPolicyEvaluator.Evaluate(Concat(covered, replacedRoot), covered.Length).Violations,
            violation => violation.Message.Contains("catalog replaced", StringComparison.Ordinal));
    }

    [Fact]
    public void DeletionInCrossReferenceStreamIsContentChange()
    {
        byte[] covered = SignedDocument();
        byte[] tail = XrefStream(12, first: 3, 1, 0);

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.True(result.IsComplete);
        Assert.Contains(result.Violations, violation => violation.Message.Contains("object 4 deleted", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Violations, violation => violation.Message.Contains("object 3 deleted", StringComparison.Ordinal));
    }

    [Fact]
    public void UndecodableCrossReferenceStreamMakesAnalysisIncomplete()
    {
        byte[] covered = SignedDocument();
        byte[] tail = Encoding.ASCII.GetBytes(
            "12 0 obj\n<< /Type /XRef /W [1 2 1] /Size 13 /Root 1 0 R /Filter /FlateDecode /Length 6 >>\nstream\ngarbag\nendstream\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Empty(result.Violations);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void FieldMdpDetectsLockedValueChangeEvenWhenTitleIsDropped()
    {
        byte[] covered = FormDocument(
            "8 0 obj\n<< /FT /Tx /T (Amount) /V (100) >>\nendobj\n",
            "/TransformMethod /FieldMDP /TransformParams << /Action /Include /Fields [(Amount)] >>");
        byte[] tail = Encoding.ASCII.GetBytes("8 0 obj\n<< /FT /Tx /V (999) >>\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Contains(result.Violations, violation => violation.Code == "FieldMdpViolation" && violation.FieldName == "Amount");
    }

    [Fact]
    public void FieldMdpMatchesHexEncodedFullyQualifiedNames()
    {
        const string invoice = "<FEFF0049006E0076006F006900630065>";
        const string invoiceAmount = "<FEFF0049006E0076006F006900630065002E0041006D006F0075006E0074>";
        byte[] covered = FormDocument(
            $"8 0 obj\n<< /T {invoice} /Kids [9 0 R] >>\nendobj\n" +
            "9 0 obj\n<< /Parent 8 0 R /FT /Tx /T (Amount) /V (1) >>\nendobj\n",
            $"/TransformMethod /FieldMDP /TransformParams << /Action /Include /Fields [{invoiceAmount}] >>");
        byte[] tail = Encoding.ASCII.GetBytes("9 0 obj\n<< /Parent 8 0 R /FT /Tx /T (Amount) /V (2) >>\nendobj\n");

        PdfModificationPolicyEvaluation result = PdfModificationPolicyEvaluator.Evaluate(
            Concat(covered, tail), covered.Length);

        Assert.Equal(["Invoice.Amount"], result.Policy.FieldNames);
        Assert.Contains(result.Violations, violation => violation.FieldName == "Invoice.Amount");
    }

    private static byte[] FormDocument(string fields, string policy) =>
        Encoding.ASCII.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "5 0 obj\n<< /Fields [6 0 R 8 0 R] >>\nendobj\n" +
            "6 0 obj\n<< /FT /Sig /T (Signature1) /V 7 0 R >>\nendobj\n" +
            $"7 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached /Reference [<< {policy} >>] >>\nendobj\n" +
            fields +
            "trailer\n<< /Size 10 /Root 1 0 R >>\n%%EOF\n");

    // A one-page document with a content stream, an AcroForm and one signature (objects 1-7).
    private static byte[] SignedDocument(string policy = "") =>
        Encoding.ASCII.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n" +
            "4 0 obj\n<< /Length 18 >>\nstream\nBT (Invoice) Tj ET\nendstream\nendobj\n" +
            "5 0 obj\n<< /Fields [6 0 R] /SigFlags 3 >>\nendobj\n" +
            "6 0 obj\n<< /FT /Sig /T (Signature1) /V 7 0 R >>\nendobj\n" +
            $"7 0 obj\n<< /Type /Sig /SubFilter /ETSI.CAdES.detached {policy} >>\nendobj\n" +
            "trailer\n<< /Size 8 /Root 1 0 R >>\n%%EOF\n");

    private static byte[] ObjectStream(int number, params (int Number, string Body)[] objects)
    {
        StringBuilder header = new();
        StringBuilder bodies = new();
        foreach ((int objectNumber, string body) in objects)
        {
            header.Append(objectNumber).Append(' ').Append(bodies.Length).Append(' ');
            bodies.Append(body).Append('\n');
        }

        byte[] data = Deflate(Encoding.ASCII.GetBytes(header.ToString() + bodies));
        byte[] prefix = Encoding.ASCII.GetBytes(
            $"{number} 0 obj\n<< /Type /ObjStm /N {objects.Length} /First {header.Length} /Filter /FlateDecode /Length {data.Length} >>\nstream\n");
        byte[] suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n");
        return [.. prefix, .. data, .. suffix];
    }

    // A cross-reference stream (/W [1 2 1]) with one entry of the given type per object from `first`,
    // compressed with FlateDecode and the PNG Up predictor, as PDF writers usually emit it.
    private static byte[] XrefStream(int number, int first, params byte[] types)
    {
        const int columns = 4;
        byte[] rows = new byte[types.Length * (columns + 1)];
        byte[] previous = new byte[columns];
        for (int entry = 0; entry < types.Length; entry++)
        {
            byte[] row = [types[entry], 0, (byte)(16 * (entry + 1)), 0];
            rows[entry * (columns + 1)] = 2;
            for (int column = 0; column < columns; column++)
            {
                rows[(entry * (columns + 1)) + 1 + column] = (byte)(row[column] - previous[column]);
            }

            previous = row;
        }

        byte[] data = Deflate(rows);
        byte[] prefix = Encoding.ASCII.GetBytes(
            $"{number} 0 obj\n<< /Type /XRef /W [1 2 1] /Index [{first} {types.Length}] /Size {number + 1} /Root 1 0 R " +
            $"/Filter /FlateDecode /DecodeParms << /Columns {columns} /Predictor 12 >> /Length {data.Length} >>\nstream\n");
        byte[] suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n");
        return [.. prefix, .. data, .. suffix];
    }

    private static byte[] Deflate(byte[] plain)
    {
        using MemoryStream compressed = new();
        using (System.IO.Compression.ZLibStream deflater = new(compressed, System.IO.Compression.CompressionMode.Compress))
        {
            deflater.Write(plain);
        }

        return compressed.ToArray();
    }

    private static byte[] Covered(string policy) =>
        Encoding.ASCII.GetBytes($"%PDF-1.7\n{policy}\n%%EOF\n");

    private static byte[] Concat(byte[] covered, byte[] tail)
    {
        byte[] pdf = new byte[covered.Length + tail.Length];
        covered.CopyTo(pdf, 0);
        tail.CopyTo(pdf, covered.Length);
        return pdf;
    }
}
