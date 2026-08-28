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
