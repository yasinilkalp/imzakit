using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using ImzaKit.PAdES.Policy;

namespace ImzaKit.Verify.Validation;

public static class PadesValidator
{
    private const int MaximumPdfSize = 32 * 1024 * 1024;

    public static PadesValidationReport Validate(ReadOnlySpan<byte> pdf)
    {
        if (!pdf.StartsWith("%PDF-"u8))
        {
            return FailedByteRange("UnsupportedPdf", "The input does not have a supported PDF header.");
        }

        if (pdf.Length > MaximumPdfSize)
        {
            return FailedByteRange("PdfTooLarge", "PDF exceeds the verification size limit.");
        }

        IReadOnlyList<PdfCadesLocatedSignature> located = PdfCadesSignatureReader.ReadAll(pdf);
        if (located.Count == 0)
        {
            return new(
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                null,
                [new("SignatureNotFound", "No PDF signature ByteRange was found.")]);
        }

        List<PadesSignatureRevisionReport> signatures = [];
        PadesValidationReport? last = null;
        for (int index = 0; index < located.Count; index++)
        {
            last = Evaluate(pdf, located[index], out PadesSignatureRevisionReport revision, index + 1);
            signatures.Add(revision);
        }

        PadesValidationReport combined = last! with { Signatures = signatures };
        if (signatures.Any(signature =>
                signature.ByteRangeStatus == ValidationStatus.Failed
                || signature.CryptographicStatus == ValidationStatus.Failed
                || signature.ModificationPolicyStatus == ValidationStatus.Failed))
        {
            combined = combined with
            {
                Status = ValidationStatus.Failed,
                ByteRangeStatus = signatures.Any(signature => signature.ByteRangeStatus == ValidationStatus.Failed)
                    ? ValidationStatus.Failed
                    : combined.ByteRangeStatus,
                CryptographicStatus = signatures.Any(signature => signature.CryptographicStatus == ValidationStatus.Failed)
                    ? ValidationStatus.Failed
                    : combined.CryptographicStatus,
                ModificationPolicyStatus = signatures.Any(signature => signature.ModificationPolicyStatus == ValidationStatus.Failed)
                    ? ValidationStatus.Failed
                    : combined.ModificationPolicyStatus
            };
        }

        return combined;
    }

    public static PadesValidationReport Validate(ReadOnlySpan<byte> pdf, ValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        PadesValidationService service = new(
            new ImzaKit.Certificate.Building.CertificateChainBuilder(),
            new ImzaKit.Certificate.Validation.CertificateChainValidator(),
            new ImzaKit.Trust.Evaluation.TrustPolicyEvaluator(),
            new ImzaKit.Revocation.Evaluation.OfflineRevocationEvaluator(
                new ImzaKit.Revocation.Parsing.BouncyCastleRevocationEvidenceParser()),
            new ValidationDecisionEngine());
        return service.Validate(pdf, context);
    }

    private static PadesValidationReport Evaluate(
        ReadOnlySpan<byte> pdf,
        PdfCadesLocatedSignature located,
        out PadesSignatureRevisionReport revision,
        int index)
    {
        int coveredRevision = PdfCadesSignatureReader.CountCoveredRevisions(pdf, Math.Min(located.CoveredLength, pdf.Length));
        int subsequent = Math.Max(0, pdf.Length - located.CoveredLength);
        if (located.Status == PdfCadesReadStatus.InvalidByteRange)
        {
            PadesValidationReport failed = FailedByteRange(
                "InvalidByteRange",
                "The PDF signature ByteRange is malformed or outside the document.");
            revision = ToRevision(
                index,
                located,
                coveredRevision,
                subsequent,
                failed.ByteRangeStatus,
                failed.CryptographicStatus,
                ValidationStatus.Indeterminate,
                null,
                null,
                failed.Findings);
            return failed;
        }

        if (located.Status == PdfCadesReadStatus.InvalidCms)
        {
            PadesValidationReport failed = FailedCrypto("InvalidCms", "The signature container is not valid DER-encoded CMS data.");
            revision = ToRevision(
                index,
                located,
                coveredRevision,
                subsequent,
                ValidationStatus.Passed,
                failed.CryptographicStatus,
                ValidationStatus.Indeterminate,
                null,
                null,
                failed.Findings);
            return failed;
        }

        try
        {
            SignedCms cms = new(new ContentInfo(located.SignedBytes), detached: true);
            cms.Decode(located.Cms);
            cms.CheckSignature(verifySignatureOnly: true);
            System.Security.Cryptography.X509Certificates.X509Certificate2? certificate =
                cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
            string? fingerprint = certificate is null
                ? null
                : Convert.ToHexString(SHA256.HashData(certificate.RawData));
            List<ValidationFinding> findings = [new("TrustNotEvaluated", "Certificate trust and revocation were not evaluated.")];
            if (fingerprint is null)
            {
                findings.Insert(0, new("SignerCertificateMissing", "The signer certificate is not embedded in the CMS container."));
            }

            PdfModificationPolicyEvaluation modification = PdfModificationPolicyEvaluator.Evaluate(pdf, located.CoveredLength);
            foreach (PdfModificationPolicyViolation violation in modification.Violations)
            {
                findings.Add(new(violation.Code, violation.Message));
            }

            bool modificationFailed = modification.Violations.Count > 0;
            string? level = PdfCadesSignatureReader.DetectLevel(pdf, cms);
            PadesValidationReport passed = new(
                modificationFailed ? ValidationStatus.Failed : ValidationStatus.Indeterminate,
                ValidationStatus.Passed,
                ValidationStatus.Passed,
                ValidationStatus.Indeterminate,
                fingerprint,
                findings)
            {
                SignatureLevel = level,
                ModificationPolicyStatus = modificationFailed ? ValidationStatus.Failed : ValidationStatus.Passed
            };
            revision = ToRevision(
                index,
                located,
                coveredRevision,
                subsequent,
                ValidationStatus.Passed,
                ValidationStatus.Passed,
                passed.ModificationPolicyStatus,
                fingerprint,
                level,
                [.. findings.Where(finding => finding.Code != "TrustNotEvaluated")]);
            return passed;
        }
        catch (CryptographicException)
        {
            PadesValidationReport failed = FailedCrypto("CmsSignatureInvalid", "The CMS signature does not match the signed PDF bytes.");
            revision = ToRevision(
                index,
                located,
                coveredRevision,
                subsequent,
                ValidationStatus.Passed,
                ValidationStatus.Failed,
                ValidationStatus.Indeterminate,
                null,
                null,
                failed.Findings);
            return failed;
        }
        catch (FormatException)
        {
            PadesValidationReport failed = FailedByteRange("InvalidByteRange", "The CMS container is not valid hexadecimal data.");
            revision = ToRevision(
                index,
                located,
                coveredRevision,
                subsequent,
                ValidationStatus.Failed,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                null,
                null,
                failed.Findings);
            return failed;
        }
    }

    private static PadesSignatureRevisionReport ToRevision(
        int index,
        PdfCadesLocatedSignature located,
        int coveredRevision,
        int subsequentByteCount,
        ValidationStatus byteRangeStatus,
        ValidationStatus cryptographicStatus,
        ValidationStatus modificationPolicyStatus,
        string? fingerprint,
        string? signatureLevel,
        IReadOnlyList<ValidationFinding> findings) =>
        new(
            index,
            located.FieldName,
            coveredRevision,
            located.CoveredLength,
            subsequentByteCount,
            byteRangeStatus,
            cryptographicStatus,
            modificationPolicyStatus,
            fingerprint,
            signatureLevel,
            findings);

    private static PadesValidationReport FailedByteRange(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Failed, ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate, null, [new(code, message)]);

    private static PadesValidationReport FailedCrypto(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Passed, ValidationStatus.Failed,
            ValidationStatus.Indeterminate, null, [new(code, message)]);
}
