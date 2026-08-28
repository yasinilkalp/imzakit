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

        PdfCadesReadStatus status = PdfCadesSignatureReader.TryRead(pdf, out long[] byteRange, out byte[] cmsDer, out byte[] signedBytes);
        if (status == PdfCadesReadStatus.NotFound)
        {
            return new(
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                null,
                [new("SignatureNotFound", "No PDF signature ByteRange was found.")]);
        }

        if (status == PdfCadesReadStatus.InvalidByteRange)
        {
            return FailedByteRange("InvalidByteRange", "The PDF signature ByteRange is malformed or outside the document.");
        }

        if (status == PdfCadesReadStatus.InvalidCms)
        {
            return FailedCrypto("InvalidCms", "The signature container is not valid DER-encoded CMS data.");
        }

        try
        {
            SignedCms cms = new(new ContentInfo(signedBytes), detached: true);
            cms.Decode(cmsDer);
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

            int coveredLength = checked((int)(byteRange[2] + byteRange[3]));
            PdfModificationPolicyEvaluation modification = PdfModificationPolicyEvaluator.Evaluate(pdf, coveredLength);
            foreach (PdfModificationPolicyViolation violation in modification.Violations)
            {
                findings.Add(new(violation.Code, violation.Message));
            }

            bool modificationFailed = modification.Violations.Count > 0;
            return new(
                modificationFailed ? ValidationStatus.Failed : ValidationStatus.Indeterminate,
                ValidationStatus.Passed,
                ValidationStatus.Passed,
                ValidationStatus.Indeterminate,
                fingerprint,
                findings)
            {
                SignatureLevel = PdfCadesSignatureReader.DetectLevel(pdf, cms),
                ModificationPolicyStatus = modificationFailed ? ValidationStatus.Failed : ValidationStatus.Passed
            };
        }
        catch (CryptographicException)
        {
            return FailedCrypto("CmsSignatureInvalid", "The CMS signature does not match the signed PDF bytes.");
        }
        catch (FormatException)
        {
            return FailedByteRange("InvalidByteRange", "The CMS container is not valid hexadecimal data.");
        }
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

    private static PadesValidationReport FailedByteRange(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Failed, ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate, null, [new(code, message)]);

    private static PadesValidationReport FailedCrypto(string code, string message) =>
        new(ValidationStatus.Failed, ValidationStatus.Passed, ValidationStatus.Failed,
            ValidationStatus.Indeterminate, null, [new(code, message)]);
}
