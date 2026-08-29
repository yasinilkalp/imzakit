using ImzaKit.ASiC;
using ImzaKit.CAdES;
using ImzaKit.Revocation.Models;
using ImzaKit.XAdES;

namespace ImzaKit.Verify.Validation;

public static class SignatureValidationReportMapper
{
    private static readonly ValidationFinding TrustNotEvaluated = new(
        "TrustNotEvaluated",
        "Certificate trust and revocation were not evaluated.");

    public static SignatureValidationReport FromPades(PadesValidationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        IReadOnlyList<SignatureReport> signatures = report.Signatures.Count == 0
            ? []
            : [.. report.Signatures.Select(ToSignature)];
        return new(
            SignatureFormat.Pades,
            report.Status,
            report.ByteRangeStatus,
            report.CryptographicStatus,
            report.ChainStatus,
            report.TrustStatus,
            report.PolicyStatus,
            report.RevocationStatus,
            signatures,
            report.Findings)
        {
            ValidationTime = report.ValidationTime,
            ValidationTimeSource = report.ValidationTimeSource,
            TrustStoreVersion = report.TrustStoreVersion,
            PolicyCatalogVersion = report.PolicyCatalogVersion,
            EvidenceSources = report.EvidenceSources
        };
    }

    public static SignatureValidationReport FromCades(CadesValidationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        List<SignatureReport> signatures = [];
        List<ValidationFinding> findings = [];
        bool integrityFailed = report.Signers.Count == 0;
        bool cryptoFailed = false;
        bool cryptoPassed = false;
        foreach (CadesSignerReport signer in report.Signers)
        {
            ValidationFinding[] signerFindings = [.. signer.Findings.Select(ToFinding)];
            ValidationStatus integrity = signer.Findings.Any(IsIntegrityCode)
                ? ValidationStatus.Failed
                : ValidationStatus.Passed;
            ValidationStatus crypto = Map(signer.CryptographicStatus);
            integrityFailed |= integrity == ValidationStatus.Failed;
            cryptoFailed |= crypto == ValidationStatus.Failed;
            cryptoPassed |= crypto == ValidationStatus.Passed;
            signatures.Add(new(
                signer.Index,
                SignatureFormat.Cades,
                integrity,
                crypto,
                signer.SignatureLevel,
                signer.SignerCertificateSha256,
                signerFindings));
            findings.AddRange(signerFindings);
        }

        if (integrityFailed)
        {
            return Failed(
                SignatureFormat.Cades,
                ValidationStatus.Failed,
                cryptoFailed ? ValidationStatus.Failed : ValidationStatus.Indeterminate,
                signatures,
                findings);
        }

        if (cryptoFailed || report.Status == CadesStatus.Failed)
        {
            return Failed(
                SignatureFormat.Cades,
                ValidationStatus.Passed,
                ValidationStatus.Failed,
                signatures,
                findings);
        }

        return UnevaluatedTrust(
            SignatureFormat.Cades,
            ValidationStatus.Passed,
            cryptoPassed ? ValidationStatus.Passed : ValidationStatus.Indeterminate,
            signatures,
            findings);
    }

    public static SignatureValidationReport FromXades(XadesValidationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        ValidationFinding[] mappedFindings = [.. report.Findings.Select(ToFinding)];
        bool integrityFailed = report.Findings.Any(IsIntegrityCode);
        ValidationStatus integrity = integrityFailed ? ValidationStatus.Failed : ValidationStatus.Passed;
        ValidationStatus crypto = report.Status == XadesStatus.Failed && !integrityFailed
            ? ValidationStatus.Failed
            : report.Status == XadesStatus.Passed
                ? ValidationStatus.Passed
                : ValidationStatus.Indeterminate;
        SignatureReport signature = new(
            1,
            SignatureFormat.Xades,
            integrity,
            crypto,
            report.SignatureLevel,
            report.SignerCertificateSha256,
            mappedFindings)
        {
            Packaging = report.Packaging.ToString()
        };

        if (integrityFailed || report.Status == XadesStatus.Failed)
        {
            return Failed(SignatureFormat.Xades, integrity, crypto, [signature], mappedFindings);
        }

        return UnevaluatedTrust(
            SignatureFormat.Xades,
            ValidationStatus.Passed,
            ValidationStatus.Passed,
            [signature],
            mappedFindings);
    }

    public static SignatureValidationReport FromAsic(AsicContainer container)
    {
        ArgumentNullException.ThrowIfNull(container);
        if (container.Profile != AsicProfile.Simple || container.DataObjects.Count != 1)
        {
            return new(
                SignatureFormat.Asic,
                ValidationStatus.Indeterminate,
                ValidationStatus.Passed,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                RevocationStatus.Unavailable,
                [],
                [new(
                    "AsicExtendedBindingNotEvaluated",
                    "ASiC-E signature-to-data binding is not evaluated in the common report.")]);
        }

        byte[] content = container.DataObjects[0].Content;
        List<SignatureReport> signatures = [];
        List<ValidationFinding> findings = [];
        bool failed = false;
        bool cryptoFailed = false;
        bool cryptoPassed = false;
        int index = 1;
        foreach (AsicSignatureFile file in container.Signatures)
        {
            SignatureValidationReport inner = file.FileName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
                ? FromXades(XadesValidator.Validate(file.Content, content))
                : FromCades(CadesValidator.ValidateDetached(file.Content, content));
            failed |= inner.Status == ValidationStatus.Failed;
            cryptoFailed |= inner.CryptographicStatus == ValidationStatus.Failed;
            cryptoPassed |= inner.CryptographicStatus == ValidationStatus.Passed;
            foreach (SignatureReport signature in inner.Signatures)
            {
                signatures.Add(signature with { Index = index++ });
            }

            findings.AddRange(inner.Findings.Where(finding => finding.Code != TrustNotEvaluated.Code));
        }

        ValidationStatus crypto = cryptoFailed
            ? ValidationStatus.Failed
            : cryptoPassed ? ValidationStatus.Passed : ValidationStatus.Indeterminate;
        if (failed)
        {
            return Failed(SignatureFormat.Asic, ValidationStatus.Passed, crypto, signatures, findings);
        }

        return UnevaluatedTrust(
            SignatureFormat.Asic,
            ValidationStatus.Passed,
            crypto,
            signatures,
            findings);
    }

    private static SignatureReport ToSignature(PadesSignatureRevisionReport revision) =>
        new(
            revision.Index,
            SignatureFormat.Pades,
            revision.ByteRangeStatus,
            revision.CryptographicStatus,
            revision.SignatureLevel,
            revision.SignerCertificateSha256,
            revision.Findings)
        {
            FieldName = revision.FieldName,
            CoveredRevision = revision.CoveredRevision
        };

    private static SignatureValidationReport Failed(
        SignatureFormat format,
        ValidationStatus integrity,
        ValidationStatus crypto,
        IReadOnlyList<SignatureReport> signatures,
        IReadOnlyList<ValidationFinding> findings) =>
        new(
            format,
            ValidationStatus.Failed,
            integrity,
            crypto,
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            RevocationStatus.Unavailable,
            signatures,
            findings);

    private static SignatureValidationReport UnevaluatedTrust(
        SignatureFormat format,
        ValidationStatus integrity,
        ValidationStatus crypto,
        IReadOnlyList<SignatureReport> signatures,
        IReadOnlyList<ValidationFinding> findings) =>
        new(
            format,
            ValidationStatus.Indeterminate,
            integrity,
            crypto,
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            RevocationStatus.Unavailable,
            signatures,
            [.. findings, TrustNotEvaluated]);

    private static ValidationFinding ToFinding(string code) => new(code, code);

    private static ValidationStatus Map(CadesStatus status) => status switch
    {
        CadesStatus.Passed => ValidationStatus.Passed,
        CadesStatus.Failed => ValidationStatus.Failed,
        _ => ValidationStatus.Indeterminate
    };

    private static bool IsIntegrityCode(string code) => code is
        "InvalidCms" or
        "InvalidXml" or
        "SignatureMissing" or
        "DetachedContentMissing" or
        "InvalidSignatureXml" or
        "UnsupportedPdf" or
        "PdfTooLarge" or
        "InvalidByteRange" or
        "CanonicalizationNotAllowed" or
        "SignatureMethodNotAllowed" or
        "ExternalUriDereferenceDisabled" or
        "DigestMethodNotAllowed" or
        "TransformNotAllowed";
}
