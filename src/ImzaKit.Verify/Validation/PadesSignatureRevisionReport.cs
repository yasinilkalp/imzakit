namespace ImzaKit.Verify.Validation;

public sealed record PadesSignatureRevisionReport(
    int Index,
    string? FieldName,
    int CoveredRevision,
    int CoveredLength,
    int SubsequentByteCount,
    ValidationStatus ByteRangeStatus,
    ValidationStatus CryptographicStatus,
    ValidationStatus ModificationPolicyStatus,
    string? SignerCertificateSha256,
    string? SignatureLevel,
    IReadOnlyList<ValidationFinding> Findings);
