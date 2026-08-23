namespace ImzaKit.Verify.Validation;

public sealed record PadesValidationReport(
    ValidationStatus Status,
    ValidationStatus ByteRangeStatus,
    ValidationStatus CryptographicStatus,
    ValidationStatus TrustStatus,
    string? SignerCertificateSha256,
    IReadOnlyList<ValidationFinding> Findings);
