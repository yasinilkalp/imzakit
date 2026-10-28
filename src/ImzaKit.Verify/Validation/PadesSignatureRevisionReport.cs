using ImzaKit.Revocation.Models;

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
    IReadOnlyList<ValidationFinding> Findings)
{
    public ValidationStatus Status { get; init; } = ValidationStatus.Indeterminate;

    public ValidationStatus ChainStatus { get; init; } = ValidationStatus.Indeterminate;

    public ValidationStatus TrustStatus { get; init; } = ValidationStatus.Indeterminate;

    public ValidationStatus PolicyStatus { get; init; } = ValidationStatus.Indeterminate;

    public RevocationStatus? RevocationStatus { get; init; }
}
