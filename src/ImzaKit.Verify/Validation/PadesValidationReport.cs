using ImzaKit.Revocation.Models;
using ImzaKit.Trust.Models;

namespace ImzaKit.Verify.Validation;

public sealed record PadesValidationReport(
    ValidationStatus Status,
    ValidationStatus ByteRangeStatus,
    ValidationStatus CryptographicStatus,
    ValidationStatus TrustStatus,
    string? SignerCertificateSha256,
    IReadOnlyList<ValidationFinding> Findings)
{
    public ValidationStatus ChainStatus { get; init; } = ValidationStatus.Indeterminate;

    public ValidationStatus PolicyStatus { get; init; } = ValidationStatus.Indeterminate;

    public RevocationStatus? RevocationStatus { get; init; }

    public DateTimeOffset? ValidationTime { get; init; }

    public ValidationTimeSource? ValidationTimeSource { get; init; }

    public ValidationProfile? ValidationProfile { get; init; }

    public string? TrustStoreVersion { get; init; }

    public string? PolicyCatalogVersion { get; init; }

    public IReadOnlyList<RevocationEvidenceSource> EvidenceSources { get; init; } =
        Array.Empty<RevocationEvidenceSource>();

    public string? SignatureLevel { get; init; }

    public ValidationStatus ModificationPolicyStatus { get; init; } = ValidationStatus.Indeterminate;
}
