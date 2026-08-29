using ImzaKit.Revocation.Models;

namespace ImzaKit.Verify.Validation;

public sealed record SignatureValidationReport(
    SignatureFormat Format,
    ValidationStatus Status,
    ValidationStatus IntegrityStatus,
    ValidationStatus CryptographicStatus,
    ValidationStatus ChainStatus,
    ValidationStatus TrustStatus,
    ValidationStatus PolicyStatus,
    RevocationStatus? RevocationStatus,
    IReadOnlyList<SignatureReport> Signatures,
    IReadOnlyList<ValidationFinding> Findings)
{
    public DateTimeOffset? ValidationTime { get; init; }

    public ValidationTimeSource? ValidationTimeSource { get; init; }

    public string? TrustStoreVersion { get; init; }

    public string? PolicyCatalogVersion { get; init; }

    public IReadOnlyList<RevocationEvidenceSource> EvidenceSources { get; init; } =
        Array.Empty<RevocationEvidenceSource>();
}
