namespace ImzaKit.Verify.Validation;

public sealed record SignatureReport(
    int Index,
    SignatureFormat Format,
    ValidationStatus IntegrityStatus,
    ValidationStatus CryptographicStatus,
    string? SignatureLevel,
    string? SignerCertificateSha256,
    IReadOnlyList<ValidationFinding> Findings)
{
    public string? FieldName { get; init; }

    public string? Packaging { get; init; }

    public int? CoveredRevision { get; init; }
}
