namespace ImzaKit.CAdES;

public enum CadesStatus
{
    Passed,
    Failed,
    Indeterminate
}

public sealed record CadesSignerReport(
    int Index,
    CadesStatus CryptographicStatus,
    string? SignerCertificateSha256,
    string SignatureLevel,
    IReadOnlyList<string> Findings);

public sealed record CadesValidationReport(
    CadesStatus Status,
    IReadOnlyList<CadesSignerReport> Signers);
