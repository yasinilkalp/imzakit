namespace ImzaKit.XAdES;

public enum XadesStatus
{
    Passed,
    Failed,
    Indeterminate
}

public sealed record XadesValidationReport(
    XadesStatus Status,
    XadesPackaging Packaging,
    string SignatureLevel,
    string? SignerCertificateSha256,
    IReadOnlyList<string> Findings);
