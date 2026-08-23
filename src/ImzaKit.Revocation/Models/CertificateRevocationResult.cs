namespace ImzaKit.Revocation.Models;

public sealed record CertificateRevocationResult(
    string CertificateSha256,
    RevocationStatus Status,
    RevocationEvidenceSource? EvidenceSource,
    RevocationEvidenceType? EvidenceType,
    DateTimeOffset? ThisUpdateUtc,
    DateTimeOffset? NextUpdateUtc,
    IReadOnlyList<string> Findings);
