using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Evaluation;

public sealed record OfflineRevocationResult(
    RevocationStatus Status,
    IReadOnlyList<CertificateRevocationResult> Certificates);
