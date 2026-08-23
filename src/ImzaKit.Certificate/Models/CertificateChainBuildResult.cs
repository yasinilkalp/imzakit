namespace ImzaKit.Certificate.Models;

public sealed record CertificateChainBuildResult(
    CertificateChainStatus Status,
    CertificateChainCandidate? Candidate,
    IReadOnlyList<string> Findings);
