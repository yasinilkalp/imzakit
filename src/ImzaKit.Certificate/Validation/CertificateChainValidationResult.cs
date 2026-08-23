using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Validation;

public sealed record CertificateChainValidationResult(
    CertificateChainStatus Status,
    IReadOnlyList<CertificateValidationFailure> Failures);
