using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Validation;

public sealed record CertificateChainValidationRequest
{
    public CertificateChainValidationRequest(
        CertificateChainCandidate chain,
        DateTimeOffset validationTimeUtc)
    {
        ArgumentNullException.ThrowIfNull(chain);
        if (validationTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Validation time must be UTC.", nameof(validationTimeUtc));
        }

        Chain = chain;
        ValidationTimeUtc = validationTimeUtc;
    }

    public CertificateChainCandidate Chain { get; }

    public DateTimeOffset ValidationTimeUtc { get; }
}
