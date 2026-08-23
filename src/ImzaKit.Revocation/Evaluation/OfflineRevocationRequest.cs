using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Evaluation;

public sealed record OfflineRevocationRequest
{
    public OfflineRevocationRequest(
        CertificateChainCandidate chain,
        RevocationEvidenceSet evidence,
        DateTimeOffset validationTimeUtc,
        TimeSpan freshnessTolerance)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(evidence);
        if (validationTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Validation time must be UTC.", nameof(validationTimeUtc));
        }

        if (freshnessTolerance < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(freshnessTolerance),
                "Freshness tolerance cannot be negative.");
        }

        Chain = chain;
        Evidence = evidence;
        ValidationTimeUtc = validationTimeUtc;
        FreshnessTolerance = freshnessTolerance;
    }

    public CertificateChainCandidate Chain { get; }

    public RevocationEvidenceSet Evidence { get; }

    public DateTimeOffset ValidationTimeUtc { get; }

    public TimeSpan FreshnessTolerance { get; }
}
