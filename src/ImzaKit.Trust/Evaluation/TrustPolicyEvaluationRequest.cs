using ImzaKit.Certificate.Models;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Evaluation;

public sealed record TrustPolicyEvaluationRequest
{
    public TrustPolicyEvaluationRequest(
        CertificateChainCandidate chain,
        ValidationProfile profile,
        TrustStoreSnapshot trustStore,
        CertificatePolicyCatalog policyCatalog,
        DateTimeOffset validationTimeUtc)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(trustStore);
        ArgumentNullException.ThrowIfNull(policyCatalog);
        if (validationTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Validation time must be UTC.", nameof(validationTimeUtc));
        }

        Chain = chain;
        Profile = profile;
        TrustStore = trustStore;
        PolicyCatalog = policyCatalog;
        ValidationTimeUtc = validationTimeUtc;
    }

    public CertificateChainCandidate Chain { get; }

    public ValidationProfile Profile { get; }

    public TrustStoreSnapshot TrustStore { get; }

    public CertificatePolicyCatalog PolicyCatalog { get; }

    public DateTimeOffset ValidationTimeUtc { get; }
}
