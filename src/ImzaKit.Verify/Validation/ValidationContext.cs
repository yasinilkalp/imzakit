using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;
using ImzaKit.Trust.Models;

namespace ImzaKit.Verify.Validation;

public sealed class ValidationContext
{
    private readonly IReadOnlyList<CertificateDescriptor> _embeddedIntermediates;
    private readonly IReadOnlyList<CertificateDescriptor> _localIntermediates;

    public ValidationContext(
        ValidationProfile profile,
        DateTimeOffset validationTimeUtc,
        ValidationTimeSource validationTimeSource,
        TrustStoreSnapshot trustStore,
        CertificatePolicyCatalog policyCatalog,
        IEnumerable<CertificateDescriptor>? embeddedIntermediates = null,
        IEnumerable<CertificateDescriptor>? localIntermediates = null,
        RevocationEvidenceSet? revocationEvidence = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);
        ArgumentNullException.ThrowIfNull(policyCatalog);
        if (validationTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Validation time must be UTC.", nameof(validationTimeUtc));
        }

        Profile = profile;
        ValidationTimeUtc = validationTimeUtc;
        ValidationTimeSource = validationTimeSource;
        TrustStore = trustStore;
        PolicyCatalog = policyCatalog;
        _embeddedIntermediates = Array.AsReadOnly((embeddedIntermediates ?? []).ToArray());
        _localIntermediates = Array.AsReadOnly((localIntermediates ?? []).ToArray());
        RevocationEvidence = revocationEvidence ?? RevocationEvidenceSet.Empty;
    }

    public ValidationProfile Profile { get; }

    public DateTimeOffset ValidationTimeUtc { get; }

    public ValidationTimeSource ValidationTimeSource { get; }

    public TrustStoreSnapshot TrustStore { get; }

    public CertificatePolicyCatalog PolicyCatalog { get; }

    public IReadOnlyList<CertificateDescriptor> EmbeddedIntermediates => _embeddedIntermediates;

    public IReadOnlyList<CertificateDescriptor> LocalIntermediates => _localIntermediates;

    public RevocationEvidenceSet RevocationEvidence { get; }
}
