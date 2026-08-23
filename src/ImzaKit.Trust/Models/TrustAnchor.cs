using ImzaKit.Certificate.Models;

namespace ImzaKit.Trust.Models;

public sealed class TrustAnchor
{
    private readonly IReadOnlyList<ValidationProfile> _profiles;

    public TrustAnchor(
        CertificateDescriptor certificate,
        IEnumerable<ValidationProfile> profiles,
        string? provenance = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(profiles);
        ValidationProfile[] copiedProfiles = profiles.Distinct().ToArray();
        if (copiedProfiles.Length == 0)
        {
            throw new ArgumentException("A trust anchor must enable at least one profile.", nameof(profiles));
        }

        Certificate = certificate;
        _profiles = Array.AsReadOnly(copiedProfiles);
        Provenance = string.IsNullOrWhiteSpace(provenance) ? null : provenance.Trim();
    }

    public CertificateDescriptor Certificate { get; }

    public IReadOnlyList<ValidationProfile> Profiles => _profiles;

    public string? Provenance { get; }
}
