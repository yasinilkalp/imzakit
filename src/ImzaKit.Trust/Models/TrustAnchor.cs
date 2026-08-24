using ImzaKit.Certificate.Models;

namespace ImzaKit.Trust.Models;

public sealed class TrustAnchor
{
    private readonly IReadOnlyList<ValidationProfile> _profiles;

    public TrustAnchor(
        CertificateDescriptor certificate,
        IEnumerable<ValidationProfile> profiles,
        string? provenance = null,
        TrustAnchorRole role = TrustAnchorRole.Root)
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
        Role = role;
    }

    public CertificateDescriptor Certificate { get; }

    public IReadOnlyList<ValidationProfile> Profiles => _profiles;

    public string? Provenance { get; }

    public TrustAnchorRole Role { get; }
}
