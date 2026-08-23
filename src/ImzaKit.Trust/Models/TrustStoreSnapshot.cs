namespace ImzaKit.Trust.Models;

public sealed class TrustStoreSnapshot
{
    private readonly IReadOnlyList<TrustAnchor> _anchors;

    public TrustStoreSnapshot(string version, IEnumerable<TrustAnchor> anchors)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new ArgumentException("Trust store version cannot be blank.", nameof(version));
        }

        ArgumentNullException.ThrowIfNull(anchors);
        TrustAnchor[] copiedAnchors = anchors.ToArray();
        if (copiedAnchors
            .GroupBy(anchor => anchor.Certificate.Sha256Thumbprint, StringComparer.Ordinal)
            .Any(group => group.Count() > 1))
        {
            throw new ArgumentException("Trust store cannot contain duplicate certificate anchors.", nameof(anchors));
        }

        Version = version.Trim();
        _anchors = Array.AsReadOnly(copiedAnchors);
    }

    public string Version { get; }

    public IReadOnlyList<TrustAnchor> Anchors => _anchors;
}
