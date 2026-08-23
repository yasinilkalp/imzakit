using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Building;

public sealed class CertificateChainBuildRequest
{
    private readonly CertificateDescriptor[] _embedded;
    private readonly CertificateDescriptor[] _local;

    public CertificateChainBuildRequest(
        CertificateDescriptor leaf,
        IEnumerable<CertificateDescriptor> embedded,
        IEnumerable<CertificateDescriptor> local,
        int maximumDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(leaf);
        ArgumentNullException.ThrowIfNull(embedded);
        ArgumentNullException.ThrowIfNull(local);
        if (maximumDepth is < 2 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDepth), "Chain depth must be between 2 and 32.");
        }

        Leaf = leaf;
        _embedded = embedded.ToArray();
        _local = local.ToArray();
        MaximumDepth = maximumDepth;
    }

    public CertificateDescriptor Leaf { get; }

    public IReadOnlyList<CertificateDescriptor> Embedded => _embedded;

    public IReadOnlyList<CertificateDescriptor> Local => _local;

    public int MaximumDepth { get; }
}
