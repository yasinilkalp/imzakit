namespace ImzaKit.Certificate.Models;

public sealed class CertificateChainCandidate
{
    private readonly CertificateDescriptor[] _certificates;

    public CertificateChainCandidate(IEnumerable<CertificateDescriptor> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        _certificates = certificates.ToArray();
        if (_certificates.Length == 0)
        {
            throw new ArgumentException("A certificate chain cannot be empty.", nameof(certificates));
        }
    }

    public IReadOnlyList<CertificateDescriptor> Certificates => _certificates;
}
