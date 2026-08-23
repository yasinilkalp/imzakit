using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Building;

public sealed class CertificateChainBuilder : ICertificateChainBuilder
{
    public CertificateChainBuildResult Build(CertificateChainBuildRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        CertificateDescriptor[] candidates = request.Embedded
            .Concat(request.Local)
            .Where(certificate => certificate.Sha256Thumbprint != request.Leaf.Sha256Thumbprint)
            .GroupBy(certificate => certificate.Sha256Thumbprint, StringComparer.Ordinal)
            .Select(group => group
                .OrderBy(certificate => certificate.Source == CertificateSource.Embedded ? 0 : 1)
                .First())
            .ToArray();

        List<CertificateDescriptor> chain = [request.Leaf];
        HashSet<string> visited = new(StringComparer.Ordinal) { request.Leaf.Sha256Thumbprint };

        while (!IsSelfIssued(chain[^1]))
        {
            CertificateDescriptor current = chain[^1];
            CertificateDescriptor? issuer = candidates
                .Where(candidate => IsIssuerOf(candidate, current))
                .OrderBy(candidate => candidate.Source == CertificateSource.Embedded ? 0 : 1)
                .ThenBy(candidate => candidate.Sha256Thumbprint, StringComparer.Ordinal)
                .FirstOrDefault();

            if (issuer is null)
            {
                return new(
                    CertificateChainStatus.Incomplete,
                    new CertificateChainCandidate(chain),
                    ["CertificateChainIncomplete"]);
            }

            if (!visited.Add(issuer.Sha256Thumbprint))
            {
                return new(
                    CertificateChainStatus.Invalid,
                    new CertificateChainCandidate(chain),
                    ["CertificateChainLoop"]);
            }

            chain.Add(issuer);
            if (chain.Count > request.MaximumDepth)
            {
                return new(
                    CertificateChainStatus.Invalid,
                    new CertificateChainCandidate(chain),
                    ["CertificateChainDepthExceeded"]);
            }
        }

        return new(
            CertificateChainStatus.Complete,
            new CertificateChainCandidate(chain),
            Array.Empty<string>());
    }

    private static bool IsSelfIssued(CertificateDescriptor certificate) =>
        string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);

    private static bool IsIssuerOf(CertificateDescriptor candidate, CertificateDescriptor certificate)
    {
        if (!string.Equals(candidate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return certificate.AuthorityKeyIdentifier is null
            || candidate.SubjectKeyIdentifier is null
            || string.Equals(
                certificate.AuthorityKeyIdentifier,
                candidate.SubjectKeyIdentifier,
                StringComparison.OrdinalIgnoreCase);
    }
}
