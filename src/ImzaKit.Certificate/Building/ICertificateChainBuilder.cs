using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Building;

public interface ICertificateChainBuilder
{
    CertificateChainBuildResult Build(CertificateChainBuildRequest request);
}
