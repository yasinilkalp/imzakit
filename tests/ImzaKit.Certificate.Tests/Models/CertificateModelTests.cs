using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Testing.Certificates;

namespace ImzaKit.Certificate.Tests.Models;

public sealed class CertificateModelTests
{
    [Fact]
    public void CertificateDescriptorCopiesDerAndDerivesStableIdentity()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        byte[] originalDer = pki.Leaf.Export(X509ContentType.Cert);
        byte[] callerOwnedDer = originalDer.ToArray();
        string expectedThumbprint = Convert.ToHexString(SHA256.HashData(originalDer));

        CertificateDescriptor descriptor = CertificateDescriptor.FromDer(
            callerOwnedDer,
            CertificateSource.Embedded);
        callerOwnedDer[0] ^= 0xff;
        byte[] exported = descriptor.ExportDer();
        exported[1] ^= 0xff;

        Assert.Equal(expectedThumbprint, descriptor.Sha256Thumbprint);
        Assert.Equal(originalDer, descriptor.ExportDer());
        Assert.Equal(CertificateSource.Embedded, descriptor.Source);
        Assert.Equal(pki.Leaf.Subject, descriptor.Subject);
        Assert.Equal(pki.Leaf.Issuer, descriptor.Issuer);
    }
}
