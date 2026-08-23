using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Models;
using ImzaKit.Testing.Certificates;

namespace ImzaKit.Certificate.Tests.Building;

public sealed class CertificateChainBuilderTests
{
    [Fact]
    public void BuildCreatesLeafToRootChainAndPrefersEmbeddedDuplicate()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        CertificateDescriptor leaf = Describe(pki.Leaf, CertificateSource.Embedded);
        CertificateDescriptor embeddedIntermediate = Describe(pki.Intermediate, CertificateSource.Embedded);
        CertificateDescriptor localIntermediate = Describe(pki.Intermediate, CertificateSource.Local);
        CertificateDescriptor root = Describe(pki.Root, CertificateSource.Local);

        CertificateChainBuildResult result = new CertificateChainBuilder().Build(
            new CertificateChainBuildRequest(
                leaf,
                [embeddedIntermediate],
                [localIntermediate, root]));

        Assert.Equal(CertificateChainStatus.Complete, result.Status);
        Assert.NotNull(result.Candidate);
        Assert.Equal(3, result.Candidate.Certificates.Count);
        Assert.Equal(leaf.Sha256Thumbprint, result.Candidate.Certificates[0].Sha256Thumbprint);
        Assert.Equal(CertificateSource.Embedded, result.Candidate.Certificates[1].Source);
        Assert.Equal(root.Sha256Thumbprint, result.Candidate.Certificates[2].Sha256Thumbprint);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void BuildReturnsIncompleteWhenIssuerIsUnavailable()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        CertificateChainBuildResult result = new CertificateChainBuilder().Build(
            new CertificateChainBuildRequest(
                Describe(pki.Leaf, CertificateSource.Embedded),
                [],
                [Describe(pki.Root, CertificateSource.Local)]));

        Assert.Equal(CertificateChainStatus.Incomplete, result.Status);
        Assert.NotNull(result.Candidate);
        Assert.Single(result.Candidate.Certificates);
        Assert.Contains("CertificateChainIncomplete", result.Findings);
    }

    [Fact]
    public void BuildRejectsChainThatExceedsConfiguredDepth()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        CertificateChainBuildResult result = new CertificateChainBuilder().Build(
            new CertificateChainBuildRequest(
                Describe(pki.Leaf, CertificateSource.Embedded),
                [Describe(pki.Intermediate, CertificateSource.Embedded)],
                [Describe(pki.Root, CertificateSource.Local)],
                maximumDepth: 2));

        Assert.Equal(CertificateChainStatus.Invalid, result.Status);
        Assert.Contains("CertificateChainDepthExceeded", result.Findings);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(33)]
    public void RequestRejectsUnsafeDepthLimits(int maximumDepth)
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        CertificateDescriptor leaf = Describe(pki.Leaf, CertificateSource.Embedded);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CertificateChainBuildRequest(leaf, [], [], maximumDepth));
    }

    private static CertificateDescriptor Describe(X509Certificate2 certificate, CertificateSource source) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), source);
}
