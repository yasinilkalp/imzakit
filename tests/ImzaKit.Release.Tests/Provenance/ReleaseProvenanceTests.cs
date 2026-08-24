using System.Security.Cryptography;
using ImzaKit.Release.Provenance;

namespace ImzaKit.Release.Tests.Provenance;

public sealed class ReleaseProvenanceTests
{
    [Fact]
    public void ProvenanceBindsCommitAndArtifactDigest()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] artifact = "imzakit-agent-win-x64"u8.ToArray();
        ReleaseProvenance provenance = ReleaseProvenanceFactory.Create(
            product: "ImzaKit.Agent",
            version: "1.0.0-alpha.4",
            gitCommit: "0123456789abcdef0123456789abcdef01234567",
            artifactSha256: Convert.ToHexString(SHA256.HashData(artifact)),
            builderId: "https://github.com/yasinilkalp/imzakit/.github/workflows/publish.yml",
            releaseKey);

        Assert.True(ReleaseProvenanceFactory.Verify(provenance, releaseKey, SHA256.HashData(artifact)));
        Assert.False(ReleaseProvenanceFactory.Verify(provenance, releaseKey, SHA256.HashData("tampered"u8.ToArray())));
        Assert.Contains("0123456789abcdef0123456789abcdef01234567", provenance.GitCommit, StringComparison.Ordinal);
    }
}
