using System.Security.Cryptography;
using ImzaKit.Release.Provenance;
using ImzaKit.Release.Sbom;
using ImzaKit.Release.Signing;

namespace ImzaKit.Release.Tests.Signing;

public sealed class ReleasePublishBundleTests
{
    [Fact]
    public void BundleWritesCycloneDxSbomAndSignedProvenanceForArtifact()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] artifact = "imzakit-nupkg-bytes"u8.ToArray();
        SoftwareComponent[] components =
        [
            new("ImzaKit", "1.0.0-alpha.8", "Apache-2.0", "pkg:nuget/ImzaKit@1.0.0-alpha.8"),
            new("BouncyCastle.Cryptography", "2.7.0", "MIT", "pkg:nuget/BouncyCastle.Cryptography@2.7.0")
        ];

        ReleasePublishBundle bundle = ReleasePublishBundleFactory.Create(
            product: "ImzaKit",
            version: "1.0.0-alpha.8",
            gitCommit: "0123456789abcdef0123456789abcdef01234567",
            artifact: artifact,
            components: components,
            builderId: "https://github.com/yasinilkalp/imzakit/.github/workflows/publish.yml",
            releaseKey: releaseKey);

        Assert.Contains("CycloneDX", bundle.SbomJson, StringComparison.Ordinal);
        Assert.Contains("1.6", bundle.SbomJson, StringComparison.Ordinal);
        Assert.Contains("BouncyCastle.Cryptography", bundle.SbomJson, StringComparison.Ordinal);
        Assert.NotNull(bundle.Provenance);
        Assert.True(ReleaseProvenanceFactory.Verify(
            bundle.Provenance,
            releaseKey,
            SHA256.HashData(artifact)));
    }

    [Fact]
    public void PrereleaseBundleOmitsProvenanceWhenReleaseKeyIsAbsent()
    {
        ReleasePublishBundle bundle = ReleasePublishBundleFactory.Create(
            product: "ImzaKit",
            version: "1.0.0-alpha.8",
            gitCommit: "0123456789abcdef0123456789abcdef01234567",
            artifact: "imzakit-nupkg-bytes"u8.ToArray(),
            components:
            [
                new("ImzaKit", "1.0.0-alpha.8", "Apache-2.0", "pkg:nuget/ImzaKit@1.0.0-alpha.8")
            ],
            builderId: "https://github.com/yasinilkalp/imzakit/.github/workflows/publish.yml",
            releaseKey: null);

        Assert.Contains("CycloneDX", bundle.SbomJson, StringComparison.Ordinal);
        Assert.Null(bundle.Provenance);
    }
}
