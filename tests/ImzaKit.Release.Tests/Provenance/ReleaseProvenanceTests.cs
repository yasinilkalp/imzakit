using System.Security.Cryptography;
using ImzaKit.Release.Provenance;

namespace ImzaKit.Release.Tests.Provenance;

public sealed class ReleaseProvenanceTests
{
    private static readonly byte[] Artifact = "imzakit-agent-win-x64"u8.ToArray();
    private static readonly byte[] Sbom = """{"bomFormat":"CycloneDX"}"""u8.ToArray();

    [Fact]
    public void ProvenanceBindsCommitArtifactAndSbomDigest()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ReleaseProvenance provenance = Create(releaseKey);

        Assert.True(ReleaseProvenanceFactory.Verify(provenance, releaseKey, SHA256.HashData(Artifact), SHA256.HashData(Sbom)));
        Assert.False(ReleaseProvenanceFactory.Verify(
            provenance,
            releaseKey,
            SHA256.HashData("tampered"u8.ToArray()),
            SHA256.HashData(Sbom)));
        Assert.False(ReleaseProvenanceFactory.Verify(
            provenance,
            releaseKey,
            SHA256.HashData(Artifact),
            SHA256.HashData("tampered"u8.ToArray())));
        Assert.Contains("0123456789abcdef0123456789abcdef01234567", provenance.GitCommit, StringComparison.Ordinal);
    }

    [Fact]
    public void PublishedJsonRoundTripsAndStillVerifies()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa publicKey = ECDsa.Create();
        publicKey.ImportFromPem(releaseKey.ExportSubjectPublicKeyInfoPem());
        ReleaseProvenance provenance = Create(releaseKey);

        ReleaseProvenance read = ReleaseProvenanceJson.Read(ReleaseProvenanceJson.Write(provenance));

        Assert.Equal(provenance, read);
        Assert.True(ReleaseProvenanceFactory.Verify(read, publicKey, SHA256.HashData(Artifact), SHA256.HashData(Sbom)));
        Assert.False(ReleaseProvenanceFactory.Verify(
            read with { GitCommit = "fedcba9876543210fedcba9876543210fedcba98" },
            publicKey,
            SHA256.HashData(Artifact),
            SHA256.HashData(Sbom)));
    }

    [Fact]
    public void MalformedJsonIsRejected()
    {
        InvalidDataException missing = Assert.Throws<InvalidDataException>(() =>
            ReleaseProvenanceJson.Read("""{"product":"ImzaKit"}"""));
        InvalidDataException invalid = Assert.Throws<InvalidDataException>(() =>
            ReleaseProvenanceJson.Read("not json"));

        Assert.Equal("IMZAKIT.RELEASE.PROVENANCE_MALFORMED", missing.Message);
        Assert.Equal("IMZAKIT.RELEASE.PROVENANCE_MALFORMED", invalid.Message);
    }

    private static ReleaseProvenance Create(ECDsa releaseKey) =>
        ReleaseProvenanceFactory.Create(
            product: "ImzaKit.Agent",
            version: "1.0.0-alpha.4",
            gitCommit: "0123456789abcdef0123456789abcdef01234567",
            artifactSha256: Convert.ToHexString(SHA256.HashData(Artifact)),
            sbomSha256: Convert.ToHexString(SHA256.HashData(Sbom)),
            builderId: "https://github.com/yasinilkalp/imzakit/.github/workflows/publish.yml",
            releaseKey);
}
