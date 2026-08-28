using ImzaKit.Release.Signing;

namespace ImzaKit.Release.Tests.Signing;

public sealed class ReleaseSigningPolicyTests
{
    private static readonly ReleaseSigningMaterials Empty = new(
        AuthenticodeCertificatePresent: false,
        ReleaseEcdsaKeyPresent: false);

    private static readonly ReleaseSigningMaterials Complete = new(
        AuthenticodeCertificatePresent: true,
        ReleaseEcdsaKeyPresent: true);

    [Fact]
    public void PrereleaseNugetMayPublishWithoutAuthenticodeWhenProvenanceKeyMissing()
    {
        ReleaseSigningPolicy.AssertCanPublish(
            "1.0.0-alpha.8",
            ReleaseArtifactKind.NugetPackage,
            Empty);
    }

    [Fact]
    public void AgentInstallerNeverPublishesWithoutAuthenticode()
    {
        InvalidOperationException prerelease = Assert.Throws<InvalidOperationException>(() =>
            ReleaseSigningPolicy.AssertCanPublish(
                "1.0.0-alpha.8",
                ReleaseArtifactKind.AgentPeOrInstaller,
                Empty));
        InvalidOperationException stable = Assert.Throws<InvalidOperationException>(() =>
            ReleaseSigningPolicy.AssertCanPublish(
                "1.0.0",
                ReleaseArtifactKind.AgentPeOrInstaller,
                new(AuthenticodeCertificatePresent: false, ReleaseEcdsaKeyPresent: true)));

        Assert.Equal("IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING", prerelease.Message);
        Assert.Equal("IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING", stable.Message);
    }

    [Fact]
    public void StableReleaseRequiresAuthenticodeAndProvenanceKey()
    {
        InvalidOperationException authenticode = Assert.Throws<InvalidOperationException>(() =>
            ReleaseSigningPolicy.AssertCanPublish(
                "1.0.0",
                ReleaseArtifactKind.NugetPackage,
                new(AuthenticodeCertificatePresent: false, ReleaseEcdsaKeyPresent: true)));
        InvalidOperationException provenance = Assert.Throws<InvalidOperationException>(() =>
            ReleaseSigningPolicy.AssertCanPublish(
                "1.0.0",
                ReleaseArtifactKind.NugetPackage,
                new(AuthenticodeCertificatePresent: true, ReleaseEcdsaKeyPresent: false)));

        Assert.Equal("IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING", authenticode.Message);
        Assert.Equal("IMZAKIT.RELEASE.PROVENANCE_KEY_MISSING", provenance.Message);
        ReleaseSigningPolicy.AssertCanPublish("1.0.0", ReleaseArtifactKind.NugetPackage, Complete);
    }

    [Fact]
    public void UpdateManifestAlwaysRequiresProvenanceKey()
    {
        InvalidOperationException missing = Assert.Throws<InvalidOperationException>(() =>
            ReleaseSigningPolicy.AssertCanPublish(
                "1.0.0-alpha.8",
                ReleaseArtifactKind.UpdateManifest,
                Empty));

        Assert.Equal("IMZAKIT.RELEASE.PROVENANCE_KEY_MISSING", missing.Message);
        ReleaseSigningPolicy.AssertCanPublish(
            "1.0.0-alpha.8",
            ReleaseArtifactKind.UpdateManifest,
            new(AuthenticodeCertificatePresent: false, ReleaseEcdsaKeyPresent: true));
    }
}
