using System.Security.Cryptography;
using ImzaKit.Release.Installer;
using ImzaKit.Release.Updates;

namespace ImzaKit.Release.Tests.Installer;

public sealed class AgentInstallerAndUpdateTests
{
    [Fact]
    public void PayloadIsLoopbackOnlyForWindowsX64AndArm64AndDoesNotShipVendorPkcs11()
    {
        AgentInstallerPayload payload = AgentInstallerLayout.Create(
            version: "1.0.0-alpha.4",
            rids: ["win-x64", "win-arm64"]);

        Assert.True(payload.AuthenticodeRequired);
        Assert.Equal(@"%ProgramFiles%\ImzaKit\Agent", payload.InstallDirectory);
        Assert.Contains("win-x64", payload.RuntimeIdentifiers);
        Assert.Contains("win-arm64", payload.RuntimeIdentifiers);
        Assert.True(payload.DisableDllSearchPathHijacking);
        Assert.All(payload.LoopbackBindAddresses, address => Assert.True(address is "127.0.0.1" or "::1"));
        Assert.Contains(@"%ProgramFiles%\AKIS", payload.Pkcs11AllowlistRoots);
        Assert.DoesNotContain(payload.Files, file => file.Contains("akisp11", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("sbom.cdx.json", payload.Files);
        Assert.Contains("provenance.json", payload.Files);
        Assert.Contains("NOTICE", payload.Files);
        Assert.Contains("LICENSE", payload.Files);
    }

    [Fact]
    public void SignedUpdateManifestRejectsTamperingAndAllowsRollbackToOlderVersion()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        AgentUpdateManifest manifest = new(
            Version: "1.0.0-alpha.5",
            RollbackVersion: "1.0.0-alpha.4",
            Artifacts:
            [
                new RidArtifact("win-x64", new string('A', 64)),
                new RidArtifact("win-arm64", new string('B', 64))
            ]);
        byte[] signed = AgentUpdateManifestCodec.Sign(manifest, releaseKey);

        Assert.True(AgentUpdateManifestCodec.TryVerify(signed, releaseKey, out AgentUpdateManifest? verified));
        Assert.Equal("1.0.0-alpha.4", verified!.RollbackVersion);
        Assert.True(AgentUpdateManifestCodec.CanRollback(verified, "1.0.0-alpha.5"));
        Assert.False(AgentUpdateManifestCodec.CanRollback(verified, "1.0.0-alpha.4"));

        signed[signed.Length / 2] ^= 0xFF;
        Assert.False(AgentUpdateManifestCodec.TryVerify(signed, releaseKey, out _));
    }
}
