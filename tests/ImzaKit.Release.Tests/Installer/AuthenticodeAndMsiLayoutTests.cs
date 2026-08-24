using ImzaKit.Release.Installer;

namespace ImzaKit.Release.Tests.Installer;

public sealed class AuthenticodeAndMsiLayoutTests
{
    [Fact]
    public void UnsignedPeFailsAuthenticodeGateWhenRequired()
    {
        byte[] unsigned = CreateMinimalPe(hasSecurityDirectory: false);
        Assert.False(AuthenticodePeSignature.HasEmbeddedSignature(unsigned));
        Assert.Throws<InvalidOperationException>(() =>
            AuthenticodeGate.Require(unsigned, required: true));
        AuthenticodeGate.Require(unsigned, required: false);
    }

    [Fact]
    public void PeWithSecurityDirectoryPassesStructuralAuthenticodePresenceCheck()
    {
        byte[] signed = CreateMinimalPe(hasSecurityDirectory: true);
        Assert.True(AuthenticodePeSignature.HasEmbeddedSignature(signed));
        AuthenticodeGate.Require(signed, required: true);
    }

    [Fact]
    public void WixSourceInstallsToProgramFilesExcludesVendorDllAndRequiresAuthenticode()
    {
        AgentInstallerPayload payload = AgentInstallerLayout.Create("1.0.0-alpha.6", ["win-x64", "win-arm64"]);
        string wxs = AgentMsiDocument.CreateWixSource(payload);

        Assert.Contains(@"ProgramFiles64Folder", wxs, StringComparison.Ordinal);
        Assert.Contains(@"ImzaKit", wxs, StringComparison.Ordinal);
        Assert.Contains("win-x64", wxs, StringComparison.Ordinal);
        Assert.Contains("win-arm64", wxs, StringComparison.Ordinal);
        Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AuthenticodeRequired", wxs, StringComparison.Ordinal);
        Assert.Contains("127.0.0.1", wxs, StringComparison.Ordinal);
    }

    private static byte[] CreateMinimalPe(bool hasSecurityDirectory)
    {
        byte[] pe = new byte[512];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        BitConverter.TryWriteBytes(pe.AsSpan(0x3C), 0x80);
        pe[0x80] = (byte)'P';
        pe[0x81] = (byte)'E';
        pe[0x82] = 0;
        pe[0x83] = 0;
        BitConverter.TryWriteBytes(pe.AsSpan(0x84), (ushort)0x8664);
        pe[0x80 + 24] = 0x0B;
        pe[0x80 + 24 + 1] = 0x02;
        int optionalHeader = 0x80 + 24;
        int dataDirectories = optionalHeader + 112;
        if (hasSecurityDirectory)
        {
            BitConverter.TryWriteBytes(pe.AsSpan(dataDirectories + (4 * 8)), 0x200);
            BitConverter.TryWriteBytes(pe.AsSpan(dataDirectories + (4 * 8) + 4), 16);
        }

        return pe;
    }
}
