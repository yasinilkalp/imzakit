using ImzaKit.Release.Installer;

namespace ImzaKit.Release.Tests.Installer;

public sealed class DesktopInstallerAndUpdateTests
{
    [Fact]
    public void PayloadInstallsToProgramFilesDesktopWithoutVendorPkcs11()
    {
        DesktopInstallerPayload payload = DesktopInstallerLayout.Create(
            version: "1.0.0-alpha.13",
            rids: ["win-x64", "win-arm64"]);

        Assert.True(payload.AuthenticodeRequired);
        Assert.Equal(@"%ProgramFiles%\ImzaKit\Desktop", payload.InstallDirectory);
        Assert.Contains("win-x64", payload.RuntimeIdentifiers);
        Assert.Contains("win-arm64", payload.RuntimeIdentifiers);
        Assert.True(payload.DisableDllSearchPathHijacking);
        Assert.Contains(@"%ProgramFiles%\AKIS", payload.Pkcs11AllowlistRoots);
        Assert.Equal(
            [
                @"%ProgramFiles%\SafeNet\Authentication\SAC\x64",
                @"%ProgramFiles%\Thales\SafeNet Authentication Client"
            ],
            payload.EtokenPkcs11AllowlistRoots);
        Assert.DoesNotContain(payload.Files, file => file.Contains("akisp11", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(payload.Files, file => file.Contains("etpkcs11", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("ImzaKit.Hosts.Desktop.App.exe", payload.Files);
        Assert.Contains("sbom.cdx.json", payload.Files);
        Assert.Contains("NOTICE", payload.Files);
    }

    [Fact]
    public void WixSourceExcludesVendorDllAndRequiresAuthenticode()
    {
        DesktopInstallerPayload payload = DesktopInstallerLayout.Create("1.0.0-alpha.14", ["win-x64"]);
        string harvest = Path.Combine("artifacts", "desktop-publish");
        string wxs = DesktopMsiDocument.CreateWixSource(payload, harvest);

        Assert.Contains(@"ProgramFiles64Folder", wxs, StringComparison.Ordinal);
        Assert.Contains("Desktop", wxs, StringComparison.Ordinal);
        Assert.Contains("win-x64", wxs, StringComparison.Ordinal);
        Assert.Contains(@"Version=""1.0.14""", wxs, StringComparison.Ordinal);
        Assert.Contains(@"UpgradeCode=""E1B47A62-9C3D-4F80-A6D1-5E8C2B9F0147""", wxs, StringComparison.Ordinal);
        Assert.DoesNotContain("1.0.0.alpha", wxs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("etpkcs11.dll", wxs, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AuthenticodeRequired", wxs, StringComparison.Ordinal);
        Assert.Contains(@"SafeNet\Authentication\SAC\x64", wxs, StringComparison.Ordinal);
        Assert.Contains(Path.Combine(harvest, "ImzaKit.Hosts.Desktop.App.exe"), wxs, StringComparison.Ordinal);
    }

    [Fact]
    public void WixSourceRejectsEmptyHarvestDirectory()
    {
        DesktopInstallerPayload payload = DesktopInstallerLayout.Create("1.0.0-alpha.14", ["win-x64"]);
        Assert.Throws<ArgumentException>(() => DesktopMsiDocument.CreateWixSource(payload, " "));
    }

    [Fact]
    public void BurnBundleWrapsMsiAsWinX64SetupExe()
    {
        string wxs = DesktopBurnDocument.CreateWixSource("1.0.0-alpha.14", "ImzaKit.Desktop.msi");
        Assert.Equal("ImzaKit.Desktop-win-x64.setup.exe", DesktopBurnDocument.SetupExeFileName);
        Assert.Contains(@"Version=""1.0.14""", wxs, StringComparison.Ordinal);
        Assert.Contains("ImzaKit Desktop 1.0.0-alpha.14", wxs, StringComparison.Ordinal);
        Assert.Contains("ImzaKit.Desktop.msi", wxs, StringComparison.Ordinal);
        Assert.Contains("B7E4C1A2-8F93-4D6E-9B10-2C5A7E8D4F31", wxs, StringComparison.Ordinal);
        Assert.Contains(@"LicenseUrl=""""", wxs, StringComparison.Ordinal);
        Assert.DoesNotContain("akisp11", wxs, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsNonWindowsRuntimeIdentifiers()
    {
        Assert.Throws<ArgumentException>(() => DesktopInstallerLayout.Create("1.0.0", ["linux-x64"]));
    }
}
