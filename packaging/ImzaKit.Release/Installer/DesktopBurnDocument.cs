using System.Globalization;

namespace ImzaKit.Release.Installer;

public static class DesktopBurnDocument
{
    public const string SetupExeFileName = "ImzaKit.Desktop-win-x64.setup.exe";
    public const string UpgradeCode = "B7E4C1A2-8F93-4D6E-9B10-2C5A7E8D4F31";

    public static string CreateWixSource(string version, string msiFileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(msiFileName);
        string productVersion = WindowsInstallerVersion.FromSemVer(version);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"""
            <Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:bal="http://wixtoolset.org/schemas/v4/wxs/bal">
              <Bundle Name="ImzaKit Desktop {version}" Manufacturer="ImzaKit" Version="{productVersion}" UpgradeCode="{UpgradeCode}">
                <BootstrapperApplication>
                  <bal:WixStandardBootstrapperApplication Theme="hyperlinkLicense" />
                </BootstrapperApplication>
                <Chain>
                  <MsiPackage SourceFile="{msiFileName}" />
                </Chain>
              </Bundle>
            </Wix>
            """);
    }
}
