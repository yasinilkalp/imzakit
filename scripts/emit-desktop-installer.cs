#:project ../packaging/ImzaKit.Release/ImzaKit.Release.csproj

using ImzaKit.Release.Installer;

if (args.Contains("--compile-check", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("DESKTOP_INSTALLER_COMPILE_OK");
    return 0;
}

string? version = ReadOption(args, "--version");
string? publishDir = ReadOption(args, "--publish-dir");
string? outputDir = ReadOption(args, "--output-dir");
if (string.IsNullOrWhiteSpace(version) ||
    string.IsNullOrWhiteSpace(publishDir) ||
    string.IsNullOrWhiteSpace(outputDir))
{
    Console.Error.WriteLine("Usage: --version <semver> --publish-dir <dir> --output-dir <dir>");
    return 2;
}

DesktopInstallerPayload payload = DesktopInstallerLayout.Create(version, ["win-x64"]);
foreach (string file in payload.Files)
{
    if (file.Contains("akisp11", StringComparison.OrdinalIgnoreCase) ||
        file.Contains("etpkcs11", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("IMZAKIT.RELEASE.VENDOR_PKCS11_FORBIDDEN");
        return 1;
    }
}

Directory.CreateDirectory(outputDir);
string msiWxs = DesktopMsiDocument.CreateWixSource(payload, publishDir);
string bundleWxs = DesktopBurnDocument.CreateWixSource(version, "ImzaKit.Desktop.msi");
File.WriteAllText(Path.Combine(outputDir, "desktop.wxs"), msiWxs);
File.WriteAllText(Path.Combine(outputDir, "desktop-bundle.wxs"), bundleWxs);
Console.WriteLine("DESKTOP_INSTALLER_WXS_OK " + DesktopBurnDocument.SetupExeFileName);
return 0;

static string? ReadOption(string[] arguments, string name)
{
    int index = Array.FindIndex(arguments, argument => string.Equals(argument, name, StringComparison.Ordinal));
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}
