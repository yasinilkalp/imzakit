namespace ImzaKit.Release.Installer;

public sealed record DesktopInstallerPayload(
    string Version,
    string InstallDirectory,
    IReadOnlyList<string> RuntimeIdentifiers,
    IReadOnlyList<string> Pkcs11AllowlistRoots,
    IReadOnlyList<string> EtokenPkcs11AllowlistRoots,
    IReadOnlyList<string> Files,
    bool AuthenticodeRequired,
    bool DisableDllSearchPathHijacking);

public static class DesktopInstallerLayout
{
    public static DesktopInstallerPayload Create(string version, IReadOnlyList<string> rids)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentNullException.ThrowIfNull(rids);
        string[] runtimeIdentifiers = [.. rids];
        if (runtimeIdentifiers.Length == 0 ||
            runtimeIdentifiers.Any(rid => rid is not ("win-x64" or "win-arm64")))
        {
            throw new ArgumentException("Desktop installer supports only win-x64 and win-arm64.", nameof(rids));
        }

        return new DesktopInstallerPayload(
            version,
            @"%ProgramFiles%\ImzaKit\Desktop",
            runtimeIdentifiers,
            [@"%ProgramFiles%\AKIS"],
            [
                @"%ProgramFiles%\SafeNet\Authentication\SAC\x64",
                @"%ProgramFiles%\Thales\SafeNet Authentication Client"
            ],
            [
                "ImzaKit.Hosts.Desktop.App.exe",
                "ImzaKit.Hosts.Desktop.dll",
                "LICENSE",
                "NOTICE",
                "sbom.cdx.json",
                "provenance.json"
            ],
            AuthenticodeRequired: true,
            DisableDllSearchPathHijacking: true);
    }
}
