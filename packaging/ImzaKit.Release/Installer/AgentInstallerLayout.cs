namespace ImzaKit.Release.Installer;

public sealed record AgentInstallerPayload(
    string Version,
    string InstallDirectory,
    IReadOnlyList<string> RuntimeIdentifiers,
    IReadOnlyList<string> LoopbackBindAddresses,
    IReadOnlyList<string> Pkcs11AllowlistRoots,
    IReadOnlyList<string> EtokenPkcs11AllowlistRoots,
    IReadOnlyList<string> Files,
    bool AuthenticodeRequired,
    bool DisableDllSearchPathHijacking);

public static class AgentInstallerLayout
{
    public static AgentInstallerPayload Create(string version, IReadOnlyList<string> rids)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentNullException.ThrowIfNull(rids);
        string[] runtimeIdentifiers = [.. rids];
        if (runtimeIdentifiers.Length == 0 ||
            runtimeIdentifiers.Any(rid => rid is not ("win-x64" or "win-arm64")))
        {
            throw new ArgumentException("Agent installer MVP supports only win-x64 and win-arm64.", nameof(rids));
        }

        return new AgentInstallerPayload(
            version,
            @"%ProgramFiles%\ImzaKit\Agent",
            runtimeIdentifiers,
            ["127.0.0.1", "::1"],
            [@"%ProgramFiles%\AKIS"],
            [
                @"%ProgramFiles%\SafeNet\Authentication\SAC\x64",
                @"%ProgramFiles%\Thales\SafeNet Authentication Client"
            ],
            [
                "ImzaKit.Agent.dll",
                "agent.json",
                "LICENSE",
                "NOTICE",
                "sbom.cdx.json",
                "provenance.json"
            ],
            AuthenticodeRequired: true,
            DisableDllSearchPathHijacking: true);
    }
}
