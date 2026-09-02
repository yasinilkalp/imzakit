namespace ImzaKit.Release.Signing;

public static class ReleaseArtifactKindParser
{
    public static ReleaseArtifactKind Parse(string? value) => value switch
    {
        null or "nuget" => ReleaseArtifactKind.NugetPackage,
        "agent" => ReleaseArtifactKind.AgentPeOrInstaller,
        "desktop" => ReleaseArtifactKind.DesktopPeOrInstaller,
        "manifest" => ReleaseArtifactKind.UpdateManifest,
        _ => throw new InvalidOperationException("Unknown --kind: " + value)
    };
}
