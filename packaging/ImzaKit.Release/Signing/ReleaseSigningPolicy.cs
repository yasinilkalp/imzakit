namespace ImzaKit.Release.Signing;

public enum ReleaseArtifactKind
{
    NugetPackage,
    AgentPeOrInstaller,
    UpdateManifest
}

public sealed record ReleaseSigningMaterials(
    bool AuthenticodeCertificatePresent,
    bool ReleaseEcdsaKeyPresent);

public static class ReleaseSigningPolicy
{
    public static bool IsPrerelease(string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        return version.Contains('-', StringComparison.Ordinal);
    }

    public static void AssertCanPublish(
        string version,
        ReleaseArtifactKind kind,
        ReleaseSigningMaterials materials)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentNullException.ThrowIfNull(materials);

        bool prerelease = IsPrerelease(version);
        bool authenticodeRequired = kind is ReleaseArtifactKind.AgentPeOrInstaller || !prerelease;
        if (authenticodeRequired && !materials.AuthenticodeCertificatePresent)
        {
            throw new InvalidOperationException("IMZAKIT.RELEASE.AUTHENTICODE_CERTIFICATE_MISSING");
        }

        bool provenanceRequired = kind is ReleaseArtifactKind.UpdateManifest || !prerelease;
        if (provenanceRequired && !materials.ReleaseEcdsaKeyPresent)
        {
            throw new InvalidOperationException("IMZAKIT.RELEASE.PROVENANCE_KEY_MISSING");
        }
    }
}
