using System.Security.Cryptography;
using ImzaKit.Release.Provenance;
using ImzaKit.Release.Sbom;

namespace ImzaKit.Release.Signing;

public sealed record ReleasePublishBundle(string SbomJson, ReleaseProvenance? Provenance);

public static class ReleasePublishBundleFactory
{
    public static ReleasePublishBundle Create(
        string product,
        string version,
        string gitCommit,
        ReadOnlySpan<byte> artifact,
        IEnumerable<SoftwareComponent> components,
        string builderId,
        ECDsa? releaseKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(product);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(gitCommit);
        ArgumentException.ThrowIfNullOrWhiteSpace(builderId);
        ArgumentNullException.ThrowIfNull(components);
        string sbomJson = CycloneDxSbomGenerator.Serialize(
            CycloneDxSbomGenerator.Create(product, version, components));
        if (releaseKey is null)
        {
            return new ReleasePublishBundle(sbomJson, Provenance: null);
        }

        ReleaseProvenance provenance = ReleaseProvenanceFactory.Create(
            product,
            version,
            gitCommit,
            Convert.ToHexString(SHA256.HashData(artifact)),
            builderId,
            releaseKey);
        return new ReleasePublishBundle(sbomJson, provenance);
    }
}
