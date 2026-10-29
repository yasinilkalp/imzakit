using System.Security.Cryptography;
using System.Text;
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

        // The SBOM is published as UTF-8 bytes of SbomJson; its digest is bound into the provenance.
        ReleaseProvenance provenance = ReleaseProvenanceFactory.Create(
            product,
            version,
            gitCommit,
            Convert.ToHexString(SHA256.HashData(artifact)),
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sbomJson))),
            builderId,
            releaseKey);
        return new ReleasePublishBundle(sbomJson, provenance);
    }
}
