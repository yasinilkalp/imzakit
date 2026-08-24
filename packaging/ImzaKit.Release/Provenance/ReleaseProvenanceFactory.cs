using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ImzaKit.Release.Provenance;

public sealed record ReleaseProvenance(
    string Product,
    string Version,
    string GitCommit,
    string ArtifactSha256,
    string BuilderId,
    DateTimeOffset IssuedAtUtc,
    string Signature);

public static class ReleaseProvenanceFactory
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static ReleaseProvenance Create(
        string product,
        string version,
        string gitCommit,
        string artifactSha256,
        string builderId,
        ECDsa releaseKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(product);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(gitCommit);
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(builderId);
        ArgumentNullException.ThrowIfNull(releaseKey);
        DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
        byte[] canonical = Canonical(product, version, gitCommit, artifactSha256, builderId, issuedAt);
        return new(
            product,
            version,
            gitCommit,
            artifactSha256,
            builderId,
            issuedAt,
            Convert.ToHexString(releaseKey.SignData(canonical, HashAlgorithmName.SHA256)));
    }

    public static bool Verify(ReleaseProvenance provenance, ECDsa releasePublicKey, ReadOnlySpan<byte> artifactSha256)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(releasePublicKey);
        string expected = Convert.ToHexString(artifactSha256);
        if (!string.Equals(provenance.ArtifactSha256, expected, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        byte[] canonical = Canonical(
            provenance.Product,
            provenance.Version,
            provenance.GitCommit,
            provenance.ArtifactSha256,
            provenance.BuilderId,
            provenance.IssuedAtUtc);
        try
        {
            return releasePublicKey.VerifyData(
                canonical,
                Convert.FromHexString(provenance.Signature),
                HashAlgorithmName.SHA256);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] Canonical(
        string product,
        string version,
        string gitCommit,
        string artifactSha256,
        string builderId,
        DateTimeOffset issuedAt) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new { product, version, gitCommit, artifactSha256, builderId, issuedAt },
            Json);
}
