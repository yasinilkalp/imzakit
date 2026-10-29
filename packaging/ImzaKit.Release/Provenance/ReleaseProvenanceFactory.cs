using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ImzaKit.Release.Provenance;

public sealed record ReleaseProvenance(
    string Product,
    string Version,
    string GitCommit,
    string ArtifactSha256,
    string SbomSha256,
    string BuilderId,
    DateTimeOffset IssuedAtUtc,
    string Signature);

public static class ReleaseProvenanceFactory
{
    public static ReleaseProvenance Create(
        string product,
        string version,
        string gitCommit,
        string artifactSha256,
        string sbomSha256,
        string builderId,
        ECDsa releaseKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(product);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(gitCommit);
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(sbomSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(builderId);
        ArgumentNullException.ThrowIfNull(releaseKey);
        DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
        byte[] canonical = Canonical(product, version, gitCommit, artifactSha256, sbomSha256, builderId, issuedAt);
        return new(
            product,
            version,
            gitCommit,
            artifactSha256,
            sbomSha256,
            builderId,
            issuedAt,
            Convert.ToHexString(releaseKey.SignData(canonical, HashAlgorithmName.SHA256)));
    }

    public static bool Verify(
        ReleaseProvenance provenance,
        ECDsa releasePublicKey,
        ReadOnlySpan<byte> artifactSha256,
        ReadOnlySpan<byte> sbomSha256)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        ArgumentNullException.ThrowIfNull(releasePublicKey);
        if (!string.Equals(provenance.ArtifactSha256, Convert.ToHexString(artifactSha256), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(provenance.SbomSha256, Convert.ToHexString(sbomSha256), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        byte[] canonical = Canonical(
            provenance.Product,
            provenance.Version,
            provenance.GitCommit,
            provenance.ArtifactSha256,
            provenance.SbomSha256,
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

    // Written with Utf8JsonWriter: release scripts run as file-based apps, where reflection-based
    // JsonSerializer is disabled.
    private static byte[] Canonical(
        string product,
        string version,
        string gitCommit,
        string artifactSha256,
        string sbomSha256,
        string builderId,
        DateTimeOffset issuedAt)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("product", product);
            writer.WriteString("version", version);
            writer.WriteString("gitCommit", gitCommit);
            writer.WriteString("artifactSha256", artifactSha256);
            writer.WriteString("sbomSha256", sbomSha256);
            writer.WriteString("builderId", builderId);
            writer.WriteString("issuedAt", issuedAt.ToUniversalTime());
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}

public static class ReleaseProvenanceJson
{
    private const string Malformed = "IMZAKIT.RELEASE.PROVENANCE_MALFORMED";

    public static string Write(ReleaseProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(provenance);
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("product", provenance.Product);
            writer.WriteString("version", provenance.Version);
            writer.WriteString("gitCommit", provenance.GitCommit);
            writer.WriteString("artifactSha256", provenance.ArtifactSha256);
            writer.WriteString("sbomSha256", provenance.SbomSha256);
            writer.WriteString("builderId", provenance.BuilderId);
            writer.WriteString(
                "issuedAtUtc",
                provenance.IssuedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("signature", provenance.Signature);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static ReleaseProvenance Read(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            return new(
                Required(root, "product"),
                Required(root, "version"),
                Required(root, "gitCommit"),
                Required(root, "artifactSha256"),
                Required(root, "sbomSha256"),
                Required(root, "builderId"),
                DateTimeOffset.Parse(
                    Required(root, "issuedAtUtc"),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal),
                Required(root, "signature"));
        }
        catch (Exception exception) when (exception is JsonException or FormatException or InvalidOperationException)
        {
            throw new InvalidDataException(Malformed, exception);
        }
    }

    private static string Required(JsonElement root, string name)
    {
        string? value = root.TryGetProperty(name, out JsonElement element) ? element.GetString() : null;
        return string.IsNullOrWhiteSpace(value) ? throw new InvalidDataException(Malformed) : value;
    }
}
