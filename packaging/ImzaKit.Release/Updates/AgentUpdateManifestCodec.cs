using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ImzaKit.Release.Updates;

public sealed record RidArtifact(string RuntimeIdentifier, string Sha256);

public sealed record AgentUpdateManifest(
    string Version,
    string RollbackVersion,
    IReadOnlyList<RidArtifact> Artifacts);

public static class AgentUpdateManifestCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static byte[] Sign(AgentUpdateManifest manifest, ECDsa releaseKey)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(releaseKey);
        byte[] canonical = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
        return JsonSerializer.SerializeToUtf8Bytes(
            new Envelope(Convert.ToBase64String(canonical), Convert.ToHexString(releaseKey.SignData(canonical, HashAlgorithmName.SHA256))),
            Json);
    }

    public static bool TryVerify(ReadOnlySpan<byte> package, ECDsa releasePublicKey, out AgentUpdateManifest? manifest)
    {
        ArgumentNullException.ThrowIfNull(releasePublicKey);
        manifest = null;
        try
        {
            Envelope? envelope = JsonSerializer.Deserialize<Envelope>(package, Json);
            if (envelope is null)
            {
                return false;
            }

            byte[] canonical = Convert.FromBase64String(envelope.Payload);
            if (!releasePublicKey.VerifyData(canonical, Convert.FromHexString(envelope.Signature), HashAlgorithmName.SHA256))
            {
                return false;
            }

            manifest = JsonSerializer.Deserialize<AgentUpdateManifest>(canonical, Json);
            return manifest is not null;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException)
        {
            return false;
        }
    }

    public static bool CanRollback(AgentUpdateManifest manifest, string currentlyInstalled)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentlyInstalled);
        return string.Equals(currentlyInstalled, manifest.Version, StringComparison.Ordinal) &&
               Compare(manifest.RollbackVersion, manifest.Version) < 0;
    }

    private static int Compare(string left, string right)
    {
        Match leftMatch = VersionPattern.Match(left);
        Match rightMatch = VersionPattern.Match(right);
        if (!leftMatch.Success || !rightMatch.Success)
        {
            return string.Compare(left, right, StringComparison.Ordinal);
        }

        int core = CompareCore(leftMatch, rightMatch);
        if (core != 0)
        {
            return core;
        }

        bool leftPre = leftMatch.Groups["pre"].Success;
        bool rightPre = rightMatch.Groups["pre"].Success;
        if (leftPre != rightPre)
        {
            return leftPre ? -1 : 1;
        }

        return string.Compare(leftMatch.Groups["pre"].Value, rightMatch.Groups["pre"].Value, StringComparison.Ordinal);
    }

    private static int CompareCore(Match left, Match right)
    {
        int major = int.Parse(left.Groups["major"].Value, CultureInfo.InvariantCulture)
            .CompareTo(int.Parse(right.Groups["major"].Value, CultureInfo.InvariantCulture));
        if (major != 0)
        {
            return major;
        }

        int minor = int.Parse(left.Groups["minor"].Value, CultureInfo.InvariantCulture)
            .CompareTo(int.Parse(right.Groups["minor"].Value, CultureInfo.InvariantCulture));
        return minor != 0
            ? minor
            : int.Parse(left.Groups["patch"].Value, CultureInfo.InvariantCulture)
                .CompareTo(int.Parse(right.Groups["patch"].Value, CultureInfo.InvariantCulture));
    }

    private static readonly Regex VersionPattern = new(
        @"^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<pre>[0-9A-Za-z.-]+))?$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private sealed record Envelope(string Payload, string Signature);
}
