using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ImzaKit.Trust.Packaging;

public static class TrustStorePackageCodec
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static byte[] Sign(TrustStoreManifest manifest, ECDsa releaseKey)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(releaseKey);
        byte[] canonical = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
        string signature = Convert.ToHexString(releaseKey.SignData(canonical, HashAlgorithmName.SHA256));
        return JsonSerializer.SerializeToUtf8Bytes(
            new Envelope(Convert.ToBase64String(canonical), signature), Json);
    }

    public static bool TryVerify(ReadOnlySpan<byte> package, ECDsa releasePublicKey, out TrustStoreManifest? manifest)
    {
        ArgumentNullException.ThrowIfNull(releasePublicKey);
        manifest = null;
        try
        {
            Envelope? envelope = JsonSerializer.Deserialize<Envelope>(package, Json);
            if (envelope is null ||
                string.IsNullOrWhiteSpace(envelope.Payload) ||
                string.IsNullOrWhiteSpace(envelope.Signature))
            {
                return false;
            }

            byte[] canonical = Convert.FromBase64String(envelope.Payload);
            if (!releasePublicKey.VerifyData(
                    canonical,
                    Convert.FromHexString(envelope.Signature),
                    HashAlgorithmName.SHA256))
            {
                return false;
            }

            manifest = JsonSerializer.Deserialize<TrustStoreManifest>(canonical, Json);
            return manifest is not null;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException)
        {
            return false;
        }
    }

    private sealed record Envelope(string Payload, string Signature);
}
