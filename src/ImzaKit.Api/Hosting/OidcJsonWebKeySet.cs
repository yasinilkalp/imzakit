using System.Security.Cryptography;
using System.Text.Json;

namespace ImzaKit.Api.Hosting;

public static class OidcJsonWebKeySet
{
    public static IReadOnlyDictionary<string, RSA> Parse(string jwks)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwks);
        Dictionary<string, RSA> keys = new(StringComparer.Ordinal);
        using JsonDocument document = JsonDocument.Parse(jwks);
        if (!document.RootElement.TryGetProperty("keys", out JsonElement list) ||
            list.ValueKind != JsonValueKind.Array)
        {
            return keys;
        }

        foreach (JsonElement key in list.EnumerateArray())
        {
            string? kid = ReadString(key, "kid");
            string? n = ReadString(key, "n");
            string? e = ReadString(key, "e");
            if (!string.Equals(ReadString(key, "kty"), "RSA", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(kid) ||
                string.IsNullOrWhiteSpace(n) ||
                string.IsNullOrWhiteSpace(e) ||
                !TryBase64Url(n, out byte[] modulus) ||
                !TryBase64Url(e, out byte[] exponent))
            {
                continue;
            }

            RSA rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = modulus,
                    Exponent = exponent
                });
            }
            catch (CryptographicException)
            {
                rsa.Dispose();
                continue;
            }

            if (keys.Remove(kid, out RSA? previous))
            {
                previous.Dispose();
            }

            keys[kid] = rsa;
        }

        return keys;
    }

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool TryBase64Url(string value, out byte[] bytes)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '=');
        try
        {
            bytes = Convert.FromBase64String(padded);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
