using System.Security.Cryptography;
using System.Text.Json;

namespace ImzaKit.Api.Hosting;

public sealed record JwtBearerCallerOptions(
    string Issuer,
    string Audience,
    byte[] HmacSha256Key,
    IReadOnlyDictionary<string, RSA>? RsaKeysByKid = null)
{
    public IReadOnlyDictionary<string, RSA> RsaKeys { get; } =
        RsaKeysByKid ?? new Dictionary<string, RSA>(StringComparer.Ordinal);

    public static JwtBearerCallerOptions? FromEnvironment()
    {
        string? issuer = Environment.GetEnvironmentVariable("IMZAKIT_JWT_ISSUER");
        string? audience = Environment.GetEnvironmentVariable("IMZAKIT_JWT_AUDIENCE");
        string? hmac = Environment.GetEnvironmentVariable("IMZAKIT_JWT_HMAC_KEY");
        string? jwks = Environment.GetEnvironmentVariable("IMZAKIT_JWT_JWKS");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(audience))
        {
            return null;
        }

        byte[] hmacKey = [];
        if (!string.IsNullOrWhiteSpace(hmac))
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(hmac);
                if (bytes.Length >= 32)
                {
                    hmacKey = bytes;
                }
            }
            catch (FormatException)
            {
                return null;
            }
        }

        IReadOnlyDictionary<string, RSA> rsaKeys;
        try
        {
            rsaKeys = string.IsNullOrWhiteSpace(jwks)
                ? new Dictionary<string, RSA>(StringComparer.Ordinal)
                : OidcJsonWebKeySet.Parse(jwks);
        }
        catch (JsonException)
        {
            return null;
        }

        if (hmacKey.Length < 32 && rsaKeys.Count == 0)
        {
            return null;
        }

        return new JwtBearerCallerOptions(issuer, audience, hmacKey, rsaKeys);
    }
}
