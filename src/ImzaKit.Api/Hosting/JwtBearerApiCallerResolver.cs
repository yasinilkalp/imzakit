using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ImzaKit.Api.Hosting;

public sealed class JwtBearerApiCallerResolver(JwtBearerCallerOptions options) : IApiCallerResolver
{
    private static readonly ApiCallerIdentity Anonymous = new(false, "", "");

    public ApiCallerIdentity Resolve(ApiHttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        if (options.HmacSha256Key.Length < 32 && options.RsaKeys.Count == 0)
        {
            return Anonymous;
        }

        if (!request.Headers.TryGetValue("Authorization", out string? authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return Anonymous;
        }

        string token = authorization["Bearer ".Length..].Trim();
        if (!TryReadClaims(token, out JsonElement payload))
        {
            return Anonymous;
        }

        if (!ClaimEquals(payload, "iss", options.Issuer) ||
            !AudienceMatches(payload, options.Audience) ||
            !HasRequiredScope(payload) ||
            !TryReadUnixTime(payload, "exp", out long exp) ||
            exp <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return Anonymous;
        }

        string tenant = ReadClaim(payload, "tenant_id") ?? ReadClaim(payload, "tid") ?? "";
        string application = ReadClaim(payload, "application_id") ??
            ReadClaim(payload, "azp") ??
            ReadClaim(payload, "client_id") ?? "";
        if (string.IsNullOrWhiteSpace(tenant) || string.IsNullOrWhiteSpace(application))
        {
            return Anonymous;
        }

        return new ApiCallerIdentity(true, tenant, application);
    }

    private bool TryReadClaims(string token, out JsonElement payload)
    {
        payload = default;
        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        if (!TryBase64Url(parts[0], out byte[] headerBytes) ||
            !TryBase64Url(parts[1], out byte[] payloadBytes) ||
            !TryBase64Url(parts[2], out byte[] signature))
        {
            return false;
        }

        try
        {
            using JsonDocument header = JsonDocument.Parse(headerBytes);
            if (!header.RootElement.TryGetProperty("alg", out JsonElement algElement) ||
                algElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            string? alg = algElement.GetString();
            byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            if (!VerifySignature(header.RootElement, alg, signingInput, signature))
            {
                return false;
            }

            using JsonDocument document = JsonDocument.Parse(payloadBytes);
            payload = document.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private bool VerifySignature(JsonElement header, string? alg, byte[] signingInput, byte[] signature)
    {
        if (string.Equals(alg, "HS256", StringComparison.Ordinal))
        {
            if (options.HmacSha256Key.Length < 32)
            {
                return false;
            }

            byte[] expected = HMACSHA256.HashData(options.HmacSha256Key, signingInput);
            return CryptographicOperations.FixedTimeEquals(expected, signature);
        }

        if (!string.Equals(alg, "RS256", StringComparison.Ordinal))
        {
            return false;
        }

        if (!header.TryGetProperty("kid", out JsonElement kidElement) ||
            kidElement.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        string? kid = kidElement.GetString();
        if (string.IsNullOrWhiteSpace(kid) || !options.RsaKeys.TryGetValue(kid, out RSA? rsa))
        {
            return false;
        }

        return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool AudienceMatches(JsonElement payload, string expected)
    {
        if (!payload.TryGetProperty("aud", out JsonElement aud))
        {
            return false;
        }

        if (aud.ValueKind == JsonValueKind.String)
        {
            return string.Equals(aud.GetString(), expected, StringComparison.Ordinal);
        }

        if (aud.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in aud.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String &&
                string.Equals(item.GetString(), expected, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasRequiredScope(JsonElement payload)
    {
        if (!payload.TryGetProperty("scope", out JsonElement scope) &&
            !payload.TryGetProperty("scp", out scope))
        {
            return true;
        }

        if (scope.ValueKind == JsonValueKind.String)
        {
            return HasSignatureAccess(scope.GetString());
        }

        if (scope.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (JsonElement item in scope.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && HasSignatureAccess(item.GetString()))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasSignatureAccess(string? scopes)
    {
        if (string.IsNullOrWhiteSpace(scopes))
        {
            return false;
        }

        foreach (string token in scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.Equals(token, "signature:write", StringComparison.Ordinal) ||
                string.Equals(token, "signature:read", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ClaimEquals(JsonElement payload, string name, string expected) =>
        string.Equals(ReadClaim(payload, name), expected, StringComparison.Ordinal);

    private static string? ReadClaim(JsonElement payload, string name)
    {
        if (!payload.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? text = value.GetString();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static bool TryReadUnixTime(JsonElement payload, string name, out long value)
    {
        value = 0;
        if (!payload.TryGetProperty(name, out JsonElement element))
        {
            return false;
        }

        return element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out value);
    }

    private static bool TryBase64Url(string value, out byte[] bytes)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '=');
        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
