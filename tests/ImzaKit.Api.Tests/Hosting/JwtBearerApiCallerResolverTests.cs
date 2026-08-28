using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ImzaKit.Api.Hosting;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class JwtBearerApiCallerResolverTests
{
    private static readonly byte[] Key = "imzakit-test-hmac-key-32-bytes!!"u8.ToArray();
    private static readonly JwtBearerCallerOptions Options = new("https://identity.example", "imzakit-api", Key);

    [Fact]
    public void ResolveAcceptsSignedTokenAndReadsTenantFromClaims()
    {
        string token = Issue(new Dictionary<string, object>
        {
            ["iss"] = Options.Issuer,
            ["aud"] = Options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-42",
            ["application_id"] = "app-7"
        });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(Options).Resolve(Request("Bearer " + token));

        Assert.True(identity.Authenticated);
        Assert.Equal("tenant-42", identity.TenantId);
        Assert.Equal("app-7", identity.ApplicationId);
    }

    [Fact]
    public void ResolveIgnoresSpoofedTenantHeaders()
    {
        string token = Issue(new Dictionary<string, object>
        {
            ["iss"] = Options.Issuer,
            ["aud"] = Options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "from-token",
            ["application_id"] = "from-token-app"
        });
        ApiHttpRequest request = Request(
            "Bearer " + token,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer " + token,
                ["X-ImzaKit-Tenant"] = "spoofed-tenant",
                ["X-ImzaKit-Application"] = "spoofed-app"
            });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(Options).Resolve(request);

        Assert.True(identity.Authenticated);
        Assert.Equal("from-token", identity.TenantId);
        Assert.Equal("from-token-app", identity.ApplicationId);
    }

    [Fact]
    public void ResolveRejectsTenantHeadersWithoutJwt()
    {
        ApiHttpRequest request = Request(
            "Bearer not-a-jwt",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer not-a-jwt",
                ["X-ImzaKit-Tenant"] = "tenant-1",
                ["X-ImzaKit-Application"] = "app-1"
            });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(Options).Resolve(request);

        Assert.False(identity.Authenticated);
    }

    [Fact]
    public void ResolveRejectsExpiredToken()
    {
        string token = Issue(new Dictionary<string, object>
        {
            ["iss"] = Options.Issuer,
            ["aud"] = Options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-42",
            ["application_id"] = "app-7"
        });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(Options).Resolve(Request("Bearer " + token));

        Assert.False(identity.Authenticated);
    }

    [Fact]
    public void ResolveRejectsTamperedSignature()
    {
        string token = Issue(new Dictionary<string, object>
        {
            ["iss"] = Options.Issuer,
            ["aud"] = Options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-42",
            ["application_id"] = "app-7"
        });
        string tampered = token[..^4] + "AAAA";

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(Options).Resolve(Request("Bearer " + tampered));

        Assert.False(identity.Authenticated);
    }

    private static ApiHttpRequest Request(string authorization, IReadOnlyDictionary<string, string>? headers = null) =>
        new()
        {
            Method = "POST",
            Path = "/v1/signature-operations",
            Headers = headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = authorization
            }
        };

    private static string Issue(Dictionary<string, object> claims)
    {
        string header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"HS256","typ":"JWT"}"""));
        string payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims));
        string signingInput = header + "." + payload;
        byte[] signature = HMACSHA256.HashData(Key, Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64Url(signature);
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
