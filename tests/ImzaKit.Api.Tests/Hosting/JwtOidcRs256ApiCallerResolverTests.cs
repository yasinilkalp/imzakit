using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ImzaKit.Api.Hosting;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class JwtOidcRs256ApiCallerResolverTests : IDisposable
{
    private static readonly string[] Audiences = ["other-api", "imzakit-api"];
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly JwtBearerCallerOptions _options;

    public JwtOidcRs256ApiCallerResolverTests()
    {
        _options = new(
            "https://identity.example",
            "imzakit-api",
            [],
            new Dictionary<string, RSA>(StringComparer.Ordinal) { ["k1"] = _rsa });
    }

    public void Dispose() => _rsa.Dispose();

    [Fact]
    public void ResolveAcceptsRs256TokenFromJwksKid()
    {
        string token = IssueRs256(new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-oidc",
            ["azp"] = "spa-client",
            ["scope"] = "signature:write signature:read"
        });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(_options).Resolve(Bearer(token));

        Assert.True(identity.Authenticated);
        Assert.Equal("tenant-oidc", identity.TenantId);
        Assert.Equal("spa-client", identity.ApplicationId);
    }

    [Fact]
    public void ResolveAcceptsAudienceArrayClaim()
    {
        string token = IssueRs256(new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = Audiences,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-oidc",
            ["application_id"] = "spa-client"
        });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(_options).Resolve(Bearer(token));

        Assert.True(identity.Authenticated);
    }

    [Fact]
    public void ResolveRejectsUnknownKid()
    {
        string token = IssueRs256(
            new Dictionary<string, object>
            {
                ["iss"] = _options.Issuer,
                ["aud"] = _options.Audience,
                ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
                ["tenant_id"] = "tenant-oidc",
                ["application_id"] = "spa-client"
            },
            kid: "unknown");

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(_options).Resolve(Bearer(token));

        Assert.False(identity.Authenticated);
    }

    [Fact]
    public void ResolveRejectsAlgNone()
    {
        string header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"none","typ":"JWT"}"""));
        string payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-oidc",
            ["application_id"] = "spa-client"
        }));
        string token = header + "." + payload + ".";

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(_options).Resolve(Bearer(token));

        Assert.False(identity.Authenticated);
    }

    [Fact]
    public void ResolveRejectsScopeWithoutSignatureAccess()
    {
        string token = IssueRs256(new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-oidc",
            ["application_id"] = "spa-client",
            ["scope"] = "openid profile"
        });

        ApiCallerIdentity identity = new JwtBearerApiCallerResolver(_options).Resolve(Bearer(token));

        Assert.False(identity.Authenticated);
    }

    [Fact]
    public void ParseJwksImportsModulusAndExponent()
    {
        RSAParameters parameters = _rsa.ExportParameters(includePrivateParameters: false);
        string jwks = JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    kid = "k1",
                    n = Base64Url(parameters.Modulus!),
                    e = Base64Url(parameters.Exponent!)
                }
            }
        });

        IReadOnlyDictionary<string, RSA> keys = OidcJsonWebKeySet.Parse(jwks);
        using RSA imported = keys["k1"];
        JwtBearerCallerOptions options = new(_options.Issuer, _options.Audience, [], keys);
        string token = IssueRs256(new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["tenant_id"] = "tenant-oidc",
            ["application_id"] = "spa-client"
        });

        Assert.True(new JwtBearerApiCallerResolver(options).Resolve(Bearer(token)).Authenticated);
    }

    private string IssueRs256(Dictionary<string, object> claims, string kid = "k1")
    {
        string header = Base64Url(Encoding.UTF8.GetBytes($$"""{"alg":"RS256","typ":"JWT","kid":"{{kid}}"}"""));
        string payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims));
        string signingInput = header + "." + payload;
        byte[] signature = _rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64Url(signature);
    }

    private static ApiHttpRequest Bearer(string token) =>
        new()
        {
            Method = "POST",
            Path = "/v1/signature-operations",
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer " + token
            }
        };

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
