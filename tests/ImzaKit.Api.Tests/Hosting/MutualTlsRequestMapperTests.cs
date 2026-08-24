using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Api.Hosting;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class MutualTlsRequestMapperTests
{
    [Fact]
    public void MissingCertificateStaysMtlsAbsent()
    {
        ApiHttpRequest mapped = MutualTlsRequestMapper.Bind(
            method: "POST",
            path: "/v1/agent-callbacks/signature-results",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Idempotency-Key"] = "k1"
            },
            body: "{}",
            clientCertificate: null);

        Assert.False(mapped.HasMutualTlsClientCertificate);
        Assert.Null(mapped.ClientCertificateDer);
        Assert.Equal("POST", mapped.Method);
        Assert.Equal("/v1/agent-callbacks/signature-results", mapped.Path);
    }

    [Fact]
    public void PresentedCertificateIsCopiedAsDerWithoutPrivateKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=imzakit-device", key, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        byte[] der = cert.Export(X509ContentType.Cert);

        ApiHttpRequest mapped = MutualTlsRequestMapper.Bind(
            method: "POST",
            path: "/v1/agent-callbacks/signature-results",
            headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            body: "{}",
            clientCertificate: cert);

        Assert.True(mapped.HasMutualTlsClientCertificate);
        Assert.Equal(der, mapped.ClientCertificateDer);
        Assert.False(mapped.HasMutualTlsClientCertificate && mapped.ClientCertificateDer is null);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", Convert.ToBase64String(mapped.ClientCertificateDer!), StringComparison.Ordinal);
    }

    [Fact]
    public void KestrelPolicyAllowsMissingClientCertificateAtTlsLayerSoHandlerCanReturnMtlsRequired()
    {
        KestrelMutualTlsPolicy policy = KestrelMutualTlsPolicy.Create();

        Assert.True(policy.HttpsOnly);
        Assert.Equal(KestrelClientCertificateMode.AllowCertificate, policy.ClientCertificateMode);
        Assert.True(policy.AllowUntrustedDeviceCertificates);
        Assert.True(KestrelMutualTlsPolicy.IsCallbackPath("/v1/agent-callbacks/signature-results"));
        Assert.False(KestrelMutualTlsPolicy.IsCallbackPath("/v1/signature-operations"));
    }
}
