using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Api.Tests.Hosting;

// An RSA signing certificate for the API tests: completions must carry the RSA-SHA256 signature of the
// prepared data made with the selected certificate's key.
internal static class ApiTestSigner
{
    private static readonly RSA Key = RSA.Create(2048);

    public static byte[] CertificateDer { get; } = CreateCertificate(Key);

    public static string Fingerprint { get; } = Convert.ToHexString(SHA256.HashData(CertificateDer));

    public static string Sign(string dataToBeSignedBase64) => Sign(Key, dataToBeSignedBase64);

    public static string Sign(RSA key, string dataToBeSignedBase64) =>
        Convert.ToBase64String(key.SignData(
            Convert.FromBase64String(dataToBeSignedBase64),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

    private static byte[] CreateCertificate(RSA key)
    {
        CertificateRequest request = new("CN=ImzaKit API Test Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        return certificate.Export(X509ContentType.Cert);
    }
}
