using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Api.Mtls;

internal static class DeviceCertificateIssuer
{
    public static byte[] Issue(
        X509Certificate2 caCertificate,
        Guid deviceId,
        byte[] subjectPublicKeyInfo,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        ArgumentNullException.ThrowIfNull(caCertificate);
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        using ECDsa publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
        CertificateRequest request = new(
            new X500DistinguishedName($"CN={deviceId:D}"),
            publicKey,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        OidCollection clientAuth = new();
        clientAuth.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(clientAuth, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using X509Certificate2 issued = request.Create(caCertificate, notBefore, notAfter, serial);
        return issued.RawData.ToArray();
    }
}
