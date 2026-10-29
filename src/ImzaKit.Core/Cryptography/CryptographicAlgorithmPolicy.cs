using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Core.Cryptography;

// Minimum algorithm strength accepted when validating signatures and certificates
// (ETSI TS 119 312): no MD5/SHA-1, RSA and DSA keys of at least 2048 bits, EC keys of at least 256 bits.
public static class CryptographicAlgorithmPolicy
{
    public const int MinimumRsaKeySize = 2048;
    public const int MinimumEcKeySize = 256;

    private static readonly HashSet<string> AllowedDigestAlgorithms = new(StringComparer.Ordinal)
    {
        "2.16.840.1.101.3.4.2.1",
        "2.16.840.1.101.3.4.2.2",
        "2.16.840.1.101.3.4.2.3",
        "2.16.840.1.101.3.4.2.8",
        "2.16.840.1.101.3.4.2.9",
        "2.16.840.1.101.3.4.2.10"
    };

    private static readonly HashSet<string> DisallowedSignatureAlgorithms = new(StringComparer.Ordinal)
    {
        "1.2.840.113549.1.1.2",
        "1.2.840.113549.1.1.4",
        "1.2.840.113549.1.1.5",
        "1.2.840.10040.4.3",
        "1.2.840.10045.4.1",
        "1.3.14.3.2.29"
    };

    public static bool IsDigestAlgorithmAllowed(string? oid) =>
        oid is not null && AllowedDigestAlgorithms.Contains(oid);

    public static bool IsSignatureAlgorithmAllowed(string? oid) =>
        oid is not null && !DisallowedSignatureAlgorithms.Contains(oid);

    public static bool IsSignerAllowed(
        string? digestAlgorithmOid,
        string? signatureAlgorithmOid,
        X509Certificate2? certificate) =>
        IsDigestAlgorithmAllowed(digestAlgorithmOid)
        && IsSignatureAlgorithmAllowed(signatureAlgorithmOid)
        && (certificate is null || IsPublicKeyStrongEnough(certificate));

    public static bool IsPublicKeyStrongEnough(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using System.Security.Cryptography.RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.KeySize >= MinimumRsaKeySize;
        }

        using System.Security.Cryptography.ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return ecdsa.KeySize >= MinimumEcKeySize;
        }

        using System.Security.Cryptography.DSA? dsa = certificate.GetDSAPublicKey();
        return dsa is null || dsa.KeySize >= MinimumRsaKeySize;
    }
}
