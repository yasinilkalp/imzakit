using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.CAdES;

public enum CmsSigningCertificateBinding
{
    Bound,
    AttributeMissing,
    Mismatch
}

// Checks the signed signing-certificate(-v2) attribute (RFC 5035) against the certificate the
// SignerInfo resolves to, so a CMS cannot be re-labelled with a different certificate for the same key.
public static class CmsSigningCertificateVerifier
{
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string SigningCertificateOid = "1.2.840.113549.1.9.16.2.12";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    public static CmsSigningCertificateBinding Verify(SignerInfo signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        foreach (CryptographicAttributeObject attribute in signer.SignedAttributes)
        {
            bool v2 = attribute.Oid?.Value == SigningCertificateV2Oid;
            if (!v2 && attribute.Oid?.Value != SigningCertificateOid)
            {
                continue;
            }

            if (attribute.Values.Count != 1 || signer.Certificate is not X509Certificate2 certificate)
            {
                return CmsSigningCertificateBinding.Mismatch;
            }

            try
            {
                return MatchesFirstCertId(attribute.Values[0].RawData, v2, certificate.RawData)
                    ? CmsSigningCertificateBinding.Bound
                    : CmsSigningCertificateBinding.Mismatch;
            }
            catch (AsnContentException)
            {
                return CmsSigningCertificateBinding.Mismatch;
            }
        }

        return CmsSigningCertificateBinding.AttributeMissing;
    }

    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies ... OPTIONAL }
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, certHash OCTET STRING, ... }
    // ESSCertID   ::= SEQUENCE { certHash OCTET STRING (SHA-1), ... }
    private static bool MatchesFirstCertId(byte[] encoded, bool v2, byte[] certificateDer)
    {
        AsnReader certs = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        AsnReader certId = certs.ReadSequence();
        string hashOid = v2 ? Sha256Oid : "1.3.14.3.2.26";
        if (v2 && certId.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            hashOid = certId.ReadSequence().ReadObjectIdentifier();
        }

        byte[] expected = certId.ReadOctetString();
        byte[]? actual = hashOid switch
        {
            Sha256Oid => SHA256.HashData(certificateDer),
            "2.16.840.1.101.3.4.2.2" => SHA384.HashData(certificateDer),
            "2.16.840.1.101.3.4.2.3" => SHA512.HashData(certificateDer),
#pragma warning disable CA5350 // Legacy ESSCertID identifies the certificate by SHA-1; this is a lookup, not a security decision.
            "1.3.14.3.2.26" => SHA1.HashData(certificateDer),
#pragma warning restore CA5350
            _ => null,
        };
        return actual is not null && CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
