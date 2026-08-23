using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Testing.Certificates;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ImzaKit.Revocation.Tests.Fixtures;

internal static class RevocationEvidenceFixture
{
    internal static byte[] CreateOcsp(
        TestCertificateAuthority pki,
        bool revoked = false,
        bool wrongSerial = false,
        bool invalidSignature = false)
    {
        BcX509Certificate issuer = DotNetUtilities.FromX509Certificate(pki.Intermediate);
        BcX509Certificate leaf = DotNetUtilities.FromX509Certificate(pki.Leaf);
        using RSA issuerKey = (invalidSignature ? pki.Root : pki.Intermediate).GetRSAPrivateKey()!;
        Org.BouncyCastle.Math.BigInteger serial = wrongSerial
            ? leaf.SerialNumber.Add(Org.BouncyCastle.Math.BigInteger.One)
            : leaf.SerialNumber;
        CertificateID certificateId = new(
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance),
            issuer,
            serial);
        BasicOcspRespGenerator basicGenerator = new(issuer.GetPublicKey());
        CertificateStatus status = revoked
            ? new RevokedStatus(pki.ReferenceTimeUtc.AddHours(-1).UtcDateTime, CrlReason.KeyCompromise)
            : CertificateStatus.Good;
        basicGenerator.AddResponse(
            certificateId,
            status,
            pki.ReferenceTimeUtc.AddHours(-2).UtcDateTime,
            pki.ReferenceTimeUtc.AddHours(10).UtcDateTime,
            null);
        BasicOcspResp basic = basicGenerator.Generate(
            new Asn1SignatureFactory("SHA256WITHRSA", DotNetUtilities.GetRsaKeyPair(issuerKey).Private),
            [issuer],
            pki.ReferenceTimeUtc.UtcDateTime);
        return new OCSPRespGenerator().Generate(OCSPRespGenerator.Successful, basic).GetEncoded();
    }

    internal static byte[] CreateCrl(
        TestCertificateAuthority pki,
        int? reason = null,
        bool wrongSerial = false,
        bool mismatchedIssuerName = false)
    {
        BcX509Certificate issuer = DotNetUtilities.FromX509Certificate(pki.Intermediate);
        BcX509Certificate leaf = DotNetUtilities.FromX509Certificate(pki.Leaf);
        using RSA issuerKey = pki.Intermediate.GetRSAPrivateKey()!;
        X509V2CrlGenerator generator = new();
        generator.SetIssuerDN(mismatchedIssuerName
            ? new X509Name("CN=Different Test Issuer")
            : issuer.SubjectDN);
        generator.SetThisUpdate(pki.ReferenceTimeUtc.AddHours(-2).UtcDateTime);
        generator.SetNextUpdate(pki.ReferenceTimeUtc.AddHours(10).UtcDateTime);
        if (reason is int reasonCode)
        {
            generator.AddCrlEntry(
                wrongSerial ? leaf.SerialNumber.Add(Org.BouncyCastle.Math.BigInteger.One) : leaf.SerialNumber,
                pki.ReferenceTimeUtc.AddHours(-1).UtcDateTime,
                reasonCode);
        }

        X509Crl crl = generator.Generate(new Asn1SignatureFactory(
            "SHA256WITHRSA",
            DotNetUtilities.GetRsaKeyPair(issuerKey).Private));
        return crl.GetEncoded();
    }
}
