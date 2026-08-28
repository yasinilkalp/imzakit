using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ImzaKit.Testing.Certificates;

public sealed class TestCertificateAuthority : IDisposable
{
    private readonly RSA _rootKey;
    private readonly RSA _intermediateKey;
    private readonly RSA _leafKey;

    private TestCertificateAuthority(
        DateTimeOffset referenceTimeUtc,
        RSA rootKey,
        RSA intermediateKey,
        RSA leafKey,
        X509Certificate2 root,
        X509Certificate2 intermediate,
        X509Certificate2 leaf)
    {
        ReferenceTimeUtc = referenceTimeUtc;
        _rootKey = rootKey;
        _intermediateKey = intermediateKey;
        _leafKey = leafKey;
        Root = root;
        Intermediate = intermediate;
        Leaf = leaf;
    }

    public DateTimeOffset ReferenceTimeUtc { get; }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Intermediate { get; }

    public X509Certificate2 Leaf { get; }

    public static TestCertificateAuthority Create(
        string leafPolicyOid = "2.16.792.1.2.1.1.7.1",
        bool intermediateIsCa = true,
        bool intermediateHasKeyCertSign = true,
        bool leafHasDigitalSignature = true,
        bool useSha1Signatures = false,
        string? ocspUri = null,
        string? crlDistributionUri = null)
    {
        DateTimeOffset now = new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);
        if (useSha1Signatures)
        {
            return CreateLegacySha1(now);
        }

        RSA rootKey = RSA.Create(2048);
        RSA intermediateKey = RSA.Create(2048);
        RSA leafKey = RSA.Create(2048);

        HashAlgorithmName signatureHash = useSha1Signatures ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        CertificateRequest rootRequest = CreateCaRequest(
            "CN=ImzaKit Test Root", rootKey, pathLength: 1, isCa: true, hasKeyCertSign: true, signatureHash);
        X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-30), now.AddYears(10));

        CertificateRequest intermediateRequest = CreateCaRequest(
            "CN=ImzaKit Test Intermediate",
            intermediateKey,
            pathLength: 0,
            intermediateIsCa,
            intermediateHasKeyCertSign,
            signatureHash);
        using X509Certificate2 intermediatePublic = intermediateRequest.Create(
            root, now.AddDays(-20), now.AddYears(5), RandomNumberGenerator.GetBytes(16));
        X509Certificate2 intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

        CertificateRequest leafRequest = new(
            "CN=ImzaKit Test Signer",
            leafKey,
            signatureHash,
            RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            leafHasDigitalSignature ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyEncipherment,
            true));
        leafRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false));
        leafRequest.CertificateExtensions.Add(CreateCertificatePoliciesExtension(leafPolicyOid));
        if (ocspUri is not null)
        {
            leafRequest.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(
                ocspUris: [ocspUri],
                caIssuersUris: null,
                critical: false));
        }

        if (crlDistributionUri is not null)
        {
            leafRequest.CertificateExtensions.Add(CreateCrlDistributionPointExtension(crlDistributionUri));
        }
        X509SignatureGenerator intermediateSigner = X509SignatureGenerator.CreateForRSA(
            intermediateKey,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 leafPublic = leafRequest.Create(
            intermediate.SubjectName,
            intermediateSigner,
            now.AddDays(-10),
            now.AddYears(1),
            RandomNumberGenerator.GetBytes(16));
        X509Certificate2 leaf = leafPublic.CopyWithPrivateKey(leafKey);

        return new(now, rootKey, intermediateKey, leafKey, root, intermediate, leaf);
    }

    public void Dispose()
    {
        Leaf.Dispose();
        Intermediate.Dispose();
        Root.Dispose();
        _leafKey.Dispose();
        _intermediateKey.Dispose();
        _rootKey.Dispose();
    }

    private static CertificateRequest CreateCaRequest(
        string subject,
        RSA key,
        int pathLength,
        bool isCa,
        bool hasKeyCertSign,
        HashAlgorithmName signatureHash)
    {
        CertificateRequest request = new(subject, key, signatureHash, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, isCa, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            hasKeyCertSign ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign : X509KeyUsageFlags.DigitalSignature,
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private static System.Security.Cryptography.X509Certificates.X509Extension CreateCertificatePoliciesExtension(string policyOid)
    {
        byte[] oid = new Oid(policyOid).Value is not null
            ? EncodeCertificatePolicies(policyOid)
            : throw new ArgumentException("Policy OID is invalid.", nameof(policyOid));
        return new System.Security.Cryptography.X509Certificates.X509Extension("2.5.29.32", oid, critical: false);
    }

    private static byte[] EncodeCertificatePolicies(string policyOid)
    {
        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(policyOid);
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    private static System.Security.Cryptography.X509Certificates.X509Extension CreateCrlDistributionPointExtension(string uri)
    {
        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
            System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true)))
        using (writer.PushSequence(new System.Formats.Asn1.Asn1Tag(
            System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true)))
        {
            writer.WriteCharacterString(
                System.Formats.Asn1.UniversalTagNumber.IA5String,
                uri,
                new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 6));
        }

        return new System.Security.Cryptography.X509Certificates.X509Extension("2.5.29.31", writer.Encode(), critical: false);
    }

    private static TestCertificateAuthority CreateLegacySha1(DateTimeOffset now)
    {
        SecureRandom random = new();
        AsymmetricCipherKeyPair rootPair = GenerateKeyPair(random);
        AsymmetricCipherKeyPair intermediatePair = GenerateKeyPair(random);
        AsymmetricCipherKeyPair leafPair = GenerateKeyPair(random);
        X509Name rootName = new("CN=ImzaKit SHA1 Test Root");
        X509Name intermediateName = new("CN=ImzaKit SHA1 Test Intermediate");
        X509Name leafName = new("CN=ImzaKit SHA1 Test Signer");

        Org.BouncyCastle.X509.X509Certificate root = GenerateLegacyCertificate(
            rootName, rootName, rootPair.Public, rootPair.Private, 1001, now.AddDays(-30), now.AddYears(10), isCa: true);
        Org.BouncyCastle.X509.X509Certificate intermediate = GenerateLegacyCertificate(
            intermediateName, rootName, intermediatePair.Public, rootPair.Private, 1002, now.AddDays(-20), now.AddYears(5), isCa: true);
        Org.BouncyCastle.X509.X509Certificate leaf = GenerateLegacyCertificate(
            leafName, intermediateName, leafPair.Public, intermediatePair.Private, 1003, now.AddDays(-10), now.AddYears(1), isCa: false);

        return new(
            now,
            RSA.Create(),
            RSA.Create(),
            RSA.Create(),
            X509CertificateLoader.LoadCertificate(root.GetEncoded()),
            X509CertificateLoader.LoadCertificate(intermediate.GetEncoded()),
            X509CertificateLoader.LoadCertificate(leaf.GetEncoded()));
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(SecureRandom random)
    {
        RsaKeyPairGenerator generator = new();
        generator.Init(new KeyGenerationParameters(random, 2048));
        return generator.GenerateKeyPair();
    }

    private static Org.BouncyCastle.X509.X509Certificate GenerateLegacyCertificate(
        X509Name subject,
        X509Name issuer,
        AsymmetricKeyParameter publicKey,
        AsymmetricKeyParameter issuerPrivateKey,
        long serial,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool isCa)
    {
        X509V3CertificateGenerator generator = new();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetIssuerDN(issuer);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(publicKey);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
        generator.AddExtension(
            X509Extensions.KeyUsage,
            true,
            new KeyUsage(isCa ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature));
        return generator.Generate(new Asn1SignatureFactory("SHA1WITHRSA", issuerPrivateKey));
    }
}
