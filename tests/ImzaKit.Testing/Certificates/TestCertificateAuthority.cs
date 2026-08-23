using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

    public static TestCertificateAuthority Create(string leafPolicyOid = "2.16.792.1.2.1.1.7.1")
    {
        DateTimeOffset now = new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);
        RSA rootKey = RSA.Create(2048);
        RSA intermediateKey = RSA.Create(2048);
        RSA leafKey = RSA.Create(2048);

        CertificateRequest rootRequest = CreateCaRequest("CN=ImzaKit Test Root", rootKey, pathLength: 1);
        X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-30), now.AddYears(10));

        CertificateRequest intermediateRequest = CreateCaRequest("CN=ImzaKit Test Intermediate", intermediateKey, pathLength: 0);
        using X509Certificate2 intermediatePublic = intermediateRequest.Create(
            root, now.AddDays(-20), now.AddYears(5), RandomNumberGenerator.GetBytes(16));
        X509Certificate2 intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

        CertificateRequest leafRequest = new(
            "CN=ImzaKit Test Signer",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false));
        leafRequest.CertificateExtensions.Add(CreateCertificatePoliciesExtension(leafPolicyOid));
        using X509Certificate2 leafPublic = leafRequest.Create(
            intermediate, now.AddDays(-10), now.AddYears(1), RandomNumberGenerator.GetBytes(16));
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

    private static CertificateRequest CreateCaRequest(string subject, RSA key, int pathLength)
    {
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private static X509Extension CreateCertificatePoliciesExtension(string policyOid)
    {
        byte[] oid = new Oid(policyOid).Value is not null
            ? EncodeCertificatePolicies(policyOid)
            : throw new ArgumentException("Policy OID is invalid.", nameof(policyOid));
        return new X509Extension("2.5.29.32", oid, critical: false);
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
}
