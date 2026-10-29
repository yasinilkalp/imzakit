using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace ImzaKit.Testing.Timestamp;

public sealed class TestTsaResponder : IDisposable
{
    private const string TimeStampingEku = "1.3.6.1.5.5.7.3.8";
    private readonly RSA _key = RSA.Create(2048);
    private readonly X509Certificate2 _certificate;
    private readonly TimeStampTokenGenerator _tokenGenerator;

    // Without an issuer the TSA certificate is self-signed; with one (which must carry its private key)
    // it chains to that CA, so tests can place the TSA inside or outside a trust store.
    public TestTsaResponder(X509Certificate2? issuer = null)
    {
        CertificateRequest request = new("CN=ImzaKit Test TSA", _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(TimeStampingEku) },
            critical: true));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddYears(2);
        _certificate = issuer is null
            ? request.CreateSelfSigned(notBefore, notAfter)
            : request.Create(
                issuer,
                notBefore,
                notAfter < issuer.NotAfter ? notAfter : issuer.NotAfter,
                RandomNumberGenerator.GetBytes(16));
        CertificateDer = _certificate.Export(X509ContentType.Cert);
        X509CertificateParser parser = new();
        Org.BouncyCastle.X509.X509Certificate bcCertificate = parser.ReadCertificate(_certificate.RawData);
        _tokenGenerator = new TimeStampTokenGenerator(
            DotNetUtilities.GetRsaKeyPair(_key).Private,
            bcCertificate,
            TspAlgorithms.Sha256,
            "1.2.3.4.5");
        _tokenGenerator.SetCertificates(CollectionUtilities.CreateStore([bcCertificate]));
    }

    public byte[] CertificateDer { get; }

    public byte[] Grant(byte[] requestDer)
    {
        TimeStampRequest request = new(requestDer);
        TimeStampResponseGenerator generator = new(_tokenGenerator, new List<string> { TspAlgorithms.Sha256 });
        return generator.Generate(request, BigInteger.One, DateTime.UtcNow).GetEncoded();
    }

    public byte[] Reject(byte[] requestDer)
    {
        TimeStampRequest request = new(requestDer);
        TimeStampResponseGenerator generator = new(_tokenGenerator, new List<string> { TspAlgorithms.Sha256 });
        return generator.GenerateFailResponse(Org.BouncyCastle.Asn1.Cmp.PkiStatus.Rejection, 0, "denied").GetEncoded();
    }

    public void Dispose()
    {
        _certificate.Dispose();
        _key.Dispose();
    }
}
