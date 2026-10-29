using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.CAdES.Tests;

public sealed class CmsSigningCertificateVerifierTests
{
    private static readonly byte[] Content = "cades-binding-payload"u8.ToArray();

    [Fact]
    public void AttributeHashingTheSignerCertificateIsBound()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Bound Signer");

        byte[] cms = Sign(certificate, SHA256.HashData(certificate.RawData));

        Assert.Equal(CmsSigningCertificateBinding.Bound, CmsSigningCertificateVerifier.Verify(Decode(cms).SignerInfos[0]));
        Assert.Equal(CadesStatus.Passed, CadesValidator.ValidateDetached(cms, Content).Status);
    }

    [Fact]
    public void AttributeNamingAnotherCertificateFailsValidation()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Claimed Signer");
        using X509Certificate2 other = CreateCertificate(rsa, "CN=ImzaKit Other Identity");

        byte[] cms = Sign(certificate, SHA256.HashData(other.RawData));
        CadesValidationReport report = CadesValidator.ValidateDetached(cms, Content);

        Assert.Equal(CmsSigningCertificateBinding.Mismatch, CmsSigningCertificateVerifier.Verify(Decode(cms).SignerInfos[0]));
        Assert.Equal(CadesStatus.Failed, report.Status);
        Assert.Contains("SigningCertificateMismatch", Assert.Single(report.Signers).Findings);
    }

    [Fact]
    public void MissingAttributeIsReportedWithoutFailingTheSignature()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Unbound Signer");

        byte[] cms = Sign(certificate, certificateHash: null);
        CadesValidationReport report = CadesValidator.ValidateDetached(cms, Content);

        Assert.Equal(CadesStatus.Passed, report.Status);
        Assert.Contains("SigningCertificateAttributeMissing", Assert.Single(report.Signers).Findings);
    }

    private static byte[] Sign(X509Certificate2 certificate, byte[]? certificateHash)
    {
        SignedCms cms = new(new ContentInfo(Content), detached: true);
        CmsSigner signer = new(certificate) { DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") };
        if (certificateHash is not null)
        {
            signer.SignedAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.16.2.47", SigningCertificateV2(certificateHash)));
        }

        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    private static byte[] SigningCertificateV2(byte[] certificateHash)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence())
        using (writer.PushSequence())
        {
            writer.WriteOctetString(certificateHash);
        }

        return writer.Encode();
    }

    private static SignedCms Decode(byte[] encoded)
    {
        SignedCms cms = new(new ContentInfo(Content), detached: true);
        cms.Decode(encoded);
        return cms;
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
