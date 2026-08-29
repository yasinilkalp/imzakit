using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.ASiC;
using ImzaKit.CAdES;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;
using ImzaKit.Revocation.Models;
using ImzaKit.Verify.Validation;
using ImzaKit.XAdES;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class SignatureValidationReportTests
{
    private static readonly byte[] SampleXml = """
        <doc xmlns="urn:imzakit:xades-test"><payload>hello</payload></doc>
        """u8.ToArray();

    [Fact]
    public void PadesIntegrityFailureKeepsFailedStatusAndFormat()
    {
        PadesValidationReport pades = PadesValidator.Validate("not a pdf"u8);

        SignatureValidationReport report = SignatureValidationReportMapper.FromPades(pades);

        Assert.Equal(SignatureFormat.Pades, report.Format);
        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Failed, report.IntegrityStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "UnsupportedPdf");
    }

    [Fact]
    public void CadesCryptoOnlySuccessIsIndeterminateUntilTrustIsEvaluated()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Common CAdES");
        byte[] content = "common-cades"u8.ToArray();
        byte[] cms = SignCades(rsa, certificate, content);

        SignatureValidationReport report = SignatureValidationReportMapper.FromCades(
            CadesValidator.ValidateDetached(cms, content));

        Assert.Equal(SignatureFormat.Cades, report.Format);
        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.IntegrityStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Indeterminate, report.ChainStatus);
        Assert.Equal(ValidationStatus.Indeterminate, report.TrustStatus);
        Assert.Equal(ValidationStatus.Indeterminate, report.PolicyStatus);
        Assert.Equal(RevocationStatus.Unavailable, report.RevocationStatus);
        SignatureReport signer = Assert.Single(report.Signatures);
        Assert.Equal(ValidationStatus.Passed, signer.CryptographicStatus);
        Assert.Equal(CadesBaselineLevel.BB, signer.SignatureLevel);
        Assert.Contains(report.Findings, finding => finding.Code == "TrustNotEvaluated");
    }

    [Fact]
    public void CadesTamperedContentFailsCryptographyAndOverallStatus()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Common CAdES Tamper");
        byte[] cms = SignCades(rsa, certificate, "common-cades"u8.ToArray());

        SignatureValidationReport report = SignatureValidationReportMapper.FromCades(
            CadesValidator.ValidateDetached(cms, "other"u8.ToArray()));

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Failed, report.CryptographicStatus);
        Assert.Equal(ValidationStatus.Failed, Assert.Single(report.Signatures).CryptographicStatus);
    }

    [Fact]
    public void CadesMixedSignersAreReportedSeparately()
    {
        using RSA firstKey = RSA.Create(2048);
        using RSA secondKey = RSA.Create(2048);
        using X509Certificate2 first = CreateCertificate(firstKey, "CN=ImzaKit Common First");
        using X509Certificate2 second = CreateCertificate(secondKey, "CN=ImzaKit Common Second");
        byte[] content = "common-cosign"u8.ToArray();
        byte[] firstCms = SignCades(firstKey, first, content);
        SignaturePreparation broken = PrepareCades(second, content);
        byte[] mixed = CadesDetachedSigner.AddSigner(
            firstCms,
            broken,
            SignatureCompletion.Create(
                broken.OperationId,
                broken.PrepareVersion,
                broken.CertificateFingerprintSha256,
                new byte[256]),
            second.Export(X509ContentType.Cert));

        SignatureValidationReport report = SignatureValidationReportMapper.FromCades(
            CadesValidator.ValidateDetached(mixed, content));

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(2, report.Signatures.Count);
        Assert.Contains(report.Signatures, signer => signer.CryptographicStatus == ValidationStatus.Passed);
        Assert.Contains(report.Signatures, signer => signer.CryptographicStatus == ValidationStatus.Failed);
    }

    [Fact]
    public void XadesCryptoOnlySuccessIsIndeterminateUntilTrustIsEvaluated()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Common XAdES");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Enveloped, SampleXml, certificate, rsa);

        SignatureValidationReport report = SignatureValidationReportMapper.FromXades(
            XadesValidator.Validate(signed));

        Assert.Equal(SignatureFormat.Xades, report.Format);
        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        SignatureReport signature = Assert.Single(report.Signatures);
        Assert.Equal(XadesPackaging.Enveloped.ToString(), signature.Packaging);
        Assert.Equal(XadesBaselineLevel.BB, signature.SignatureLevel);
        Assert.Contains(report.Findings, finding => finding.Code == "TrustNotEvaluated");
    }

    [Fact]
    public void XadesInvalidXmlFailsIntegrity()
    {
        SignatureValidationReport report = SignatureValidationReportMapper.FromXades(
            XadesValidator.Validate("not-xml"u8));

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Failed, report.IntegrityStatus);
        Assert.Contains(report.Findings, finding => finding.Code == "InvalidXml");
    }

    [Fact]
    public void AsicSimpleCadesSignatureMapsContainerAndInnerCrypto()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit Common ASiC");
        byte[] content = "asic-document"u8.ToArray();
        byte[] cms = SignCades(rsa, certificate, content);
        byte[] packed = AsicPacker.PackSimple(
            new AsicDataObject("document.txt", content),
            new AsicSignatureFile("signature.p7s", cms));

        SignatureValidationReport report = SignatureValidationReportMapper.FromAsic(AsicReader.Open(packed));

        Assert.Equal(SignatureFormat.Asic, report.Format);
        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Passed, report.IntegrityStatus);
        Assert.Equal(ValidationStatus.Passed, report.CryptographicStatus);
        SignatureReport signature = Assert.Single(report.Signatures);
        Assert.Equal(SignatureFormat.Cades, signature.Format);
        Assert.Equal(ValidationStatus.Passed, signature.CryptographicStatus);
    }

    private static byte[] SignCades(RSA rsa, X509Certificate2 certificate, byte[] content)
    {
        SignaturePreparation preparation = PrepareCades(certificate, content);
        return CadesDetachedSigner.SignDetached(
            preparation,
            CompleteCades(rsa, preparation),
            certificate.Export(X509ContentType.Cert));
    }

    private static SignaturePreparation PrepareCades(X509Certificate2 certificate, byte[] content)
    {
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        return new CmsSignaturePreparer(new DefaultDigestCalculator()).PrepareDetached(
            Guid.NewGuid(),
            Convert.ToHexString(SHA256.HashData(content)),
            content,
            certificateDer,
            Convert.ToHexString(SHA256.HashData(certificateDer)),
            prepareVersion: 1);
    }

    private static SignatureCompletion CompleteCades(RSA rsa, SignaturePreparation preparation)
    {
        byte[] signature = rsa.SignData(
            preparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signature);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
