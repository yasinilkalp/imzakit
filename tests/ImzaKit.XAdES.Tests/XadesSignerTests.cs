using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using ImzaKit.Core.Net;
using ImzaKit.Testing.Timestamp;
using ImzaKit.Timestamp.Rfc3161;
using ImzaKit.XAdES;

namespace ImzaKit.XAdES.Tests;

public sealed class XadesPackagingTests
{
    private static readonly byte[] SampleXml = """
        <doc xmlns="urn:imzakit:xades-test"><payload>hello</payload></doc>
        """u8.ToArray();

    [Fact]
    public void EnvelopedBaselineBRoundTripPasses()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Enveloped");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Enveloped, SampleXml, certificate, rsa);

        XadesValidationReport report = XadesValidator.Validate(signed);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesPackaging.Enveloped, report.Packaging);
        Assert.Equal(XadesBaselineLevel.BB, report.SignatureLevel);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(certificate.RawData)), report.SignerCertificateSha256);
        Assert.Contains("<doc ", Encoding.UTF8.GetString(signed), StringComparison.Ordinal);
    }

    [Fact]
    public void EnvelopingBaselineBRoundTripPasses()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Enveloping");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Enveloping, SampleXml, certificate, rsa);

        XadesValidationReport report = XadesValidator.Validate(signed);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesPackaging.Enveloping, report.Packaging);
        Assert.Equal(XadesBaselineLevel.BB, report.SignatureLevel);
        Assert.Contains("Signature", Encoding.UTF8.GetString(signed), StringComparison.Ordinal);
    }

    [Fact]
    public void DetachedBaselineBRoundTripPasses()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Detached");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Detached, SampleXml, certificate, rsa);

        XadesValidationReport report = XadesValidator.Validate(signed, SampleXml);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesPackaging.Detached, report.Packaging);
        Assert.Equal(XadesBaselineLevel.BB, report.SignatureLevel);
        Assert.Contains("#imzakit-detached", Encoding.UTF8.GetString(signed), StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyRejectsDisallowedPackaging()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Policy");
        XadesSignaturePolicy policy = new(XadesPackaging.Enveloped);

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            XadesSigner.Sign(XadesPackaging.Detached, SampleXml, certificate, rsa, policy));

        Assert.Contains("not allowed by policy", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TamperedEnvelopedContentFails()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Tamper");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Enveloped, SampleXml, certificate, rsa);
        byte[] tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(signed).Replace("hello", "hallo", StringComparison.Ordinal));

        XadesValidationReport report = XadesValidator.Validate(tampered);

        Assert.Equal(XadesStatus.Failed, report.Status);
        Assert.Contains("XmlSignatureInvalid", report.Findings);
    }

    [Fact]
    public void TamperedDetachedContentFails()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES Detached Tamper");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Detached, SampleXml, certificate, rsa);

        XadesValidationReport report = XadesValidator.Validate(signed, "<doc xmlns=\"urn:imzakit:xades-test\"><payload>other</payload></doc>"u8.ToArray());

        Assert.Equal(XadesStatus.Failed, report.Status);
        Assert.Contains("XmlSignatureInvalid", report.Findings);
    }

    [Fact]
    public void DtdIsRejected()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES DTD");
        byte[] xml = """
            <?xml version="1.0"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><doc>&xxe;</doc>
            """u8.ToArray();

        Assert.Throws<XmlException>(() => XadesSigner.Sign(XadesPackaging.Enveloped, xml, certificate, rsa));
    }

    [Fact]
    public void ExternalHttpReferenceIsRejectedWithoutDereference()
    {
        byte[] signed = """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="https://example.invalid/payload.xml">
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AA==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AA==</SignatureValue>
            </Signature>
            """u8.ToArray();

        XadesValidationReport report = XadesValidator.Validate(signed);

        Assert.Equal(XadesStatus.Failed, report.Status);
        Assert.Contains("ExternalUriDereferenceDisabled", report.Findings);
    }

    [Fact]
    public void XsltTransformIsRejected()
    {
        byte[] signed = """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference URI="">
                  <Transforms>
                    <Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>
                  </Transforms>
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AA==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AA==</SignatureValue>
            </Signature>
            """u8.ToArray();

        XadesValidationReport report = XadesValidator.Validate(signed);

        Assert.Equal(XadesStatus.Failed, report.Status);
        Assert.Contains("TransformNotAllowed", report.Findings);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}

public sealed class XadesBaselineTests
{
    private static readonly byte[] SampleXml = """
        <doc xmlns="urn:imzakit:xades-test"><payload>baseline</payload></doc>
        """u8.ToArray();

    [Fact]
    public async Task BaselineTAddsSignatureTimestamp()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES B-T");
        byte[] timestamped = await Timestamp(rsa, certificate);

        XadesValidationReport report = XadesValidator.Validate(timestamped);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesBaselineLevel.BT, report.SignatureLevel);
        Assert.Contains("SignatureTimeStamp", Encoding.UTF8.GetString(timestamped), StringComparison.Ordinal);
    }

    [Fact]
    public void BaselineLtRejectsXmlWithoutSignatureTimestamp()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES LT reject");
        byte[] signed = XadesSigner.Sign(XadesPackaging.Enveloped, SampleXml, certificate, rsa);

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            XadesExtender.ExtendBaselineLt(
                signed,
                new XadesLongTermEvidence([certificate.Export(X509ContentType.Cert)])));

        Assert.Contains("B-T", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BaselineLtAddsCertificateAndRevocationValues()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES B-LT");
        byte[] timestamped = await Timestamp(rsa, certificate);
        byte[] crl = [0x30, 0x03, 0x02, 0x01, 0x01];

        byte[] longTerm = XadesExtender.ExtendBaselineLt(
            timestamped,
            new XadesLongTermEvidence(
                [certificate.Export(X509ContentType.Cert)],
                certificateRevocationLists: [crl]));

        XadesValidationReport report = XadesValidator.Validate(longTerm);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesBaselineLevel.BLT, report.SignatureLevel);
        Assert.Contains("CertificateValues", Encoding.UTF8.GetString(longTerm), StringComparison.Ordinal);
        Assert.Contains("RevocationValues", Encoding.UTF8.GetString(longTerm), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BaselineLtaAddsArchiveTimestampAfterLongTerm()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES B-LTA");
        byte[] timestamped = await Timestamp(rsa, certificate);
        byte[] longTerm = XadesExtender.ExtendBaselineLt(
            timestamped,
            new XadesLongTermEvidence([certificate.Export(X509ContentType.Cert)]));
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        byte[] archived = await XadesExtender.ExtendBaselineLta(
            longTerm,
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);

        XadesValidationReport report = XadesValidator.Validate(archived);

        Assert.Equal(XadesStatus.Passed, report.Status);
        Assert.Equal(XadesBaselineLevel.BLTA, report.SignatureLevel);
    }

    [Fact]
    public async Task BaselineLtaRejectsXmlWithoutLongTermEvidence()
    {
        using RSA rsa = RSA.Create(2048);
        using X509Certificate2 certificate = CreateCertificate(rsa, "CN=ImzaKit XAdES LTA reject");
        byte[] timestamped = await Timestamp(rsa, certificate);
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            XadesExtender.ExtendBaselineLta(
                timestamped,
                new Rfc3161TimeStampClient(fetcher),
                [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
                CancellationToken.None));

        Assert.Contains("B-LT", error.Message, StringComparison.Ordinal);
    }

    private static async Task<byte[]> Timestamp(RSA rsa, X509Certificate2 certificate)
    {
        using TestTsaResponder tsa = new();
        ScriptedFetcher fetcher = new((_, body) => tsa.Grant(body));
        return await XadesExtender.ExtendBaselineT(
            XadesSigner.Sign(XadesPackaging.Enveloped, SampleXml, certificate, rsa),
            new Rfc3161TimeStampClient(fetcher),
            [new TimeStampAuthority("primary", new Uri("https://tsa.example/rfc3161"))],
            CancellationToken.None);
    }

    private static X509Certificate2 CreateCertificate(RSA rsa, string subject)
    {
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ExternalResourceFetchResult(respond(request.Uri, request.Body), "application/timestamp-reply"));
    }
}
