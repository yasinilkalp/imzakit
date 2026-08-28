using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Cms.Completion;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;

namespace ImzaKit.Cms.Tests;

public sealed class CmsSignedDataCompleterTests
{
    private static readonly Asn1Tag ContextSpecificZero =
        new(TagClass.ContextSpecific, 0, isConstructed: true);

    [Fact]
    public void CompleteDetachedWritesContentInfoSignerAndSignatureValue()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x10, 0x20],
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] signatureValue = Enumerable.Repeat((byte)0x5A, 256).ToArray();
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signatureValue);

        byte[] encoded = CmsSignedDataCompleter.CompleteDetached(
            preparation,
            completion,
            certificateDer);

        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader contentInfo = reader.ReadSequence();
        Assert.Equal("1.2.840.113549.1.7.2", contentInfo.ReadObjectIdentifier());
        AsnReader explicitContent = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitContent.ReadSequence();
        Assert.Equal(1, signedData.ReadInteger());
        signedData.ReadSetOf().ReadEncodedValue();
        AsnReader encapContentInfo = signedData.ReadSequence();
        Assert.Equal("1.2.840.113549.1.7.1", encapContentInfo.ReadObjectIdentifier());
        Assert.False(encapContentInfo.HasData);
        Assert.True(signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero));
        signedData.ReadSetOf(ContextSpecificZero).ReadEncodedValue();
        AsnReader signerInfo = signedData.ReadSetOf().ReadSequence();
        Assert.Equal(1, signerInfo.ReadInteger());
        signerInfo.ReadSequence();
        signerInfo.ReadSequence();
        signerInfo.ReadSetOf(ContextSpecificZero);
        signerInfo.ReadSequence();
        Assert.Equal(signatureValue, signerInfo.ReadOctetString());
        Assert.False(signerInfo.HasData);
        Assert.False(signedData.HasData);
        Assert.False(explicitContent.HasData);
        Assert.False(contentInfo.HasData);
        Assert.False(reader.HasData);
    }

    [Fact]
    public void ReadCertificatesAndTimeStampTokenRoundTrip()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x10, 0x20],
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] encoded = CmsSignedDataCompleter.CompleteDetached(
            preparation,
            SignatureCompletion.Create(
                preparation.OperationId,
                preparation.PrepareVersion,
                fingerprint,
                Enumerable.Repeat((byte)0x5A, 256).ToArray()),
            certificateDer,
            CreateMinimalContentInfo());

        List<byte[]> certificates = CmsSignedDataCompleter.ReadCertificates(encoded);
        Assert.Single(certificates);
        Assert.Equal(certificateDer, certificates[0]);
        Assert.Equal(CreateMinimalContentInfo(), CmsSignedDataCompleter.ReadSignatureTimeStampToken(encoded));
    }

    [Fact]
    public void CompleteDetachedWritesSignatureTimeStampTokenAsUnsignedAttribute()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x10, 0x20],
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] signatureValue = Enumerable.Repeat((byte)0x5A, 256).ToArray();
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signatureValue);
        byte[] timeStampToken = CreateMinimalContentInfo();

        byte[] encoded = CmsSignedDataCompleter.CompleteDetached(
            preparation,
            completion,
            certificateDer,
            timeStampToken);

        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitContent.ReadSequence();
        signedData.ReadInteger();
        signedData.ReadSetOf().ReadEncodedValue();
        signedData.ReadSequence();
        signedData.ReadSetOf(ContextSpecificZero).ReadEncodedValue();
        AsnReader signerInfo = signedData.ReadSetOf().ReadSequence();
        signerInfo.ReadInteger();
        signerInfo.ReadSequence();
        signerInfo.ReadSequence();
        signerInfo.ReadSetOf(ContextSpecificZero);
        signerInfo.ReadSequence();
        Assert.Equal(signatureValue, signerInfo.ReadOctetString());
        Asn1Tag unsignedTag = new(TagClass.ContextSpecific, 1, isConstructed: true);
        Assert.True(signerInfo.PeekTag().HasSameClassAndValue(unsignedTag));
        AsnReader unsignedAttributes = signerInfo.ReadSetOf(unsignedTag);
        AsnReader attribute = unsignedAttributes.ReadSequence();
        Assert.Equal("1.2.840.113549.1.9.16.2.14", attribute.ReadObjectIdentifier());
        Assert.Equal(timeStampToken, attribute.ReadSetOf().ReadEncodedValue().ToArray());
        Assert.False(attribute.HasData);
        Assert.False(unsignedAttributes.HasData);
        Assert.False(signerInfo.HasData);
    }

    [Fact]
    public void AddSignatureTimeStampAppendsUnsignedAttributeToCompletedCms()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x10, 0x20],
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] signatureValue = Enumerable.Repeat((byte)0x5A, 256).ToArray();
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signatureValue);
        byte[] baseline = CmsSignedDataCompleter.CompleteDetached(preparation, completion, certificateDer);
        byte[] timeStampToken = CreateMinimalContentInfo();

        byte[] encoded = CmsSignedDataCompleter.AddSignatureTimeStamp(baseline, timeStampToken);

        Assert.Equal(signatureValue, CmsSignedDataCompleter.ReadSignatureValue(encoded));
        Assert.True(CmsSignedDataCompleter.HasSignatureTimeStamp(encoded));
        Assert.False(CmsSignedDataCompleter.HasSignatureTimeStamp(baseline));
        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitContent.ReadSequence();
        signedData.ReadInteger();
        signedData.ReadSetOf().ReadEncodedValue();
        signedData.ReadSequence();
        signedData.ReadSetOf(ContextSpecificZero).ReadEncodedValue();
        AsnReader signerInfo = signedData.ReadSetOf().ReadSequence();
        signerInfo.ReadInteger();
        signerInfo.ReadSequence();
        signerInfo.ReadSequence();
        signerInfo.ReadSetOf(ContextSpecificZero);
        signerInfo.ReadSequence();
        Assert.Equal(signatureValue, signerInfo.ReadOctetString());
        Asn1Tag unsignedTag = new(TagClass.ContextSpecific, 1, isConstructed: true);
        Assert.True(signerInfo.PeekTag().HasSameClassAndValue(unsignedTag));
        AsnReader unsignedAttributes = signerInfo.ReadSetOf(unsignedTag);
        AsnReader attribute = unsignedAttributes.ReadSequence();
        Assert.Equal("1.2.840.113549.1.9.16.2.14", attribute.ReadObjectIdentifier());
        Assert.Equal(timeStampToken, attribute.ReadSetOf().ReadEncodedValue().ToArray());
    }

    [Fact]
    public void AddSignatureTimeStampRejectsCmsThatAlreadyHasUnsignedAttributes()
    {
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x10, 0x20],
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        byte[] encoded = CmsSignedDataCompleter.CompleteDetached(
            preparation,
            SignatureCompletion.Create(
                preparation.OperationId,
                preparation.PrepareVersion,
                fingerprint,
                Enumerable.Repeat((byte)0x5A, 256).ToArray()),
            certificateDer,
            CreateMinimalContentInfo());

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => CmsSignedDataCompleter.AddSignatureTimeStamp(encoded, CreateMinimalContentInfo()));

        Assert.Contains("unsigned", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CompleteDetachedRejectsDifferentPrepareVersion()
    {
        SignaturePreparation preparation = SignaturePreparation.Create(
            Guid.NewGuid(),
            new string('A', 64),
            [0x31, 0x00],
            ImzaKit.Core.Cryptography.SignatureAlgorithmProfile.RsaSha256,
            new string('B', 64),
            prepareVersion: 1);
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            prepareVersion: 2,
            preparation.CertificateFingerprintSha256,
            [0x01]);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CmsSignedDataCompleter.CompleteDetached(preparation, completion, [0x30, 0x00]));

        Assert.Contains("prepare version", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(true, false, "operation")]
    [InlineData(false, true, "certificate")]
    public void CompleteDetachedRejectsDifferentOperationOrCertificate(
        bool differentOperation,
        bool differentCertificate,
        string expectedMessage)
    {
        SignaturePreparation preparation = SignaturePreparation.Create(
            Guid.NewGuid(),
            new string('A', 64),
            [0x31, 0x00],
            ImzaKit.Core.Cryptography.SignatureAlgorithmProfile.RsaSha256,
            new string('B', 64),
            prepareVersion: 1);
        SignatureCompletion completion = SignatureCompletion.Create(
            differentOperation ? Guid.NewGuid() : preparation.OperationId,
            preparation.PrepareVersion,
            differentCertificate ? new string('C', 64) : preparation.CertificateFingerprintSha256,
            [0x01]);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CmsSignedDataCompleter.CompleteDetached(preparation, completion, [0x30, 0x00]));

        Assert.Contains(expectedMessage, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CompleteDetachedRejectsCertificateDerOutsidePrepareContext()
    {
        using X509Certificate2 preparedCertificate = CreateCertificate();
        using X509Certificate2 differentCertificate = CreateCertificate();
        byte[] preparedCertificateDer = preparedCertificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(preparedCertificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            [0x01],
            preparedCertificateDer,
            fingerprint,
            prepareVersion: 1);
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            [0x01]);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CmsSignedDataCompleter.CompleteDetached(
                preparation,
                completion,
                differentCertificate.Export(X509ContentType.Cert)));

        Assert.Contains("certificate", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CompleteDetachedRoundTripsWithIndependentSignedCmsVerifier()
    {
        byte[] content = "independent detached verification"u8.ToArray();
        using X509Certificate2 certificate = CreateCertificate();
        byte[] certificateDer = certificate.Export(X509ContentType.Cert);
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificateDer));
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());
        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            content,
            certificateDer,
            fingerprint,
            prepareVersion: 1);
        using RSA privateKey = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Test certificate has no RSA private key.");
        byte[] signatureValue = privateKey.SignData(
            preparation.DataToBeSigned.Span,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        SignatureCompletion completion = SignatureCompletion.Create(
            preparation.OperationId,
            preparation.PrepareVersion,
            preparation.CertificateFingerprintSha256,
            signatureValue);
        byte[] encoded = CmsSignedDataCompleter.CompleteDetached(
            preparation,
            completion,
            certificateDer);

        SignedCms validCms = new(new ContentInfo(content), detached: true);
        validCms.Decode(encoded);
        validCms.CheckSignature(verifySignatureOnly: true);

        SignedCms modifiedCms = new(new ContentInfo("modified"u8.ToArray()), detached: true);
        modifiedCms.Decode(encoded);
        Assert.Throws<CryptographicException>(() =>
            modifiedCms.CheckSignature(verifySignatureOnly: true));
    }

    private static byte[] CreateMinimalContentInfo()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        }

        return writer.Encode();
    }

    private static X509Certificate2 CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=ImzaKit CMS Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
    }
}
