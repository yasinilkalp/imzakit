using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using ImzaKit.Cms.Preparation;
using ImzaKit.Core.Cryptography;
using ImzaKit.Core.Signing;
using ImzaKit.Cryptography.Digests;

namespace ImzaKit.Cms.Tests;

public sealed class CmsSignaturePreparerTests
{
    [Fact]
    public void PrepareDetachedBindsOperationAndAlgorithmContext()
    {
        Guid operationId = Guid.Parse("2af90dd8-4cb7-4fe3-a71a-cc15aec81bdb");
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());

        SignaturePreparation preparation = preparer.PrepareDetached(
            operationId,
            new string('A', 64),
            Encoding.ASCII.GetBytes("detached content"),
            [0x30, 0x00],
            new string('B', 64),
            prepareVersion: 2);

        Assert.Equal(operationId, preparation.OperationId);
        Assert.Equal(new string('A', 64), preparation.DocumentSha256);
        Assert.Equal(SignatureAlgorithmProfile.RsaSha256, preparation.Algorithm);
        Assert.Equal(new string('B', 64), preparation.CertificateFingerprintSha256);
        Assert.Equal(2, preparation.PrepareVersion);
    }

    [Fact]
    public void PrepareDetachedHashesContentAndCertificateIntoSignedAttributes()
    {
        byte[] content = Encoding.ASCII.GetBytes("detached content");
        byte[] certificateDer = [0x30, 0x00];
        CmsSignaturePreparer preparer = new(new DefaultDigestCalculator());

        SignaturePreparation preparation = preparer.PrepareDetached(
            Guid.NewGuid(),
            new string('A', 64),
            content,
            certificateDer,
            new string('B', 64),
            prepareVersion: 1);

        Dictionary<string, AsnReader> values = ReadAttributeValues(preparation.DataToBeSigned);
        Assert.Equal(
            SHA256.HashData(content),
            values["1.2.840.113549.1.9.4"].ReadOctetString());

        AsnReader signingCertificateV2 = values["1.2.840.113549.1.9.16.2.47"].ReadSequence();
        AsnReader certificates = signingCertificateV2.ReadSequence();
        AsnReader essCertIdV2 = certificates.ReadSequence();
        Assert.Equal(SHA256.HashData(certificateDer), essCertIdV2.ReadOctetString());
    }

    private static Dictionary<string, AsnReader> ReadAttributeValues(ReadOnlyMemory<byte> encoded)
    {
        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader attributes = reader.ReadSetOf();
        Dictionary<string, AsnReader> values = [];

        while (attributes.HasData)
        {
            AsnReader attribute = attributes.ReadSequence();
            values.Add(attribute.ReadObjectIdentifier(), attribute.ReadSetOf());
        }

        return values;
    }
}
