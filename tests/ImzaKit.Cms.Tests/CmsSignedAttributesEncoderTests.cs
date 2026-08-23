using System.Formats.Asn1;
using ImzaKit.Cms.SignedAttributes;

namespace ImzaKit.Cms.Tests;

public sealed class CmsSignedAttributesEncoderTests
{
    private const string ContentTypeAttributeOid = "1.2.840.113549.1.9.3";
    private const string MessageDigestAttributeOid = "1.2.840.113549.1.9.4";
    private const string SigningCertificateV2AttributeOid = "1.2.840.113549.1.9.16.2.47";
    private const string DataContentTypeOid = "1.2.840.113549.1.7.1";

    [Fact]
    public void EncodeSha256WritesRequiredSignedAttributes()
    {
        byte[] contentDigest = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte[] certificateHash = Enumerable.Range(32, 32).Select(static value => (byte)value).ToArray();

        byte[] encoded = CmsSignedAttributesEncoder.EncodeSha256(contentDigest, certificateHash);

        AsnReader reader = new(encoded, AsnEncodingRules.DER);
        AsnReader attributes = reader.ReadSetOf();
        Dictionary<string, AsnReader> valuesByOid = [];

        while (attributes.HasData)
        {
            AsnReader attribute = attributes.ReadSequence();
            string oid = attribute.ReadObjectIdentifier();
            valuesByOid.Add(oid, attribute.ReadSetOf());
            Assert.False(attribute.HasData);
        }

        Assert.False(reader.HasData);
        Assert.Equal(3, valuesByOid.Count);
        Assert.Equal(DataContentTypeOid, valuesByOid[ContentTypeAttributeOid].ReadObjectIdentifier());
        Assert.Equal(contentDigest, valuesByOid[MessageDigestAttributeOid].ReadOctetString());

        AsnReader signingCertificateV2 = valuesByOid[SigningCertificateV2AttributeOid].ReadSequence();
        AsnReader certificates = signingCertificateV2.ReadSequence();
        AsnReader essCertIdV2 = certificates.ReadSequence();
        Assert.Equal(certificateHash, essCertIdV2.ReadOctetString());
        Assert.False(essCertIdV2.HasData);
        Assert.False(certificates.HasData);
        Assert.False(signingCertificateV2.HasData);
    }

    [Fact]
    public void EncodeSha256IsDeterministic()
    {
        byte[] contentDigest = Enumerable.Repeat((byte)0xA5, 32).ToArray();
        byte[] certificateHash = Enumerable.Repeat((byte)0x5A, 32).ToArray();

        byte[] first = CmsSignedAttributesEncoder.EncodeSha256(contentDigest, certificateHash);
        byte[] second = CmsSignedAttributesEncoder.EncodeSha256(contentDigest, certificateHash);

        Assert.Equal(first, second);
    }

    [Theory]
    [InlineData(31, 32, "contentDigest")]
    [InlineData(32, 31, "certificateHash")]
    public void EncodeSha256RejectsInvalidHashLength(
        int contentDigestLength,
        int certificateHashLength,
        string expectedParameter)
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            CmsSignedAttributesEncoder.EncodeSha256(
                new byte[contentDigestLength],
                new byte[certificateHashLength]));

        Assert.Equal(expectedParameter, exception.ParamName);
    }
}
