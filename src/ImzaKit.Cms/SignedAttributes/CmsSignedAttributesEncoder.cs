using System.Formats.Asn1;

namespace ImzaKit.Cms.SignedAttributes;

public static class CmsSignedAttributesEncoder
{
    private const int Sha256Length = 32;
    private const string ContentTypeAttributeOid = "1.2.840.113549.1.9.3";
    private const string MessageDigestAttributeOid = "1.2.840.113549.1.9.4";
    private const string SigningCertificateV2AttributeOid = "1.2.840.113549.1.9.16.2.47";
    private const string DataContentTypeOid = "1.2.840.113549.1.7.1";

    public static byte[] EncodeSha256(
        ReadOnlySpan<byte> contentDigest,
        ReadOnlySpan<byte> certificateHash)
    {
        EnsureSha256Length(contentDigest, nameof(contentDigest));
        EnsureSha256Length(certificateHash, nameof(certificateHash));

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            WriteContentType(writer);
            WriteMessageDigest(writer, contentDigest);
            WriteSigningCertificateV2(writer, certificateHash);
        }

        return writer.Encode();
    }

    private static void WriteContentType(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(ContentTypeAttributeOid);
            using (writer.PushSetOf())
            {
                writer.WriteObjectIdentifier(DataContentTypeOid);
            }
        }
    }

    private static void WriteMessageDigest(AsnWriter writer, ReadOnlySpan<byte> contentDigest)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(MessageDigestAttributeOid);
            using (writer.PushSetOf())
            {
                writer.WriteOctetString(contentDigest);
            }
        }
    }

    private static void WriteSigningCertificateV2(
        AsnWriter writer,
        ReadOnlySpan<byte> certificateHash)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SigningCertificateV2AttributeOid);
            using (writer.PushSetOf())
            using (writer.PushSequence())
            using (writer.PushSequence())
            using (writer.PushSequence())
            {
                writer.WriteOctetString(certificateHash);
            }
        }
    }

    private static void EnsureSha256Length(ReadOnlySpan<byte> value, string parameterName)
    {
        if (value.Length != Sha256Length)
        {
            throw new ArgumentException(
                $"SHA-256 value must contain exactly {Sha256Length} bytes.",
                parameterName);
        }
    }
}
