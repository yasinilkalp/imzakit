using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Core.Signing;

namespace ImzaKit.Cms.Completion;

public static class CmsSignedDataCompleter
{
    private const string DataContentTypeOid = "1.2.840.113549.1.7.1";
    private const string SignedDataContentTypeOid = "1.2.840.113549.1.7.2";
    private const string Sha256AlgorithmOid = "2.16.840.1.101.3.4.2.1";
    private const string RsaEncryptionAlgorithmOid = "1.2.840.113549.1.1.1";
    private static readonly Asn1Tag ContextSpecificZero =
        new(TagClass.ContextSpecific, 0, isConstructed: true);

    public static byte[] CompleteDetached(
        SignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(completion);
        EnsureMatchingContext(preparation, completion);
        EnsureCertificateMatchesPreparation(preparation, signingCertificateDer);

        using X509Certificate2 certificate =
            X509CertificateLoader.LoadCertificate(signingCertificateDer);
        byte[] implicitSignedAttributes = CreateImplicitSignedAttributes(
            preparation.DataToBeSigned.Span);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataContentTypeOid);
            using (writer.PushSequence(ContextSpecificZero))
            using (writer.PushSequence())
            {
                writer.WriteInteger(1);
                WriteDigestAlgorithms(writer);
                WriteDetachedContentInfo(writer);
                WriteCertificates(writer, signingCertificateDer);
                WriteSignerInfos(writer, certificate, implicitSignedAttributes, completion.SignatureValue.Span);
            }
        }

        return writer.Encode();
    }

    private static void WriteDigestAlgorithms(AsnWriter writer)
    {
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Sha256AlgorithmOid);
        }
    }

    private static void WriteDetachedContentInfo(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(DataContentTypeOid);
        }
    }

    private static void WriteCertificates(AsnWriter writer, ReadOnlySpan<byte> certificateDer)
    {
        using (writer.PushSetOf(ContextSpecificZero))
        {
            writer.WriteEncodedValue(certificateDer);
        }
    }

    private static void WriteSignerInfos(
        AsnWriter writer,
        X509Certificate2 certificate,
        ReadOnlySpan<byte> implicitSignedAttributes,
        ReadOnlySpan<byte> signatureValue)
    {
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            WriteIssuerAndSerialNumber(writer, certificate);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha256AlgorithmOid);
            }

            writer.WriteEncodedValue(implicitSignedAttributes);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(RsaEncryptionAlgorithmOid);
                writer.WriteNull();
            }

            writer.WriteOctetString(signatureValue);
        }
    }

    private static void WriteIssuerAndSerialNumber(AsnWriter writer, X509Certificate2 certificate)
    {
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(certificate.IssuerName.RawData);
            writer.WriteIntegerUnsigned(certificate.SerialNumberBytes.Span);
        }
    }

    private static byte[] CreateImplicitSignedAttributes(ReadOnlySpan<byte> signedAttributes)
    {
        byte[] encoded = signedAttributes.ToArray();
        if (encoded.Length == 0 || encoded[0] != 0x31)
        {
            throw new ArgumentException(
                "Signed attributes must be a DER SET OF value.",
                nameof(signedAttributes));
        }

        encoded[0] = 0xA0;
        return encoded;
    }

    private static void EnsureMatchingContext(
        SignaturePreparation preparation,
        SignatureCompletion completion)
    {
        if (preparation.OperationId != completion.OperationId)
        {
            throw new InvalidOperationException("Completion operation does not match preparation operation.");
        }

        if (preparation.PrepareVersion != completion.PrepareVersion)
        {
            throw new InvalidOperationException("Completion prepare version does not match preparation.");
        }

        if (!string.Equals(
                preparation.CertificateFingerprintSha256,
                completion.CertificateFingerprintSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Completion certificate does not match preparation certificate.");
        }
    }

    private static void EnsureCertificateMatchesPreparation(
        SignaturePreparation preparation,
        ReadOnlySpan<byte> signingCertificateDer)
    {
        string certificateFingerprint = Convert.ToHexString(SHA256.HashData(signingCertificateDer));
        if (!string.Equals(
                preparation.CertificateFingerprintSha256,
                certificateFingerprint,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Signing certificate does not match the certificate bound to preparation.");
        }
    }
}
