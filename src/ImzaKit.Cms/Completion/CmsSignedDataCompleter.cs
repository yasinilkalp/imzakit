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
    private const string SignatureTimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";
    private static readonly Asn1Tag ContextSpecificZero =
        new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag ContextSpecificOne =
        new(TagClass.ContextSpecific, 1, isConstructed: true);

    public static byte[] CompleteDetached(
        SignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer,
        ReadOnlySpan<byte> signatureTimeStampToken = default)
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
                WriteSignerInfos(
                    writer,
                    certificate,
                    implicitSignedAttributes,
                    completion.SignatureValue.Span,
                    signatureTimeStampToken);
            }
        }

        return writer.Encode();
    }

    public static byte[] AddSignatureTimeStamp(
        ReadOnlySpan<byte> cms,
        ReadOnlySpan<byte> signatureTimeStampToken)
    {
        if (cms.IsEmpty)
        {
            throw new ArgumentException("CMS container is empty.", nameof(cms));
        }

        if (signatureTimeStampToken.IsEmpty)
        {
            throw new ArgumentException("Signature timestamp token is empty.", nameof(signatureTimeStampToken));
        }

        AsnReader root = new(cms.ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = root.ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != SignedDataContentTypeOid)
        {
            throw new ArgumentException("CMS content type must be signedData.", nameof(cms));
        }

        AsnReader explicitSignedData = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitSignedData.ReadSequence();
        if (root.HasData || contentInfo.HasData || explicitSignedData.HasData)
        {
            throw new ArgumentException("CMS container has trailing data.", nameof(cms));
        }

        System.Numerics.BigInteger version = signedData.ReadInteger();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte>? certificates = null;
        ReadOnlyMemory<byte>? crls = null;
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            certificates = signedData.ReadEncodedValue();
        }

        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificOne))
        {
            crls = signedData.ReadEncodedValue();
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        ReadOnlyMemory<byte> signerInfo = signerInfos.ReadEncodedValue();
        if (signerInfos.HasData)
        {
            throw new NotSupportedException("Only a single signerInfo is supported when adding a signature timestamp.");
        }

        if (signedData.HasData)
        {
            throw new ArgumentException("Unexpected SignedData fields.", nameof(cms));
        }

        byte[] extendedSigner = AppendUnsignedTimeStamp(signerInfo.Span, signatureTimeStampToken);
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataContentTypeOid);
            using (writer.PushSequence(ContextSpecificZero))
            using (writer.PushSequence())
            {
                writer.WriteInteger(version);
                writer.WriteEncodedValue(digestAlgorithms.Span);
                writer.WriteEncodedValue(encapContentInfo.Span);
                if (certificates is not null)
                {
                    writer.WriteEncodedValue(certificates.Value.Span);
                }

                if (crls is not null)
                {
                    writer.WriteEncodedValue(crls.Value.Span);
                }

                using (writer.PushSetOf())
                {
                    writer.WriteEncodedValue(extendedSigner);
                }
            }
        }

        return writer.Encode();
    }

    public static byte[] ReadSignatureValue(ReadOnlySpan<byte> cms)
    {
        if (cms.IsEmpty)
        {
            throw new ArgumentException("CMS container is empty.", nameof(cms));
        }

        AsnReader signerInfo = OpenFirstSignerInfo(cms);
        signerInfo.ReadInteger();
        signerInfo.ReadEncodedValue();
        signerInfo.ReadEncodedValue();
        if (signerInfo.HasData && signerInfo.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            signerInfo.ReadEncodedValue();
        }

        signerInfo.ReadEncodedValue();
        return signerInfo.ReadOctetString();
    }

    public static bool HasSignatureTimeStamp(ReadOnlySpan<byte> cms) =>
        HasUnsignedAttribute(cms, SignatureTimeStampTokenOid);

    public static bool HasUnsignedAttribute(ReadOnlySpan<byte> cms, string oid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        AsnReader signerInfo = OpenFirstSignerInfo(cms);
        signerInfo.ReadInteger();
        signerInfo.ReadEncodedValue();
        signerInfo.ReadEncodedValue();
        if (signerInfo.HasData && signerInfo.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            signerInfo.ReadEncodedValue();
        }

        signerInfo.ReadEncodedValue();
        signerInfo.ReadOctetString();
        if (!signerInfo.HasData)
        {
            return false;
        }

        AsnReader unsignedAttributes = signerInfo.ReadSetOf(ContextSpecificOne);
        while (unsignedAttributes.HasData)
        {
            AsnReader attribute = unsignedAttributes.ReadSequence();
            if (attribute.ReadObjectIdentifier() == oid)
            {
                return true;
            }

            if (attribute.HasData)
            {
                attribute.ReadSetOf();
            }
        }

        return false;
    }

    public static byte[] AddUnsignedAttributes(
        ReadOnlySpan<byte> cms,
        IReadOnlyList<CmsUnsignedValue> attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        if (cms.IsEmpty)
        {
            throw new ArgumentException("CMS container is empty.", nameof(cms));
        }

        if (attributes.Count == 0)
        {
            throw new ArgumentException("At least one unsigned attribute is required.", nameof(attributes));
        }

        AsnReader root = new(cms.ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = root.ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != SignedDataContentTypeOid)
        {
            throw new ArgumentException("CMS content type must be signedData.", nameof(cms));
        }

        AsnReader explicitSignedData = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitSignedData.ReadSequence();
        if (root.HasData || contentInfo.HasData || explicitSignedData.HasData)
        {
            throw new ArgumentException("CMS container has trailing data.", nameof(cms));
        }

        System.Numerics.BigInteger version = signedData.ReadInteger();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte>? certificates = null;
        ReadOnlyMemory<byte>? crls = null;
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            certificates = signedData.ReadEncodedValue();
        }

        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificOne))
        {
            crls = signedData.ReadEncodedValue();
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        ReadOnlyMemory<byte> signerInfo = signerInfos.ReadEncodedValue();
        if (signerInfos.HasData)
        {
            throw new NotSupportedException("Only a single signerInfo is supported when adding unsigned attributes.");
        }

        if (signedData.HasData)
        {
            throw new ArgumentException("Unexpected SignedData fields.", nameof(cms));
        }

        byte[] extendedSigner = MergeUnsignedAttributes(signerInfo.Span, attributes);
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataContentTypeOid);
            using (writer.PushSequence(ContextSpecificZero))
            using (writer.PushSequence())
            {
                writer.WriteInteger(version);
                writer.WriteEncodedValue(digestAlgorithms.Span);
                writer.WriteEncodedValue(encapContentInfo.Span);
                if (certificates is not null)
                {
                    writer.WriteEncodedValue(certificates.Value.Span);
                }

                if (crls is not null)
                {
                    writer.WriteEncodedValue(crls.Value.Span);
                }

                using (writer.PushSetOf())
                {
                    writer.WriteEncodedValue(extendedSigner);
                }
            }
        }

        return writer.Encode();
    }

    public static List<byte[]> ReadCertificates(ReadOnlySpan<byte> cms)
    {
        AsnReader signedData = OpenSignedData(cms);
        signedData.ReadInteger();
        signedData.ReadEncodedValue();
        signedData.ReadEncodedValue();
        List<byte[]> certificates = [];
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            AsnReader set = signedData.ReadSetOf(ContextSpecificZero);
            while (set.HasData)
            {
                certificates.Add(set.ReadEncodedValue().ToArray());
            }
        }

        return certificates;
    }

    public static byte[]? ReadSignatureTimeStampToken(ReadOnlySpan<byte> cms)
    {
        AsnReader signerInfo = OpenFirstSignerInfo(cms);
        signerInfo.ReadInteger();
        signerInfo.ReadEncodedValue();
        signerInfo.ReadEncodedValue();
        if (signerInfo.HasData && signerInfo.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            signerInfo.ReadEncodedValue();
        }

        signerInfo.ReadEncodedValue();
        signerInfo.ReadOctetString();
        if (!signerInfo.HasData)
        {
            return null;
        }

        AsnReader unsignedAttributes = signerInfo.ReadSetOf(ContextSpecificOne);
        while (unsignedAttributes.HasData)
        {
            AsnReader attribute = unsignedAttributes.ReadSequence();
            if (attribute.ReadObjectIdentifier() == SignatureTimeStampTokenOid)
            {
                return attribute.ReadSetOf().ReadEncodedValue().ToArray();
            }

            if (attribute.HasData)
            {
                attribute.ReadSetOf();
            }
        }

        return null;
    }

    public static byte[] AddDetachedSigner(
        ReadOnlySpan<byte> cms,
        SignaturePreparation preparation,
        SignatureCompletion completion,
        ReadOnlySpan<byte> signingCertificateDer)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        ArgumentNullException.ThrowIfNull(completion);
        EnsureMatchingContext(preparation, completion);
        EnsureCertificateMatchesPreparation(preparation, signingCertificateDer);
        if (cms.IsEmpty)
        {
            throw new ArgumentException("CMS container is empty.", nameof(cms));
        }

        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(signingCertificateDer);
        byte[] implicitSignedAttributes = CreateImplicitSignedAttributes(preparation.DataToBeSigned.Span);
        byte[] newSigner = EncodeSignerInfo(
            certificate,
            implicitSignedAttributes,
            completion.SignatureValue.Span,
            signatureTimeStampToken: default);

        AsnReader root = new(cms.ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = root.ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != SignedDataContentTypeOid)
        {
            throw new ArgumentException("CMS content type must be signedData.", nameof(cms));
        }

        AsnReader explicitSignedData = contentInfo.ReadSequence(ContextSpecificZero);
        AsnReader signedData = explicitSignedData.ReadSequence();
        if (root.HasData || contentInfo.HasData || explicitSignedData.HasData)
        {
            throw new ArgumentException("CMS container has trailing data.", nameof(cms));
        }

        System.Numerics.BigInteger version = signedData.ReadInteger();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();
        List<byte[]> certificates = [];
        ReadOnlyMemory<byte>? crls = null;
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            AsnReader set = signedData.ReadSetOf(ContextSpecificZero);
            while (set.HasData)
            {
                certificates.Add(set.ReadEncodedValue().ToArray());
            }
        }

        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificOne))
        {
            crls = signedData.ReadEncodedValue();
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        List<byte[]> signers = [];
        while (signerInfos.HasData)
        {
            signers.Add(signerInfos.ReadEncodedValue().ToArray());
        }

        if (signedData.HasData)
        {
            throw new ArgumentException("Unexpected SignedData fields.", nameof(cms));
        }

        byte[] newCertificate = signingCertificateDer.ToArray();
        if (!certificates.Any(existing => existing.AsSpan().SequenceEqual(newCertificate)))
        {
            certificates.Add(newCertificate);
        }

        signers.Add(newSigner);
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignedDataContentTypeOid);
            using (writer.PushSequence(ContextSpecificZero))
            using (writer.PushSequence())
            {
                writer.WriteInteger(version);
                writer.WriteEncodedValue(digestAlgorithms.Span);
                writer.WriteEncodedValue(encapContentInfo.Span);
                using (writer.PushSetOf(ContextSpecificZero))
                {
                    foreach (byte[] certificateDer in certificates)
                    {
                        writer.WriteEncodedValue(certificateDer);
                    }
                }

                if (crls is not null)
                {
                    writer.WriteEncodedValue(crls.Value.Span);
                }

                using (writer.PushSetOf())
                {
                    foreach (byte[] signer in signers)
                    {
                        writer.WriteEncodedValue(signer);
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static AsnReader OpenSignedData(ReadOnlySpan<byte> cms)
    {
        AsnReader contentInfo = new AsnReader(cms.ToArray(), AsnEncodingRules.DER).ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != SignedDataContentTypeOid)
        {
            throw new ArgumentException("CMS content type must be signedData.", nameof(cms));
        }

        return contentInfo.ReadSequence(ContextSpecificZero).ReadSequence();
    }

    private static AsnReader OpenFirstSignerInfo(ReadOnlySpan<byte> cms)
    {
        AsnReader signedData = OpenSignedData(cms);
        signedData.ReadInteger();
        signedData.ReadEncodedValue();
        signedData.ReadEncodedValue();
        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificZero))
        {
            signedData.ReadEncodedValue();
        }

        if (signedData.HasData && signedData.PeekTag().HasSameClassAndValue(ContextSpecificOne))
        {
            signedData.ReadEncodedValue();
        }

        return signedData.ReadSetOf().ReadSequence();
    }

    private static byte[] AppendUnsignedTimeStamp(
        ReadOnlySpan<byte> signerInfo,
        ReadOnlySpan<byte> signatureTimeStampToken)
    {
        AsnReader reader = new AsnReader(signerInfo.ToArray(), AsnEncodingRules.DER).ReadSequence();
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(reader.ReadInteger());
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            if (reader.HasData && reader.PeekTag().HasSameClassAndValue(ContextSpecificZero))
            {
                writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            }

            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            writer.WriteOctetString(reader.ReadOctetString());
            if (reader.HasData)
            {
                throw new InvalidOperationException("The CMS already contains unsigned attributes.");
            }

            WriteSignatureTimeStampUnsignedAttributes(writer, signatureTimeStampToken);
        }

        return writer.Encode();
    }

    private static byte[] MergeUnsignedAttributes(
        ReadOnlySpan<byte> signerInfo,
        IReadOnlyList<CmsUnsignedValue> attributes)
    {
        AsnReader reader = new AsnReader(signerInfo.ToArray(), AsnEncodingRules.DER).ReadSequence();
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(reader.ReadInteger());
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            if (reader.HasData && reader.PeekTag().HasSameClassAndValue(ContextSpecificZero))
            {
                writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            }

            writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
            writer.WriteOctetString(reader.ReadOctetString());
            List<byte[]> encodedAttributes = [];
            HashSet<string> existingOids = new(StringComparer.Ordinal);
            if (reader.HasData)
            {
                AsnReader unsignedAttributes = reader.ReadSetOf(ContextSpecificOne);
                while (unsignedAttributes.HasData)
                {
                    ReadOnlyMemory<byte> encoded = unsignedAttributes.ReadEncodedValue();
                    AsnReader attribute = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence();
                    existingOids.Add(attribute.ReadObjectIdentifier());
                    encodedAttributes.Add(encoded.ToArray());
                }
            }

            if (reader.HasData)
            {
                throw new InvalidOperationException("Unexpected SignerInfo fields.");
            }

            foreach (CmsUnsignedValue attribute in attributes)
            {
                ArgumentNullException.ThrowIfNull(attribute);
                if (!existingOids.Add(attribute.Oid))
                {
                    throw new InvalidOperationException(
                        $"The CMS already contains unsigned attribute {attribute.Oid}.");
                }

                encodedAttributes.Add(EncodeUnsignedAttribute(attribute));
            }

            using (writer.PushSetOf(ContextSpecificOne))
            {
                foreach (byte[] encoded in encodedAttributes)
                {
                    writer.WriteEncodedValue(encoded);
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] EncodeUnsignedAttribute(CmsUnsignedValue attribute)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(attribute.Oid);
            using (writer.PushSetOf())
            {
                writer.WriteEncodedValue(attribute.Value);
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
        ReadOnlySpan<byte> signatureValue,
        ReadOnlySpan<byte> signatureTimeStampToken)
    {
        using (writer.PushSetOf())
        {
            writer.WriteEncodedValue(EncodeSignerInfo(
                certificate,
                implicitSignedAttributes,
                signatureValue,
                signatureTimeStampToken));
        }
    }

    private static byte[] EncodeSignerInfo(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> implicitSignedAttributes,
        ReadOnlySpan<byte> signatureValue,
        ReadOnlySpan<byte> signatureTimeStampToken)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
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
            if (!signatureTimeStampToken.IsEmpty)
            {
                WriteSignatureTimeStampUnsignedAttributes(writer, signatureTimeStampToken);
            }
        }

        return writer.Encode();
    }

    private static void WriteSignatureTimeStampUnsignedAttributes(
        AsnWriter writer,
        ReadOnlySpan<byte> signatureTimeStampToken)
    {
        using (writer.PushSetOf(ContextSpecificOne))
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(SignatureTimeStampTokenOid);
            using (writer.PushSetOf())
            {
                writer.WriteEncodedValue(signatureTimeStampToken);
            }
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
