using System.Formats.Asn1;
using System.Security.Cryptography;
using ImzaKit.Cms.Completion;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.CAdES;

public static class CadesExtender
{
    private const string CertificateValuesOid = "1.2.840.113549.1.9.16.2.23";
    private const string RevocationValuesOid = "1.2.840.113549.1.9.16.2.24";
    private const string ArchiveTimeStampOid = "1.2.840.113549.1.9.16.2.48";
    private static readonly Asn1Tag ContextSpecificZero =
        new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag ContextSpecificOne =
        new(TagClass.ContextSpecific, 1, isConstructed: true);

    public static async Task<byte[]> ExtendBaselineT(
        byte[] cms,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cms);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);
        byte[] signatureValue = CmsSignedDataCompleter.ReadSignatureValue(cms);
        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(signatureValue),
            authorities,
            cancellationToken).ConfigureAwait(false);
        return CmsSignedDataCompleter.AddSignatureTimeStamp(cms, timestamp.TokenDer);
    }

    public static byte[] ExtendBaselineLt(byte[] cms, CadesLongTermEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(cms);
        ArgumentNullException.ThrowIfNull(evidence);
        if (!CmsSignedDataCompleter.HasSignatureTimeStamp(cms))
        {
            throw new InvalidOperationException("CAdES B-LT requires a B-T signature timestamp.");
        }

        if (CmsSignedDataCompleter.HasUnsignedAttribute(cms, CertificateValuesOid)
            || CmsSignedDataCompleter.HasUnsignedAttribute(cms, RevocationValuesOid))
        {
            throw new InvalidOperationException("The CMS already contains CAdES B-LT attributes.");
        }

        List<CmsUnsignedValue> attributes =
        [
            new(CertificateValuesOid, EncodeCertificateValues(evidence.Certificates))
        ];
        if (evidence.OcspResponses.Count > 0 || evidence.CertificateRevocationLists.Count > 0)
        {
            attributes.Add(new(RevocationValuesOid, EncodeRevocationValues(evidence)));
        }

        return CmsSignedDataCompleter.AddUnsignedAttributes(cms, attributes);
    }

    public static async Task<byte[]> ExtendBaselineLta(
        byte[] cms,
        Rfc3161TimeStampClient timeStampClient,
        IReadOnlyList<TimeStampAuthority> authorities,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cms);
        ArgumentNullException.ThrowIfNull(timeStampClient);
        ArgumentNullException.ThrowIfNull(authorities);
        if (!CmsSignedDataCompleter.HasSignatureTimeStamp(cms)
            || (!CmsSignedDataCompleter.HasUnsignedAttribute(cms, CertificateValuesOid)
                && !CmsSignedDataCompleter.HasUnsignedAttribute(cms, RevocationValuesOid)))
        {
            throw new InvalidOperationException("CAdES B-LTA requires B-LT certificate-values or revocation-values.");
        }

        if (CmsSignedDataCompleter.HasUnsignedAttribute(cms, ArchiveTimeStampOid))
        {
            throw new InvalidOperationException("The CMS already contains a CAdES archive time-stamp.");
        }

        Rfc3161TimeStampResult timestamp = await timeStampClient.RequestAsync(
            SHA256.HashData(cms),
            authorities,
            cancellationToken).ConfigureAwait(false);
        return CmsSignedDataCompleter.AddUnsignedAttributes(
            cms,
            [new CmsUnsignedValue(ArchiveTimeStampOid, timestamp.TokenDer)]);
    }

    private static byte[] EncodeCertificateValues(IReadOnlyList<byte[]> certificates)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (byte[] certificate in certificates)
            {
                writer.WriteEncodedValue(certificate);
            }
        }

        return writer.Encode();
    }

    private static byte[] EncodeRevocationValues(CadesLongTermEvidence evidence)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (evidence.CertificateRevocationLists.Count > 0)
            {
                using (writer.PushSequence(ContextSpecificZero))
                {
                    foreach (byte[] crl in evidence.CertificateRevocationLists)
                    {
                        writer.WriteEncodedValue(crl);
                    }
                }
            }

            if (evidence.OcspResponses.Count > 0)
            {
                using (writer.PushSequence(ContextSpecificOne))
                {
                    foreach (byte[] ocsp in evidence.OcspResponses)
                    {
                        writer.WriteEncodedValue(ocsp);
                    }
                }
            }
        }

        return writer.Encode();
    }
}
