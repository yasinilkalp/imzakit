using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.CAdES;

public static class CadesValidator
{
    private const string SignatureTimeStampOid = "1.2.840.113549.1.9.16.2.14";
    private const string CertificateValuesOid = "1.2.840.113549.1.9.16.2.23";
    private const string RevocationValuesOid = "1.2.840.113549.1.9.16.2.24";
    private const string ArchiveTimeStampOid = "1.2.840.113549.1.9.16.2.48";

    public static CadesValidationReport ValidateDetached(ReadOnlySpan<byte> cms, ReadOnlySpan<byte> content)
    {
        if (cms.IsEmpty)
        {
            throw new ArgumentException("CMS container is empty.", nameof(cms));
        }

        SignedCms signed = new(new ContentInfo(content.ToArray()), detached: true);
        try
        {
            signed.Decode(cms.ToArray());
        }
        catch (CryptographicException)
        {
            return new(
                CadesStatus.Failed,
                [new(1, CadesStatus.Failed, null, CadesBaselineLevel.BB, ["InvalidCms"])]);
        }

        if (signed.SignerInfos.Count == 0)
        {
            return new(CadesStatus.Failed, []);
        }

        List<CadesSignerReport> signers = [];
        for (int index = 0; index < signed.SignerInfos.Count; index++)
        {
            signers.Add(Evaluate(signed.SignerInfos[index], index + 1));
        }

        CadesStatus status = signers.Any(signer => signer.CryptographicStatus == CadesStatus.Failed)
            ? CadesStatus.Failed
            : CadesStatus.Passed;
        return new(status, signers);
    }

    private static CadesSignerReport Evaluate(SignerInfo signer, int index)
    {
        List<string> findings = [];
        CadesStatus crypto = CadesStatus.Passed;
        try
        {
            signer.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException)
        {
            crypto = CadesStatus.Failed;
            findings.Add("CmsSignatureInvalid");
        }

        X509Certificate2? certificate = signer.Certificate;
        string? fingerprint = certificate is null
            ? null
            : Convert.ToHexString(SHA256.HashData(certificate.RawData));
        if (fingerprint is null)
        {
            findings.Add("SignerCertificateMissing");
        }

        return new(
            index,
            crypto,
            fingerprint,
            DetectLevel(signer),
            findings);
    }

    private static string DetectLevel(SignerInfo signer)
    {
        bool timestamp = HasOid(signer, SignatureTimeStampOid);
        bool longTerm = HasOid(signer, CertificateValuesOid) || HasOid(signer, RevocationValuesOid);
        bool archive = HasOid(signer, ArchiveTimeStampOid);
        return (timestamp, longTerm, archive) switch
        {
            (true, true, true) => CadesBaselineLevel.BLTA,
            (true, true, false) => CadesBaselineLevel.BLT,
            (true, false, _) => CadesBaselineLevel.BT,
            _ => CadesBaselineLevel.BB
        };
    }

    private static bool HasOid(SignerInfo signer, string oid)
    {
        foreach (CryptographicAttributeObject attribute in signer.UnsignedAttributes)
        {
            if (attribute.Oid?.Value == oid)
            {
                return true;
            }
        }

        return false;
    }
}
