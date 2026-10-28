using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using ImzaKit.Timestamp.Rfc3161;

namespace ImzaKit.CAdES;

public static class CadesSignatureTimeStampVerifier
{
    private const string SignatureTimeStampOid = "1.2.840.113549.1.9.16.2.14";

    // Returns null when the signer carries no signature time-stamp. Otherwise the first token that
    // verifies over this signer's signature value wins; if none does, the first failure is returned.
    public static Rfc3161TimeStampTokenVerification? Verify(SignerInfo signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        byte[] signatureValue = signer.GetSignature();
        Rfc3161TimeStampTokenVerification? firstFailure = null;
        foreach (CryptographicAttributeObject attribute in signer.UnsignedAttributes)
        {
            if (attribute.Oid?.Value != SignatureTimeStampOid)
            {
                continue;
            }

            foreach (AsnEncodedData token in attribute.Values)
            {
                Rfc3161TimeStampTokenVerification verification =
                    Rfc3161TimeStampTokenVerifier.Verify(token.RawData, signatureValue);
                if (verification.IsValid)
                {
                    return verification;
                }

                firstFailure ??= verification;
            }
        }

        return firstFailure;
    }
}
