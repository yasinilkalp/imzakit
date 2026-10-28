using System.Security.Cryptography;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace ImzaKit.Timestamp.Rfc3161;

public sealed record Rfc3161TimeStampTokenVerification(
    bool IsValid,
    string? FailureCode,
    DateTimeOffset? GenerationTimeUtc)
{
    internal static Rfc3161TimeStampTokenVerification Invalid(string failureCode) => new(false, failureCode, null);
}

// Verifies a time-stamp token on its own: the TSA's CMS signature with the certificate embedded in
// the token, the ESSCertID binding, the critical timeStamping EKU, the certificate's validity at genTime,
// and that the message imprint covers the given data. Trust in the TSA chain is the caller's decision.
public static class Rfc3161TimeStampTokenVerifier
{
    public static Rfc3161TimeStampTokenVerification Verify(ReadOnlySpan<byte> tokenDer, ReadOnlySpan<byte> coveredData)
    {
        TimeStampToken token;
        try
        {
            token = new TimeStampToken(new CmsSignedData(tokenDer.ToArray()));
        }
        catch (Exception exception) when (exception is CmsException or TspException or IOException
            or ArgumentException or InvalidCastException or InvalidOperationException)
        {
            return Rfc3161TimeStampTokenVerification.Invalid("IMZAKIT.TS.TOKEN_MALFORMED");
        }

        byte[]? digest = Hash(token.TimeStampInfo.MessageImprintAlgOid, coveredData);
        if (digest is null)
        {
            return Rfc3161TimeStampTokenVerification.Invalid("IMZAKIT.TS.IMPRINT_ALGORITHM_UNSUPPORTED");
        }

        if (!CryptographicOperations.FixedTimeEquals(digest, token.TimeStampInfo.GetMessageImprintDigest()))
        {
            return Rfc3161TimeStampTokenVerification.Invalid("IMZAKIT.TS.IMPRINT_MISMATCH");
        }

        string? failure = VerifySignature(token);
        return failure is null
            ? new(true, null, new DateTimeOffset(DateTime.SpecifyKind(token.TimeStampInfo.GenTime, DateTimeKind.Utc)))
            : Rfc3161TimeStampTokenVerification.Invalid(failure);
    }

    internal static string? VerifySignature(TimeStampToken token)
    {
        X509Certificate? signer = token.GetCertificates()
            .EnumerateMatches(token.SignerID)
            .FirstOrDefault();
        if (signer is null)
        {
            return "IMZAKIT.TS.CERTIFICATE_MISSING";
        }

        try
        {
            token.Validate(signer);
            return null;
        }
        catch (TspException)
        {
            return "IMZAKIT.TS.INVALID_TOKEN";
        }
    }

    private static byte[]? Hash(string algorithmOid, ReadOnlySpan<byte> data) => algorithmOid switch
    {
        "2.16.840.1.101.3.4.2.1" => SHA256.HashData(data),
        "2.16.840.1.101.3.4.2.2" => SHA384.HashData(data),
        "2.16.840.1.101.3.4.2.3" => SHA512.HashData(data),
        _ => null,
    };
}
