using System.Security.Cryptography.Xml;

namespace ImzaKit.XAdES;

public static class XadesXmlAlgorithms
{
    public const string ExclusiveCanonicalization = SignedXml.XmlDsigExcC14NTransformUrl;
    public const string EnvelopedSignature = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
    public const string Sha256Digest = SignedXml.XmlDsigSHA256Url;
    public const string RsaSha256 = SignedXml.XmlDsigRSASHA256Url;
    public const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";
    public const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";
    public const string DetachedObjectId = "imzakit-detached";
    public const string DetachedUri = "#" + DetachedObjectId;

    private static readonly HashSet<string> Canonicalization = new(StringComparer.Ordinal)
    {
        ExclusiveCanonicalization
    };

    private static readonly HashSet<string> Transforms = new(StringComparer.Ordinal)
    {
        ExclusiveCanonicalization,
        EnvelopedSignature
    };

    public static bool IsAllowedCanonicalization(string? algorithm) =>
        algorithm is not null && Canonicalization.Contains(algorithm);

    public static bool IsAllowedTransform(string? algorithm) =>
        algorithm is not null && Transforms.Contains(algorithm);

    public static bool IsAllowedDigest(string? algorithm) =>
        string.Equals(algorithm, Sha256Digest, StringComparison.Ordinal);

    public static bool IsAllowedSignatureMethod(string? algorithm) =>
        string.Equals(algorithm, RsaSha256, StringComparison.Ordinal);

    public static bool IsAllowedReferenceUri(string? uri)
    {
        if (string.IsNullOrEmpty(uri))
        {
            return true;
        }

        return uri[0] == '#'
            && uri.Length > 1
            && uri.AsSpan(1).IndexOf('#') < 0
            && uri.AsSpan(1).IndexOf('/') < 0
            && uri.AsSpan(1).IndexOf(':') < 0;
    }
}
