using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ImzaKit.Certificate.Models;

public sealed class CertificateDescriptor
{
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    private readonly byte[] _der;

    private CertificateDescriptor(byte[] der, CertificateSource source, X509Certificate2 certificate)
    {
        _der = der;
        Source = source;
        Sha256Thumbprint = Convert.ToHexString(SHA256.HashData(der));
        Subject = certificate.Subject;
        Issuer = certificate.Issuer;
        SerialNumber = certificate.SerialNumber;
        SubjectKeyIdentifier = certificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .Select(extension => extension.SubjectKeyIdentifier)
            .FirstOrDefault();
        AuthorityKeyIdentifier = ReadAuthorityKeyIdentifier(certificate);
        OcspUris = ReadHttpUris(ReadOcspUris(certificate));
        CrlDistributionUris = ReadHttpUris(ReadCrlDistributionUris(certificate));
        NotBeforeUtc = certificate.NotBefore.ToUniversalTime();
        NotAfterUtc = certificate.NotAfter.ToUniversalTime();
    }

    public CertificateSource Source { get; }

    public string Sha256Thumbprint { get; }

    public string Subject { get; }

    public string Issuer { get; }

    public string SerialNumber { get; }

    public string? SubjectKeyIdentifier { get; }

    public string? AuthorityKeyIdentifier { get; }

    public IReadOnlyList<Uri> OcspUris { get; }

    public IReadOnlyList<Uri> CrlDistributionUris { get; }

    public DateTimeOffset NotBeforeUtc { get; }

    public DateTimeOffset NotAfterUtc { get; }

    public static CertificateDescriptor FromDer(ReadOnlySpan<byte> der, CertificateSource source)
    {
        if (der.IsEmpty)
        {
            throw new ArgumentException("Certificate DER cannot be empty.", nameof(der));
        }

        byte[] copy = der.ToArray();
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(copy);
        return new(copy, source, certificate);
    }

    public byte[] ExportDer() => _der.ToArray();

    private static string? ReadAuthorityKeyIdentifier(X509Certificate2 certificate)
    {
        X509Extension? extension = certificate.Extensions[AuthorityKeyIdentifierOid];
        if (extension is null)
        {
            return null;
        }

        try
        {
            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            Asn1Tag keyIdentifierTag = new(TagClass.ContextSpecific, 0);
            return sequence.HasData && sequence.PeekTag().HasSameClassAndValue(keyIdentifierTag)
                ? Convert.ToHexString(sequence.ReadOctetString(keyIdentifierTag))
                : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static Uri[] ReadOcspUris(X509Certificate2 certificate)
    {
        X509Extension? extension = certificate.Extensions["1.3.6.1.5.5.7.1.1"];
        if (extension is null)
        {
            return [];
        }

        try
        {
            X509AuthorityInformationAccessExtension aia = new(extension.RawData, extension.Critical);
            List<Uri> uris = [];
            foreach (string value in aia.EnumerateOcspUris())
            {
                if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
                {
                    uris.Add(uri);
                }
            }

            return ReadHttpUris(uris);
        }
        catch (CryptographicException)
        {
            return [];
        }
    }

    private static Uri[] ReadCrlDistributionUris(X509Certificate2 certificate)
    {
        X509Extension? extension = certificate.Extensions["2.5.29.31"];
        if (extension is null)
        {
            return [];
        }

        try
        {
            List<Uri> uris = [];
            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader points = reader.ReadSequence();
            while (points.HasData)
            {
                AsnReader point = points.ReadSequence();
                if (!point.HasData)
                {
                    continue;
                }

                Asn1Tag distributionPointTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
                if (!point.PeekTag().HasSameClassAndValue(distributionPointTag))
                {
                    continue;
                }

                AsnReader distributionPoint = point.ReadSequence(distributionPointTag);
                Asn1Tag fullNameTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
                if (!distributionPoint.HasData || !distributionPoint.PeekTag().HasSameClassAndValue(fullNameTag))
                {
                    continue;
                }

                AsnReader names = distributionPoint.ReadSequence(fullNameTag);
                Asn1Tag uriTag = new(TagClass.ContextSpecific, 6);
                while (names.HasData)
                {
                    if (!names.PeekTag().HasSameClassAndValue(uriTag))
                    {
                        names.ReadEncodedValue();
                        continue;
                    }

                    string value = names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);
                    if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
                    {
                        uris.Add(uri);
                    }
                }
            }

            return uris.ToArray();
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    private static Uri[] ReadHttpUris(IEnumerable<Uri> uris) =>
        uris.Where(static uri =>
                uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            .ToArray();
}
