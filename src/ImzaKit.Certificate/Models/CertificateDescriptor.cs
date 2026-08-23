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
}
