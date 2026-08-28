using System.Security.Cryptography;
using ImzaKit.Certificate.Models;
using ImzaKit.Cms.Completion;
using ImzaKit.PAdES.Dss;
using ImzaKit.PAdES.Reading;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Online;

namespace ImzaKit.PAdES.Completion;

public static class PadesLongTermEvidenceCollector
{
    public static async Task<PadesValidationMaterial> CollectAsync(
        byte[] signedPdf,
        OnlineRevocationClient client,
        DateTimeOffset nowUtc,
        IEnumerable<byte[]>? additionalCertificates = null,
        IEnumerable<byte[]>? additionalOcspResponses = null,
        IEnumerable<byte[]>? additionalCertificateRevocationLists = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(client);
        if (!PdfCadesSignatureLocator.TryRead(signedPdf, out _, out byte[] cms, out _, out _))
        {
            throw new ArgumentException("The PDF does not contain a PAdES CAdES signature.", nameof(signedPdf));
        }

        Dictionary<string, byte[]> certificates = new(StringComparer.Ordinal);
        AddCertificates(certificates, CmsSignedDataCompleter.ReadCertificates(cms));
        byte[]? timestamp = CmsSignedDataCompleter.ReadSignatureTimeStampToken(cms);
        if (timestamp is not null)
        {
            AddCertificates(certificates, CmsSignedDataCompleter.ReadCertificates(timestamp));
        }

        AddCertificates(certificates, additionalCertificates);

        List<byte[]> ocspResponses = Copy(additionalOcspResponses);
        List<byte[]> crls = Copy(additionalCertificateRevocationLists);
        HashSet<string> evidenceDigests = new(StringComparer.Ordinal);
        foreach (byte[] encoded in ocspResponses.Concat(crls))
        {
            evidenceDigests.Add(Convert.ToHexString(SHA256.HashData(encoded)));
        }

        List<CertificateDescriptor> descriptors = [.. certificates.Values
            .Select(der => CertificateDescriptor.FromDer(der, CertificateSource.Embedded))];
        foreach (CertificateDescriptor certificate in descriptors)
        {
            CertificateDescriptor? issuer = FindIssuer(certificate, descriptors);
            if (issuer is null)
            {
                continue;
            }

            await AddEvidence(
                client,
                certificate,
                issuer,
                nowUtc,
                ocspResponses,
                crls,
                evidenceDigests,
                cancellationToken).ConfigureAwait(false);
        }

        return new PadesValidationMaterial(certificates.Values, ocspResponses, crls);
    }

    private static async Task AddEvidence(
        OnlineRevocationClient client,
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        DateTimeOffset nowUtc,
        List<byte[]> ocspResponses,
        List<byte[]> crls,
        HashSet<string> evidenceDigests,
        CancellationToken cancellationToken)
    {
        try
        {
            RevocationEvidence? ocsp = await client.TryFetchOcspAsync(
                certificate, issuer, nowUtc, cancellationToken).ConfigureAwait(false);
            if (ocsp is not null)
            {
                byte[] encoded = ocsp.ExportEncoded();
                if (AddUnique(evidenceDigests, encoded))
                {
                    ocspResponses.Add(encoded);
                    return;
                }
            }
        }
        catch (InvalidOperationException)
        {
        }

        try
        {
            RevocationEvidence? crl = await client.TryFetchCrlAsync(
                certificate, issuer, nowUtc, cancellationToken).ConfigureAwait(false);
            if (crl is not null)
            {
                byte[] encoded = crl.ExportEncoded();
                if (AddUnique(evidenceDigests, encoded))
                {
                    crls.Add(encoded);
                }
            }
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static CertificateDescriptor? FindIssuer(
        CertificateDescriptor certificate,
        IReadOnlyList<CertificateDescriptor> pool)
    {
        foreach (CertificateDescriptor candidate in pool)
        {
            if (string.Equals(candidate.Sha256Thumbprint, certificate.Sha256Thumbprint, StringComparison.Ordinal))
            {
                continue;
            }

            if (string.Equals(candidate.Subject, certificate.Issuer, StringComparison.Ordinal)
                || (certificate.AuthorityKeyIdentifier is not null
                    && string.Equals(
                        candidate.SubjectKeyIdentifier,
                        certificate.AuthorityKeyIdentifier,
                        StringComparison.OrdinalIgnoreCase)))
            {
                return candidate;
            }
        }

        return null;
    }

    private static void AddCertificates(Dictionary<string, byte[]> certificates, IEnumerable<byte[]>? values)
    {
        if (values is null)
        {
            return;
        }

        foreach (byte[] value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Length == 0)
            {
                continue;
            }

            certificates[Convert.ToHexString(SHA256.HashData(value))] = value.ToArray();
        }
    }

    private static List<byte[]> Copy(IEnumerable<byte[]>? values)
    {
        List<byte[]> copy = [];
        if (values is null)
        {
            return copy;
        }

        foreach (byte[] value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Length == 0)
            {
                continue;
            }

            copy.Add(value.ToArray());
        }

        return copy;
    }

    private static bool AddUnique(HashSet<string> digests, byte[] encoded) =>
        digests.Add(Convert.ToHexString(SHA256.HashData(encoded)));
}
