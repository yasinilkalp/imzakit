using System.Security.Cryptography;
using ImzaKit.Certificate.Models;
using ImzaKit.Core.Net;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ImzaKit.Revocation.Online;

public sealed class OnlineRevocationClient(
    IExternalResourceFetcher fetcher,
    IRevocationEvidenceCache cache,
    IRevocationEvidenceParser parser)
{
    public async Task<RevocationEvidence?> TryFetchOcspAsync(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);

        string key = OcspKey(certificate, issuer);
        if (cache.TryGet(key, nowUtc, out RevocationEvidence cached))
        {
            return cached;
        }

        if (certificate.OcspUris.Count == 0)
        {
            return null;
        }

        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        byte[] requestDer = CreateOcspRequest(certificate, issuer, nonce);
        InvalidOperationException? lastTransient = null;
        for (int index = 0; index < certificate.OcspUris.Count; index++)
        {
            Uri uri = certificate.OcspUris[index];
            try
            {
                ExternalResourceFetchResult fetched = await fetcher.FetchAsync(
                    new ExternalResourceFetchRequest(
                        uri,
                        "POST",
                        requestDer,
                        "application/ocsp-request",
                        ["application/ocsp-response"],
                        MaxResponseBytes: 65536,
                        Timeout: TimeSpan.FromSeconds(15),
                        MaxRedirects: 0),
                    cancellationToken).ConfigureAwait(false);
                EnsureNonceMatches(fetched.Body, nonce);
                RevocationEvidence evidence = new(
                    RevocationEvidenceType.Ocsp,
                    RevocationEvidenceSource.Online,
                    fetched.Body);
                ParsedRevocationEvidence parsed = parser.Parse(evidence, certificate, issuer);
                if (parsed.TargetMatches
                    && parsed.SignatureValid
                    && parsed.ResponderAuthorized
                    && parsed.NextUpdateUtc is DateTimeOffset nextUpdate)
                {
                    cache.Store(key, RevocationEvidenceType.Ocsp, fetched.Body, nextUpdate, nowUtc);
                }

                return evidence;
            }
            catch (InvalidOperationException exception) when (exception.Message == "IMZAKIT.OCSP.NONCE_MISMATCH")
            {
                throw;
            }
            catch (InvalidOperationException exception) when (
                IsTransient(exception.Message) && index < certificate.OcspUris.Count - 1)
            {
                lastTransient = exception;
            }
            catch (InvalidOperationException exception) when (
                exception.Message is "IMZAKIT.NET.HTTP_ERROR" or "IMZAKIT.NET.UNEXPECTED_CONTENT_TYPE"
                    or "IMZAKIT.NET.PAYLOAD_TOO_LARGE" or "IMZAKIT.NET.REDIRECT_NOT_FOLLOWED"
                && index < certificate.OcspUris.Count - 1)
            {
                lastTransient = exception;
            }
        }

        return lastTransient is null ? null : throw lastTransient;
    }

    public async Task<RevocationEvidence?> TryFetchCrlAsync(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fetcher);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);

        string key = CrlKey(issuer);
        if (cache.TryGet(key, nowUtc, out RevocationEvidence cached))
        {
            return cached;
        }

        if (certificate.CrlDistributionUris.Count == 0)
        {
            return null;
        }

        InvalidOperationException? lastTransient = null;
        for (int index = 0; index < certificate.CrlDistributionUris.Count; index++)
        {
            Uri uri = certificate.CrlDistributionUris[index];
            try
            {
                ExternalResourceFetchResult fetched = await fetcher.FetchAsync(
                    new ExternalResourceFetchRequest(
                        uri,
                        "GET",
                        [],
                        null,
                        ["application/pkix-crl", "application/octet-stream"],
                        MaxResponseBytes: 2 * 1024 * 1024,
                        Timeout: TimeSpan.FromSeconds(15),
                        MaxRedirects: 0),
                    cancellationToken).ConfigureAwait(false);
                RevocationEvidence evidence = new(
                    RevocationEvidenceType.Crl,
                    RevocationEvidenceSource.Online,
                    fetched.Body);
                ParsedRevocationEvidence parsed = parser.Parse(evidence, certificate, issuer);
                if (parsed.TargetMatches
                    && parsed.SignatureValid
                    && parsed.ResponderAuthorized
                    && parsed.NextUpdateUtc is DateTimeOffset nextUpdate)
                {
                    cache.Store(key, RevocationEvidenceType.Crl, fetched.Body, nextUpdate, nowUtc);
                }

                return evidence;
            }
            catch (InvalidOperationException exception) when (
                IsTransient(exception.Message) && index < certificate.CrlDistributionUris.Count - 1)
            {
                lastTransient = exception;
            }
            catch (InvalidOperationException exception) when (
                exception.Message is "IMZAKIT.NET.HTTP_ERROR" or "IMZAKIT.NET.UNEXPECTED_CONTENT_TYPE"
                    or "IMZAKIT.NET.PAYLOAD_TOO_LARGE" or "IMZAKIT.NET.REDIRECT_NOT_FOLLOWED"
                && index < certificate.CrlDistributionUris.Count - 1)
            {
                lastTransient = exception;
            }
        }

        return lastTransient is null ? null : throw lastTransient;
    }

    public static string OcspKey(CertificateDescriptor certificate, CertificateDescriptor issuer) =>
        $"ocsp:{certificate.Sha256Thumbprint}:{issuer.Sha256Thumbprint}";

    public static string CrlKey(CertificateDescriptor issuer) =>
        $"crl:{issuer.Sha256Thumbprint}";

    private static byte[] CreateOcspRequest(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        byte[] nonce)
    {
        X509CertificateParser parser = new();
        BcX509Certificate issuerCertificate = parser.ReadCertificate(issuer.ExportDer());
        BcX509Certificate targetCertificate = parser.ReadCertificate(certificate.ExportDer());
        OcspReqGenerator generator = new();
        generator.AddRequest(new CertificateID(
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance),
            issuerCertificate,
            targetCertificate.SerialNumber));
        X509ExtensionsGenerator extensions = new();
        extensions.AddExtension(OcspObjectIdentifiers.PkixOcspNonce, false, nonce);
        generator.SetRequestExtensions(extensions.Generate());
        return generator.Generate().GetEncoded();
    }

    private static void EnsureNonceMatches(byte[] responseDer, byte[] nonce)
    {
        OcspResp response = new(responseDer);
        if (response.GetResponseObject() is not BasicOcspResp basic)
        {
            throw new InvalidOperationException("IMZAKIT.OCSP.NONCE_MISMATCH");
        }

        Asn1OctetString? extension = basic.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
        if (extension is null || !NonceEquals(nonce, extension.GetOctets()))
        {
            throw new InvalidOperationException("IMZAKIT.OCSP.NONCE_MISMATCH");
        }
    }

    private static bool NonceEquals(byte[] expected, byte[] actual)
    {
        if (expected.AsSpan().SequenceEqual(actual))
        {
            return true;
        }

        try
        {
            Asn1OctetString inner = Asn1OctetString.GetInstance(Asn1Object.FromByteArray(actual));
            return expected.AsSpan().SequenceEqual(inner.GetOctets());
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidCastException or IOException)
        {
            return false;
        }
    }

    private static bool IsTransient(string code) =>
        code is "IMZAKIT.NET.TRANSIENT_HTTP";
}
