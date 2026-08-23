using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;

namespace ImzaKit.Certificate.Validation;

public sealed class CertificateChainValidator : ICertificateChainValidator
{
    private static readonly HashSet<string> DisallowedSignatureAlgorithms = new(StringComparer.Ordinal)
    {
        "1.2.840.113549.1.1.4",
        "1.2.840.113549.1.1.5",
        "1.2.840.10040.4.3",
        "1.2.840.10045.4.1"
    };

    public CertificateChainValidationResult Validate(CertificateChainValidationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        List<CertificateValidationFailure> failures = [];
        X509Certificate2[] certificates = request.Chain.Certificates
            .Select(descriptor => X509CertificateLoader.LoadCertificate(descriptor.ExportDer()))
            .ToArray();

        try
        {
            ValidateTimeAndAlgorithms(certificates, request.ValidationTimeUtc, failures);
            ValidateKeyUsageAndConstraints(certificates, failures);
            ValidateChainCryptography(certificates, request.ValidationTimeUtc, failures);
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                certificate.Dispose();
            }
        }

        CertificateValidationFailure[] distinctFailures = failures.Distinct().ToArray();
        return new(
            distinctFailures.Length == 0 ? CertificateChainStatus.Valid : CertificateChainStatus.Invalid,
            distinctFailures);
    }

    private static void ValidateTimeAndAlgorithms(
        IEnumerable<X509Certificate2> certificates,
        DateTimeOffset validationTimeUtc,
        List<CertificateValidationFailure> failures)
    {
        foreach (X509Certificate2 certificate in certificates)
        {
            if (validationTimeUtc < certificate.NotBefore.ToUniversalTime())
            {
                failures.Add(CertificateValidationFailure.NotYetValid);
            }

            if (validationTimeUtc > certificate.NotAfter.ToUniversalTime())
            {
                failures.Add(CertificateValidationFailure.Expired);
            }

            if (certificate.SignatureAlgorithm.Value is string oid
                && DisallowedSignatureAlgorithms.Contains(oid))
            {
                failures.Add(CertificateValidationFailure.AlgorithmDisallowed);
            }
        }
    }

    private static void ValidateKeyUsageAndConstraints(
        X509Certificate2[] certificates,
        List<CertificateValidationFailure> failures)
    {
        X509KeyUsageExtension? leafUsage = certificates[0].Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();
        if (leafUsage is null || !leafUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
        {
            failures.Add(CertificateValidationFailure.LeafDigitalSignatureMissing);
        }

        for (int index = 1; index < certificates.Length; index++)
        {
            X509Certificate2 issuer = certificates[index];
            X509BasicConstraintsExtension? constraints = issuer.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .FirstOrDefault();
            if (constraints is null || !constraints.CertificateAuthority)
            {
                failures.Add(CertificateValidationFailure.IssuerIsNotCa);
            }

            X509KeyUsageExtension? usage = issuer.Extensions
                .OfType<X509KeyUsageExtension>()
                .FirstOrDefault();
            if (usage is null || !usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
            {
                failures.Add(CertificateValidationFailure.IssuerKeyCertSignMissing);
            }
        }
    }

    private static void ValidateChainCryptography(
        X509Certificate2[] certificates,
        DateTimeOffset validationTimeUtc,
        List<CertificateValidationFailure> failures)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certificates[^1]);
        for (int index = 1; index < certificates.Length - 1; index++)
        {
            chain.ChainPolicy.ExtraStore.Add(certificates[index]);
        }

        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = validationTimeUtc.UtcDateTime;
        if (!chain.Build(certificates[0])
            && chain.ChainStatus.Any(status => status.Status is not X509ChainStatusFlags.NotTimeValid))
        {
            failures.Add(CertificateValidationFailure.InvalidSignature);
        }
    }
}
