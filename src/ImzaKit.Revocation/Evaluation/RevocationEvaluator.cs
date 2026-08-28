using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Online;
using ImzaKit.Revocation.Parsing;

namespace ImzaKit.Revocation.Evaluation;

public sealed class RevocationEvaluator(
    IRevocationEvidenceParser parser,
    OnlineRevocationClient onlineClient) : IRevocationEvaluator
{
    public async Task<OfflineRevocationResult> EvaluateAsync(
        RevocationEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(onlineClient);
        ArgumentNullException.ThrowIfNull(request);

        List<CertificateRevocationResult> results = [];
        for (int index = 0; index < request.Chain.Certificates.Count - 1; index++)
        {
            results.Add(await EvaluateCertificateAsync(
                request.Chain.Certificates[index],
                request.Chain.Certificates[index + 1],
                request,
                cancellationToken).ConfigureAwait(false));
        }

        return new(Aggregate(results), results.ToArray());
    }

    private async Task<CertificateRevocationResult> EvaluateCertificateAsync(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        RevocationEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        if (TryEvaluateSupplied(certificate, issuer, request, RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Embedded, out CertificateRevocationResult embeddedOcsp))
        {
            return embeddedOcsp;
        }

        if (TryEvaluateSupplied(certificate, issuer, request, RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Local, out CertificateRevocationResult cachedOcsp))
        {
            return cachedOcsp;
        }

        if (request.AllowOnline)
        {
            CertificateRevocationResult? onlineOcsp = await TryOnlineAsync(
                certificate,
                issuer,
                request,
                RevocationEvidenceType.Ocsp,
                () => onlineClient.TryFetchOcspAsync(certificate, issuer, request.ValidationTimeUtc, cancellationToken)).ConfigureAwait(false);
            if (onlineOcsp is not null)
            {
                return onlineOcsp;
            }
        }

        if (TryEvaluateSupplied(certificate, issuer, request, RevocationEvidenceType.Crl, RevocationEvidenceSource.Embedded, out CertificateRevocationResult embeddedCrl))
        {
            return embeddedCrl;
        }

        if (TryEvaluateSupplied(certificate, issuer, request, RevocationEvidenceType.Crl, RevocationEvidenceSource.Local, out CertificateRevocationResult cachedCrl))
        {
            return cachedCrl;
        }

        if (request.AllowOnline)
        {
            CertificateRevocationResult? onlineCrl = await TryOnlineAsync(
                certificate,
                issuer,
                request,
                RevocationEvidenceType.Crl,
                () => onlineClient.TryFetchCrlAsync(certificate, issuer, request.ValidationTimeUtc, cancellationToken)).ConfigureAwait(false);
            if (onlineCrl is not null)
            {
                return onlineCrl;
            }
        }

        return Unavailable(certificate);
    }

    private bool TryEvaluateSupplied(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        RevocationEvaluationRequest request,
        RevocationEvidenceType type,
        RevocationEvidenceSource source,
        out CertificateRevocationResult result)
    {
        foreach (RevocationEvidence evidence in request.Evidence.Evidence)
        {
            if (evidence.Type != type || evidence.Source != source)
            {
                continue;
            }

            if (TryComplete(certificate, issuer, request, evidence, out result))
            {
                return true;
            }
        }

        result = Unavailable(certificate);
        return false;
    }

    private async Task<CertificateRevocationResult?> TryOnlineAsync(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        RevocationEvaluationRequest request,
        RevocationEvidenceType type,
        Func<Task<RevocationEvidence?>> fetch)
    {
        try
        {
            RevocationEvidence? evidence = await fetch().ConfigureAwait(false);
            if (evidence is null)
            {
                return null;
            }

            return TryComplete(certificate, issuer, request, evidence, out CertificateRevocationResult result)
                ? result
                : null;
        }
        catch (InvalidOperationException exception) when (exception.Message == "IMZAKIT.OCSP.NONCE_MISMATCH")
        {
            return new(
                certificate.Sha256Thumbprint,
                RevocationStatus.Invalid,
                RevocationEvidenceSource.Online,
                type,
                null,
                null,
                ["RevocationDataInvalid", "OcspNonceMismatch"]);
        }
        catch (InvalidOperationException exception) when (
            exception.Message.StartsWith("IMZAKIT.NET.", StringComparison.Ordinal))
        {
            return null;
        }
    }

    private bool TryComplete(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        RevocationEvaluationRequest request,
        RevocationEvidence evidence,
        out CertificateRevocationResult result)
    {
        ParsedRevocationEvidence parsed = parser.Parse(evidence, certificate, issuer);
        if (!parsed.TargetMatches)
        {
            result = Unavailable(certificate);
            return false;
        }

        List<string> findings = [];
        RevocationStatus status = DetermineStatus(
            parsed,
            request.ValidationTimeUtc,
            request.FreshnessTolerance,
            findings);
        result = new(
            certificate.Sha256Thumbprint,
            status,
            evidence.Source,
            evidence.Type,
            parsed.ThisUpdateUtc,
            parsed.NextUpdateUtc,
            findings.ToArray());
        return true;
    }

    private static CertificateRevocationResult Unavailable(CertificateDescriptor certificate) =>
        new(
            certificate.Sha256Thumbprint,
            RevocationStatus.Unavailable,
            null,
            null,
            null,
            null,
            ["RevocationDataUnavailable"]);

    private static RevocationStatus DetermineStatus(
        ParsedRevocationEvidence parsed,
        DateTimeOffset validationTimeUtc,
        TimeSpan freshnessTolerance,
        List<string> findings)
    {
        if (!parsed.SignatureValid || !parsed.ResponderAuthorized || parsed.Status == RevocationStatus.Invalid)
        {
            findings.Add("RevocationDataInvalid");
            return RevocationStatus.Invalid;
        }

        if (parsed.ThisUpdateUtc is null
            || parsed.ThisUpdateUtc > validationTimeUtc + freshnessTolerance)
        {
            findings.Add("RevocationDataInvalid");
            return RevocationStatus.Invalid;
        }

        if (parsed.NextUpdateUtc is DateTimeOffset nextUpdate && nextUpdate < validationTimeUtc)
        {
            findings.Add("RevocationDataStale");
            return RevocationStatus.Stale;
        }

        if (parsed.Status == RevocationStatus.Revoked)
        {
            findings.Add("CertificateRevoked");
        }
        else if (parsed.Status == RevocationStatus.Suspended)
        {
            findings.Add("CertificateSuspended");
        }

        return parsed.Status;
    }

    private static RevocationStatus Aggregate(IReadOnlyList<CertificateRevocationResult> results)
    {
        if (results.Any(result => result.Status == RevocationStatus.Revoked))
        {
            return RevocationStatus.Revoked;
        }

        if (results.Any(result => result.Status == RevocationStatus.Suspended))
        {
            return RevocationStatus.Suspended;
        }

        if (results.Any(result => result.Status == RevocationStatus.Invalid))
        {
            return RevocationStatus.Invalid;
        }

        if (results.Any(result => result.Status == RevocationStatus.Unavailable))
        {
            return RevocationStatus.Unavailable;
        }

        return results.Any(result => result.Status == RevocationStatus.Stale)
            ? RevocationStatus.Stale
            : RevocationStatus.Good;
    }
}
