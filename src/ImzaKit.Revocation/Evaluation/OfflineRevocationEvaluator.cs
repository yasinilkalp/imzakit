using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;

namespace ImzaKit.Revocation.Evaluation;

public sealed class OfflineRevocationEvaluator : IOfflineRevocationEvaluator
{
    private readonly IRevocationEvidenceParser _parser;

    public OfflineRevocationEvaluator(IRevocationEvidenceParser parser)
    {
        ArgumentNullException.ThrowIfNull(parser);
        _parser = parser;
    }

    public OfflineRevocationResult Evaluate(OfflineRevocationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RevocationEvidence[] orderedEvidence = request.Evidence.Evidence
            .OrderBy(EvidenceRank)
            .ToArray();
        List<CertificateRevocationResult> results = [];

        for (int index = 0; index < request.Chain.Certificates.Count - 1; index++)
        {
            results.Add(EvaluateCertificate(
                request.Chain.Certificates[index],
                request.Chain.Certificates[index + 1],
                orderedEvidence,
                request.ValidationTimeUtc,
                request.FreshnessTolerance));
        }

        return new(Aggregate(results), results.ToArray());
    }

    private CertificateRevocationResult EvaluateCertificate(
        CertificateDescriptor certificate,
        CertificateDescriptor issuer,
        IEnumerable<RevocationEvidence> evidenceItems,
        DateTimeOffset validationTimeUtc,
        TimeSpan freshnessTolerance)
    {
        List<string> findings = [];
        foreach (RevocationEvidence evidence in evidenceItems)
        {
            ParsedRevocationEvidence parsed = _parser.Parse(evidence, certificate, issuer);
            if (!parsed.TargetMatches)
            {
                findings.Add("RevocationEvidenceTargetMismatch");
                continue;
            }

            RevocationStatus status = DetermineStatus(
                parsed,
                validationTimeUtc,
                freshnessTolerance,
                findings);
            return new(
                certificate.Sha256Thumbprint,
                status,
                evidence.Source,
                evidence.Type,
                parsed.ThisUpdateUtc,
                parsed.NextUpdateUtc,
                findings.ToArray());
        }

        findings.Add("RevocationDataUnavailable");
        return new(
            certificate.Sha256Thumbprint,
            RevocationStatus.Unavailable,
            null,
            null,
            null,
            null,
            findings.ToArray());
    }

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

    private static int EvidenceRank(RevocationEvidence evidence) =>
        (evidence.Type, evidence.Source) switch
        {
            (RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Embedded) => 0,
            (RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Local) => 1,
            (RevocationEvidenceType.Crl, RevocationEvidenceSource.Embedded) => 2,
            (RevocationEvidenceType.Crl, RevocationEvidenceSource.Local) => 3,
            _ => int.MaxValue
        };

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
