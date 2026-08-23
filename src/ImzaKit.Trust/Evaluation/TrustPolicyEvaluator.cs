using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Evaluation;

public sealed class TrustPolicyEvaluator : ITrustPolicyEvaluator
{
    private const string CertificatePoliciesOid = "2.5.29.32";

    public TrustPolicyEvaluationResult Evaluate(TrustPolicyEvaluationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        List<TrustPolicyFailure> failures = [];
        string rootThumbprint = request.Chain.Certificates[^1].Sha256Thumbprint;
        TrustAnchor? anchor = request.TrustStore.Anchors.FirstOrDefault(candidate =>
            string.Equals(
                candidate.Certificate.Sha256Thumbprint,
                rootThumbprint,
                StringComparison.Ordinal));

        TrustPolicyStatus anchorStatus;
        if (anchor is null)
        {
            anchorStatus = TrustPolicyStatus.Failed;
            failures.Add(TrustPolicyFailure.TrustAnchorNotFound);
        }
        else if (!anchor.Profiles.Contains(request.Profile))
        {
            anchorStatus = TrustPolicyStatus.Failed;
            failures.Add(TrustPolicyFailure.AnchorProfileNotAllowed);
        }
        else
        {
            anchorStatus = TrustPolicyStatus.Passed;
        }

        string? matchedPolicy = null;
        TrustPolicyStatus policyStatus = TrustPolicyStatus.Passed;
        if (request.Profile == ValidationProfile.TurkiyeNes)
        {
            IReadOnlyList<string> leafPolicies = ReadCertificatePolicyOids(
                request.Chain.Certificates[0].ExportDer());
            CertificatePolicyEntry[] matchingEntries = request.PolicyCatalog.Entries
                .Where(entry => entry.Profile == request.Profile && leafPolicies.Contains(entry.PolicyOid))
                .ToArray();
            CertificatePolicyEntry? effectiveEntry = matchingEntries.FirstOrDefault(entry =>
                request.ValidationTimeUtc >= entry.EffectiveFromUtc
                && (entry.EffectiveUntilUtc is null || request.ValidationTimeUtc <= entry.EffectiveUntilUtc));

            if (effectiveEntry is not null)
            {
                matchedPolicy = effectiveEntry.PolicyOid;
            }
            else
            {
                policyStatus = TrustPolicyStatus.Failed;
                failures.Add(matchingEntries.Length == 0
                    ? TrustPolicyFailure.CertificatePolicyNotAllowed
                    : TrustPolicyFailure.PolicyNotEffective);
            }
        }

        return new(
            anchorStatus,
            policyStatus,
            anchor?.Certificate.Sha256Thumbprint,
            matchedPolicy,
            request.TrustStore.Version,
            request.PolicyCatalog.Version,
            failures.Distinct().ToArray());
    }

    private static IReadOnlyList<string> ReadCertificatePolicyOids(byte[] certificateDer)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(certificateDer);
        X509Extension? extension = certificate.Extensions[CertificatePoliciesOid];
        if (extension is null)
        {
            return Array.Empty<string>();
        }

        try
        {
            List<string> oids = [];
            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader policies = reader.ReadSequence();
            while (policies.HasData)
            {
                AsnReader policyInformation = policies.ReadSequence();
                oids.Add(policyInformation.ReadObjectIdentifier());
            }

            return oids;
        }
        catch (AsnContentException)
        {
            return Array.Empty<string>();
        }
    }
}
