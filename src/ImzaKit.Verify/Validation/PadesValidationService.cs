using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Models;
using ImzaKit.Certificate.Validation;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Trust.Evaluation;

namespace ImzaKit.Verify.Validation;

public sealed class PadesValidationService : IPadesValidationService
{
    private readonly ICertificateChainBuilder _chainBuilder;
    private readonly ICertificateChainValidator _chainValidator;
    private readonly ITrustPolicyEvaluator _trustPolicyEvaluator;
    private readonly IOfflineRevocationEvaluator _revocationEvaluator;
    private readonly ValidationDecisionEngine _decisionEngine;

    public PadesValidationService(
        ICertificateChainBuilder chainBuilder,
        ICertificateChainValidator chainValidator,
        ITrustPolicyEvaluator trustPolicyEvaluator,
        IOfflineRevocationEvaluator revocationEvaluator,
        ValidationDecisionEngine decisionEngine)
    {
        _chainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
        _chainValidator = chainValidator ?? throw new ArgumentNullException(nameof(chainValidator));
        _trustPolicyEvaluator = trustPolicyEvaluator ?? throw new ArgumentNullException(nameof(trustPolicyEvaluator));
        _revocationEvaluator = revocationEvaluator ?? throw new ArgumentNullException(nameof(revocationEvaluator));
        _decisionEngine = decisionEngine ?? throw new ArgumentNullException(nameof(decisionEngine));
    }

    public PadesValidationReport Validate(ReadOnlySpan<byte> pdf) => PadesValidator.Validate(pdf);

    public PadesValidationReport Validate(ReadOnlySpan<byte> pdf, ValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        PadesValidationReport integrity = PadesValidator.Validate(pdf);
        if (integrity.ByteRangeStatus != ValidationStatus.Passed
            || integrity.CryptographicStatus != ValidationStatus.Passed)
        {
            return integrity with
            {
                ValidationTime = context.ValidationTimeUtc,
                ValidationTimeSource = context.ValidationTimeSource,
                ValidationProfile = context.Profile,
                TrustStoreVersion = context.TrustStore.Version,
                PolicyCatalogVersion = context.PolicyCatalog.Version
            };
        }

        // Every signature gets its own chain, trust, policy and revocation decision; the document
        // passes only when all of them pass, so a trusted later signer cannot mask an untrusted one.
        IReadOnlyList<PdfCadesLocatedSignature> located = PdfCadesSignatureReader.ReadAll(pdf);
        List<ValidationFinding> findings = [.. integrity.Findings.Where(finding => finding.Code != "TrustNotEvaluated")];
        findings.Add(new("ValidationTimeUntrusted", "Validation uses the configured system time.")
        {
            ReasonCode = ValidationReasonCode.ValidationTimeUntrusted
        });
        List<PadesSignatureRevisionReport> signatures = [];
        List<RevocationEvidenceSource> evidenceSources = [];
        for (int index = 0; index < integrity.Signatures.Count; index++)
        {
            PadesSignatureRevisionReport revision = integrity.Signatures[index];
            SignatureTrust trust = EvaluateTrust(located[index], context);
            ValidationStatus status = _decisionEngine.Decide(new(
                revision.ByteRangeStatus,
                revision.CryptographicStatus,
                trust.ChainStatus,
                trust.TrustStatus,
                trust.PolicyStatus,
                trust.RevocationStatus));
            if (revision.ModificationPolicyStatus == ValidationStatus.Failed)
            {
                status = ValidationStatus.Failed;
            }
            else if (revision.ModificationPolicyStatus == ValidationStatus.Indeterminate && status == ValidationStatus.Passed)
            {
                status = ValidationStatus.Indeterminate;
            }

            signatures.Add(revision with
            {
                Status = status,
                ChainStatus = trust.ChainStatus,
                TrustStatus = trust.TrustStatus,
                PolicyStatus = trust.PolicyStatus,
                RevocationStatus = trust.RevocationStatus,
                Findings = [.. revision.Findings, .. trust.Findings]
            });
            foreach (ValidationFinding finding in trust.Findings)
            {
                if (!findings.Any(existing => existing.Code == finding.Code && existing.Message == finding.Message))
                {
                    findings.Add(finding);
                }
            }

            evidenceSources.AddRange(trust.EvidenceSources);
        }

        ValidationStatus overall = Worst(signatures.Select(signature => signature.Status));
        if (integrity.ModificationPolicyStatus == ValidationStatus.Failed)
        {
            overall = ValidationStatus.Failed;
        }

        return new(
            overall,
            integrity.ByteRangeStatus,
            integrity.CryptographicStatus,
            Worst(signatures.Select(signature => signature.TrustStatus)),
            integrity.SignerCertificateSha256,
            findings)
        {
            ChainStatus = Worst(signatures.Select(signature => signature.ChainStatus)),
            PolicyStatus = Worst(signatures.Select(signature => signature.PolicyStatus)),
            RevocationStatus = signatures
                .Select(signature => signature.RevocationStatus ?? RevocationStatus.Unavailable)
                .MaxBy(RevocationSeverity),
            ValidationTime = context.ValidationTimeUtc,
            ValidationTimeSource = context.ValidationTimeSource,
            ValidationProfile = context.Profile,
            TrustStoreVersion = context.TrustStore.Version,
            PolicyCatalogVersion = context.PolicyCatalog.Version,
            EvidenceSources = [.. evidenceSources.Distinct()],
            SignatureLevel = integrity.SignatureLevel,
            ModificationPolicyStatus = integrity.ModificationPolicyStatus,
            Signatures = signatures
        };
    }

    private SignatureTrust EvaluateTrust(PdfCadesLocatedSignature located, ValidationContext context)
    {
        SignedCms cms = new(new ContentInfo(located.SignedBytes), detached: true);
        cms.Decode(located.Cms);
        if (cms.SignerInfos.Count == 0 || cms.SignerInfos[0].Certificate is not X509Certificate2 signer)
        {
            return SignatureTrust.Unavailable(
                new ValidationFinding("SignerCertificateMissing", "The signer certificate is not embedded in the CMS container."));
        }

        CertificateDescriptor leaf = Describe(signer, CertificateSource.Embedded);
        IEnumerable<CertificateDescriptor> cmsIntermediates = cms.Certificates
            .Cast<X509Certificate2>()
            .Where(certificate => !certificate.RawData.AsSpan().SequenceEqual(signer.RawData))
            .Select(certificate => Describe(certificate, CertificateSource.Embedded));
        CertificateDescriptor[] embedded = cmsIntermediates
            .Concat(context.EmbeddedIntermediates)
            .ToArray();
        CertificateDescriptor[] local = context.LocalIntermediates
            .Concat(context.TrustStore.Anchors.Select(anchor => anchor.Certificate))
            .ToArray();
        CertificateChainBuildResult build = _chainBuilder.Build(new(leaf, embedded, local));
        if (build.Status != CertificateChainStatus.Complete || build.Candidate is null)
        {
            return SignatureTrust.Unavailable(Reason(
                ValidationReasonCode.CertificateChainIncomplete,
                "A complete signer certificate chain could not be built."));
        }

        List<ValidationFinding> findings = [];

        CertificateChainValidationResult chainValidation = _chainValidator.Validate(new(
            build.Candidate,
            context.ValidationTimeUtc));
        ValidationStatus chainStatus = chainValidation.Status == CertificateChainStatus.Valid
            ? ValidationStatus.Passed
            : ValidationStatus.Failed;
        foreach (CertificateValidationFailure failure in chainValidation.Failures)
        {
            findings.Add(MapCertificateFailure(failure));
        }

        TrustPolicyEvaluationResult trust = _trustPolicyEvaluator.Evaluate(new(
            build.Candidate,
            context.Profile,
            context.TrustStore,
            context.PolicyCatalog,
            context.ValidationTimeUtc));
        ValidationStatus trustStatus = trust.AnchorStatus == TrustPolicyStatus.Passed
            ? ValidationStatus.Passed
            : ValidationStatus.Failed;
        ValidationStatus policyStatus = trust.PolicyStatus == TrustPolicyStatus.Passed
            ? ValidationStatus.Passed
            : ValidationStatus.Failed;
        foreach (TrustPolicyFailure failure in trust.Failures)
        {
            findings.Add(MapTrustFailure(failure));
        }

        TimeSpan freshnessTolerance = context.PolicyCatalog.Entries
            .Where(entry => entry.Profile == context.Profile
                && context.ValidationTimeUtc >= entry.EffectiveFromUtc
                && (entry.EffectiveUntilUtc is null || context.ValidationTimeUtc <= entry.EffectiveUntilUtc))
            .Select(entry => entry.RevocationFreshnessTolerance)
            .DefaultIfEmpty(TimeSpan.Zero)
            .Max();
        OfflineRevocationResult revocation = _revocationEvaluator.Evaluate(new(
            build.Candidate,
            context.RevocationEvidence,
            context.ValidationTimeUtc,
            freshnessTolerance));
        foreach (string code in revocation.Certificates.SelectMany(result => result.Findings).Distinct())
        {
            findings.Add(MapRevocationFinding(code));
        }

        return new(
            chainStatus,
            trustStatus,
            policyStatus,
            revocation.Status,
            findings,
            [.. revocation.Certificates
                .Where(result => result.EvidenceSource is not null)
                .Select(result => result.EvidenceSource!.Value)
                .Distinct()]);
    }

    private static ValidationStatus Worst(IEnumerable<ValidationStatus> statuses) =>
        statuses.Aggregate(ValidationStatus.Passed, (worst, next) => Severity(next) > Severity(worst) ? next : worst);

    private static int Severity(ValidationStatus status) => status switch
    {
        ValidationStatus.Failed => 2,
        ValidationStatus.Indeterminate => 1,
        _ => 0
    };

    private static int RevocationSeverity(RevocationStatus status) => status switch
    {
        RevocationStatus.Revoked => 5,
        RevocationStatus.Suspended => 4,
        RevocationStatus.Invalid => 3,
        RevocationStatus.Stale => 2,
        RevocationStatus.Unavailable => 1,
        _ => 0
    };

    private sealed record SignatureTrust(
        ValidationStatus ChainStatus,
        ValidationStatus TrustStatus,
        ValidationStatus PolicyStatus,
        RevocationStatus RevocationStatus,
        IReadOnlyList<ValidationFinding> Findings,
        IReadOnlyList<RevocationEvidenceSource> EvidenceSources)
    {
        public static SignatureTrust Unavailable(ValidationFinding finding) => new(
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            ValidationStatus.Indeterminate,
            RevocationStatus.Unavailable,
            [finding],
            []);
    }

    private static ValidationFinding MapCertificateFailure(CertificateValidationFailure failure) => failure switch
    {
        CertificateValidationFailure.Expired => Reason(ValidationReasonCode.CertificateExpired, "A certificate is expired."),
        CertificateValidationFailure.NotYetValid => Reason(ValidationReasonCode.CertificateNotYetValid, "A certificate is not yet valid."),
        CertificateValidationFailure.AlgorithmDisallowed => Reason(ValidationReasonCode.AlgorithmDisallowed, "A certificate uses a disallowed algorithm."),
        _ => Reason(ValidationReasonCode.CertificateChainInvalid, "The certificate chain is invalid.")
    };

    private static ValidationFinding MapTrustFailure(TrustPolicyFailure failure) => failure switch
    {
        TrustPolicyFailure.TrustAnchorNotFound or TrustPolicyFailure.AnchorProfileNotAllowed =>
            Reason(ValidationReasonCode.TrustAnchorNotFound, "No profile-enabled trust anchor matched the chain."),
        _ => Reason(ValidationReasonCode.CertificatePolicyNotAllowed, "The signer certificate policy is not allowed.")
    };

    private static ValidationFinding MapRevocationFinding(string code) => code switch
    {
        "RevocationDataUnavailable" => Reason(ValidationReasonCode.RevocationDataUnavailable, "Revocation evidence is unavailable."),
        "RevocationDataStale" => Reason(ValidationReasonCode.RevocationDataStale, "Revocation evidence is stale."),
        "CertificateRevoked" => Reason(ValidationReasonCode.CertificateRevoked, "The certificate is revoked."),
        "CertificateSuspended" => Reason(ValidationReasonCode.CertificateSuspended, "The certificate is suspended."),
        "RevocationEvidenceTargetMismatch" => new(code, "Revocation evidence targeted a different certificate or issuer."),
        _ => Reason(ValidationReasonCode.RevocationDataInvalid, "Revocation evidence is invalid.")
    };

    private static ValidationFinding Reason(ValidationReasonCode code, string message) =>
        new(code.ToString(), message) { ReasonCode = code };

    private static CertificateDescriptor Describe(X509Certificate2 certificate, CertificateSource source) =>
        CertificateDescriptor.FromDer(certificate.RawData, source);
}
