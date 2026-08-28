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

        if (!TryExtractCms(pdf, out SignedCms? cms)
            || cms is null
            || cms.SignerInfos.Count == 0
            || cms.SignerInfos[0].Certificate is not X509Certificate2 signer)
        {
            return integrity with
            {
                Status = ValidationStatus.Indeterminate,
                Findings = [new("SignerCertificateMissing", "The signer certificate is not embedded in the CMS container.")],
                ValidationTime = context.ValidationTimeUtc,
                ValidationTimeSource = context.ValidationTimeSource,
                ValidationProfile = context.Profile,
                TrustStoreVersion = context.TrustStore.Version,
                PolicyCatalogVersion = context.PolicyCatalog.Version
            };
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
        List<ValidationFinding> findings = integrity.Findings
            .Where(finding => finding.Code != "TrustNotEvaluated")
            .ToList();
        findings.Add(new("ValidationTimeUntrusted", "Validation uses the configured system time.")
        {
            ReasonCode = ValidationReasonCode.ValidationTimeUntrusted
        });

        if (build.Status != CertificateChainStatus.Complete || build.Candidate is null)
        {
            findings.Add(Reason(
                ValidationReasonCode.CertificateChainIncomplete,
                "A complete signer certificate chain could not be built."));
            return CreateReport(
                integrity,
                context,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                ValidationStatus.Indeterminate,
                RevocationStatus.Unavailable,
                findings,
                []);
        }

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

        return CreateReport(
            integrity,
            context,
            chainStatus,
            trustStatus,
            policyStatus,
            revocation.Status,
            findings,
            revocation.Certificates
                .Where(result => result.EvidenceSource is not null)
                .Select(result => result.EvidenceSource!.Value)
                .Distinct()
                .ToArray());
    }

    private PadesValidationReport CreateReport(
        PadesValidationReport integrity,
        ValidationContext context,
        ValidationStatus chainStatus,
        ValidationStatus trustStatus,
        ValidationStatus policyStatus,
        RevocationStatus revocationStatus,
        IReadOnlyList<ValidationFinding> findings,
        IReadOnlyList<RevocationEvidenceSource> evidenceSources)
    {
        ValidationStatus status = _decisionEngine.Decide(new(
            integrity.ByteRangeStatus,
            integrity.CryptographicStatus,
            chainStatus,
            trustStatus,
            policyStatus,
            revocationStatus));
        if (integrity.ModificationPolicyStatus == ValidationStatus.Failed)
        {
            status = ValidationStatus.Failed;
        }

        return new(
            status,
            integrity.ByteRangeStatus,
            integrity.CryptographicStatus,
            trustStatus,
            integrity.SignerCertificateSha256,
            findings)
        {
            ChainStatus = chainStatus,
            PolicyStatus = policyStatus,
            RevocationStatus = revocationStatus,
            ValidationTime = context.ValidationTimeUtc,
            ValidationTimeSource = context.ValidationTimeSource,
            ValidationProfile = context.Profile,
            TrustStoreVersion = context.TrustStore.Version,
            PolicyCatalogVersion = context.PolicyCatalog.Version,
            EvidenceSources = evidenceSources,
            SignatureLevel = integrity.SignatureLevel,
            ModificationPolicyStatus = integrity.ModificationPolicyStatus,
            Signatures = integrity.Signatures
        };
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

    private static bool TryExtractCms(ReadOnlySpan<byte> pdf, out SignedCms? cms)
    {
        cms = null;
        if (PdfCadesSignatureReader.TryRead(pdf, out _, out byte[] cmsDer, out byte[] signedBytes)
            != PdfCadesReadStatus.Success)
        {
            return false;
        }

        cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(cmsDer);
        return true;
    }
}
