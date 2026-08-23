using System.Globalization;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Models;
using ImzaKit.Certificate.Validation;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Trust.Evaluation;

namespace ImzaKit.Verify.Validation;

public sealed class PadesValidationService : IPadesValidationService
{
    private const string ByteRangeMarker = "/ByteRange [";
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
            EvidenceSources = evidenceSources
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
        string text = Encoding.ASCII.GetString(pdf);
        int markerIndex = text.LastIndexOf(ByteRangeMarker, StringComparison.Ordinal);
        if (markerIndex < 0
            || !TryReadByteRange(text, markerIndex + ByteRangeMarker.Length, out long[] range))
        {
            return false;
        }

        int firstLength = (int)range[1];
        int secondOffset = (int)range[2];
        int secondLength = (int)range[3];
        ReadOnlySpan<byte> contents = pdf.Slice(firstLength, secondOffset - firstLength);
        byte[] paddedCms = Convert.FromHexString(Encoding.ASCII.GetString(contents[1..^1]));
        if (!TryReadDerLength(paddedCms, out int cmsLength))
        {
            return false;
        }

        byte[] signedBytes = new byte[firstLength + secondLength];
        pdf[..firstLength].CopyTo(signedBytes);
        pdf.Slice(secondOffset, secondLength).CopyTo(signedBytes.AsSpan(firstLength));
        cms = new SignedCms(new ContentInfo(signedBytes), detached: true);
        cms.Decode(paddedCms.AsSpan(0, cmsLength));
        return true;
    }

    private static bool TryReadByteRange(string text, int start, out long[] values)
    {
        values = new long[4];
        int index = start;
        for (int item = 0; item < values.Length; item++)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index])) index++;
            int numberStart = index;
            while (index < text.Length && char.IsAsciiDigit(text[index])) index++;
            if (numberStart == index
                || !long.TryParse(text.AsSpan(numberStart, index - numberStart), NumberStyles.None,
                    CultureInfo.InvariantCulture, out values[item]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryReadDerLength(ReadOnlySpan<byte> encoded, out int totalLength)
    {
        totalLength = 0;
        if (encoded.Length < 2 || encoded[0] != 0x30) return false;
        int firstLengthByte = encoded[1];
        if ((firstLengthByte & 0x80) == 0)
        {
            totalLength = 2 + firstLengthByte;
            return totalLength <= encoded.Length;
        }

        int lengthByteCount = firstLengthByte & 0x7f;
        if (lengthByteCount is 0 or > 4 || encoded.Length < 2 + lengthByteCount) return false;
        int contentLength = 0;
        for (int index = 0; index < lengthByteCount; index++)
        {
            contentLength = (contentLength << 8) | encoded[2 + index];
        }

        totalLength = 2 + lengthByteCount + contentLength;
        return totalLength <= encoded.Length;
    }
}
