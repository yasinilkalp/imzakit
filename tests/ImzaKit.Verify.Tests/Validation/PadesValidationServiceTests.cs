using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Validation;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Trust.Evaluation;
using ImzaKit.Verify.Tests.Fixtures;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class PadesValidationServiceTests
{
    [Fact]
    public void ValidPdfChainTrustAndFreshCrlPass()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();

        PadesValidationReport report = CreateService().Validate(
            fixture.Pdf,
            fixture.CreateContext(includeGoodCrl: true));

        Assert.True(
            report.Status == ValidationStatus.Passed,
            $"chain={report.ChainStatus}; trust={report.TrustStatus}; policy={report.PolicyStatus}; " +
            $"revocation={report.RevocationStatus}; findings={string.Join(',', report.Findings.Select(f => f.Code))}");
        Assert.Equal(ValidationStatus.Passed, report.ChainStatus);
        Assert.Equal(ValidationStatus.Passed, report.TrustStatus);
        Assert.Equal(ValidationStatus.Passed, report.PolicyStatus);
        Assert.Equal(RevocationStatus.Good, report.RevocationStatus);
        Assert.Equal("trust-test-v1", report.TrustStoreVersion);
        Assert.Equal("policy-test-v1", report.PolicyCatalogVersion);
        Assert.Equal(PadesBaselineLevel.BB, report.SignatureLevel);
    }

    [Fact]
    public void MissingRevocationEvidenceIsIndeterminateWithTypedFinding()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();

        PadesValidationReport report = CreateService().Validate(
            fixture.Pdf,
            fixture.CreateContext(includeGoodCrl: false));

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(RevocationStatus.Unavailable, report.RevocationStatus);
        Assert.Contains(report.Findings, finding =>
            finding.ReasonCode == ValidationReasonCode.RevocationDataUnavailable);
    }

    [Fact]
    public void ChangedSignedPdfFailsBeforeTrustDecision()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        byte[] changed = fixture.Pdf.ToArray();
        changed[10] ^= 1;

        PadesValidationReport report = CreateService().Validate(
            changed,
            fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Equal(ValidationStatus.Failed, report.CryptographicStatus);
    }

    [Fact]
    public void StaticContextFacadeProducesStructuredPassedReport()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();

        PadesValidationReport report = PadesValidator.Validate(
            fixture.Pdf,
            fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Passed, report.Status);
        Assert.Equal(RevocationStatus.Good, report.RevocationStatus);
    }

    [Fact]
    public void MissingIntermediateProducesTypedIndeterminateFinding()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();

        PadesValidationReport report = CreateService().Validate(
            fixture.Pdf,
            fixture.CreateContext(includeGoodCrl: false, includeIntermediate: false));

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Equal(ValidationStatus.Indeterminate, report.ChainStatus);
        Assert.Contains(report.Findings, finding =>
            finding.ReasonCode == ValidationReasonCode.CertificateChainIncomplete);
    }

    private static PadesValidationService CreateService() => new(
        new CertificateChainBuilder(),
        new CertificateChainValidator(),
        new TrustPolicyEvaluator(),
        new OfflineRevocationEvaluator(new BouncyCastleRevocationEvidenceParser()),
        new ValidationDecisionEngine());
}
