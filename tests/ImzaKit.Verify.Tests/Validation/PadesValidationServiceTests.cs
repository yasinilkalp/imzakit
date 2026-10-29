using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Building;
using ImzaKit.Certificate.Validation;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Testing.Timestamp;
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

    [Fact]
    public void UntrustedEarlierSignatureIsNotMaskedByTrustedLaterSignature()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        using X509Certificate2 untrusted = fixture.CreateUntrustedSigner();
        byte[] pdf = SignedPdfFixture.Sign(
            SignedPdfFixture.Sign(SignedPdfFixture.CreateUnsignedPdf(), untrusted),
            fixture.Pki.Leaf);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(2, report.Signatures.Count);
        Assert.NotEqual(ValidationStatus.Passed, report.Signatures[0].Status);
        Assert.Equal(ValidationStatus.Passed, report.Signatures[1].Status);
        Assert.Equal(ValidationStatus.Failed, report.Signatures[0].TrustStatus);
        Assert.Equal(ValidationStatus.Failed, report.TrustStatus);
        Assert.Equal(ValidationStatus.Failed, report.Status);
        Assert.Contains(report.Findings, finding => finding.ReasonCode == ValidationReasonCode.TrustAnchorNotFound);
    }

    [Fact]
    public void UntrustedLaterSignatureFailsDocumentSignedByTrustedSigner()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        using X509Certificate2 untrusted = fixture.CreateUntrustedSigner();
        byte[] pdf = SignedPdfFixture.Sign(fixture.Pdf, untrusted);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Passed, report.Signatures[0].Status);
        Assert.NotEqual(ValidationStatus.Passed, report.Signatures[1].Status);
        Assert.NotEqual(ValidationStatus.Passed, report.Status);
    }

    [Fact]
    public void EverySignatureByTrustedSignerPassesIndividually()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        byte[] pdf = SignedPdfFixture.Sign(fixture.Pdf, fixture.Pki.Leaf);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.All(report.Signatures, signature =>
        {
            Assert.Equal(ValidationStatus.Passed, signature.Status);
            Assert.Equal(ValidationStatus.Passed, signature.TrustStatus);
            Assert.Equal(RevocationStatus.Good, signature.RevocationStatus);
        });
        Assert.Equal(ValidationStatus.Passed, report.Status);
    }

    [Fact]
    public void QualifiedSignerWithOnlyNonRepudiationUsagePasses()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create(nonRepudiationOnlySigner: true);

        PadesValidationReport report = CreateService().Validate(fixture.Pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Passed, report.ChainStatus);
        Assert.Equal(ValidationStatus.Passed, report.Status);
    }

    [Fact]
    public async Task SignatureTimeStampFromTrustedAuthorityCountsAsBaselineT()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        using TestTsaResponder tsa = new(fixture.Pki.Intermediate);
        byte[] pdf = await fixture.SignBaselineTAsync(tsa);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Passed, report.Status);
        Assert.Equal(PadesBaselineLevel.BT, report.SignatureLevel);
        Assert.DoesNotContain(report.Findings, finding => finding.Code == "TimeStampAuthorityUntrusted");
    }

    [Fact]
    public async Task SignatureTimeStampFromUntrustedAuthorityDoesNotCountAsBaselineT()
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        using TestTsaResponder tsa = new();
        byte[] pdf = await fixture.SignBaselineTAsync(tsa);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(PadesBaselineLevel.BT, PadesValidator.Validate(pdf).SignatureLevel);
        Assert.Equal(ValidationStatus.Passed, report.Status);
        Assert.Equal(PadesBaselineLevel.BB, report.SignatureLevel);
        Assert.Equal(PadesBaselineLevel.BB, report.Signatures[0].SignatureLevel);
        Assert.Contains(report.Signatures[0].Findings, finding => finding.Code == "TimeStampAuthorityUntrusted");
    }

    [Theory]
    [InlineData(true, PadesBaselineLevel.BLTA)]
    [InlineData(false, PadesBaselineLevel.BLT)]
    public async Task DocumentTimeStampCountsAsBaselineLtaOnlyFromTrustedAuthority(bool trustedArchive, string expected)
    {
        using SignedPdfFixture fixture = SignedPdfFixture.Create();
        using TestTsaResponder signatureTsa = new(fixture.Pki.Intermediate);
        using TestTsaResponder archiveTsa = trustedArchive ? new(fixture.Pki.Intermediate) : new();
        byte[] pdf = await fixture.ArchiveAsync(await fixture.SignBaselineTAsync(signatureTsa), archiveTsa);

        PadesValidationReport report = CreateService().Validate(pdf, fixture.CreateContext(includeGoodCrl: true));

        Assert.Equal(ValidationStatus.Passed, report.Status);
        Assert.Equal(expected, report.SignatureLevel);
        Assert.Equal(!trustedArchive, report.Findings.Any(finding => finding.Code == "TimeStampAuthorityUntrusted"));
    }

    private static PadesValidationService CreateService() => new(
        new CertificateChainBuilder(),
        new CertificateChainValidator(),
        new TrustPolicyEvaluator(),
        new OfflineRevocationEvaluator(new BouncyCastleRevocationEvidenceParser()),
        new ValidationDecisionEngine());
}
