using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Evaluation;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Tests.Evaluation;

public sealed class TrustPolicyEvaluatorTests
{
    private const string NesPolicyOid = "2.16.792.1.2.1.1.7.1";
    private const string EidasPolicyOid = "0.4.0.194121.2.2";

    [Fact]
    public void GeneralX509AcceptsProfileEnabledConfiguredAnchorWithoutNesPolicyRequirement()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafPolicyOid: "1.2.3.4");

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.GeneralX509,
            anchorProfiles: [ValidationProfile.GeneralX509],
            catalogEntries: []));

        Assert.Equal(TrustPolicyStatus.Passed, result.AnchorStatus);
        Assert.Equal(TrustPolicyStatus.Passed, result.PolicyStatus);
        Assert.Equal("trust-test-v1", result.TrustStoreVersion);
        Assert.Equal("policy-test-v1", result.PolicyCatalogVersion);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void TurkiyeNesAcceptsProfileAnchorAndEffectiveLeafPolicy()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafPolicyOid: NesPolicyOid);
        CertificatePolicyEntry entry = EffectiveEntry(pki, NesPolicyOid);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.TurkiyeNes,
            anchorProfiles: [ValidationProfile.TurkiyeNes],
            catalogEntries: [entry]));

        Assert.Equal(TrustPolicyStatus.Passed, result.AnchorStatus);
        Assert.Equal(TrustPolicyStatus.Passed, result.PolicyStatus);
        Assert.Equal(NesPolicyOid, result.MatchedPolicyOid);
        Assert.Equal(Describe(pki.Root).Sha256Thumbprint, result.MatchedAnchorSha256);
    }

    [Fact]
    public void EvaluateRejectsRootThatIsNotInConfiguredSnapshot()
    {
        using TestCertificateAuthority chainPki = TestCertificateAuthority.Create();
        using TestCertificateAuthority otherPki = TestCertificateAuthority.Create();
        TrustStoreSnapshot otherStore = new(
            "trust-test-v1",
            [new(Describe(otherPki.Root), [ValidationProfile.GeneralX509])]);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(new(
            CreateChain(chainPki),
            ValidationProfile.GeneralX509,
            otherStore,
            new CertificatePolicyCatalog("policy-test-v1", []),
            chainPki.ReferenceTimeUtc));

        Assert.Equal(TrustPolicyStatus.Failed, result.AnchorStatus);
        Assert.Contains(TrustPolicyFailure.TrustAnchorNotFound, result.Failures);
    }

    [Fact]
    public void EvaluateRejectsAnchorThatDoesNotEnableSelectedProfile()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.TurkiyeNes,
            anchorProfiles: [ValidationProfile.GeneralX509],
            catalogEntries: [EffectiveEntry(pki, NesPolicyOid)]));

        Assert.Equal(TrustPolicyStatus.Failed, result.AnchorStatus);
        Assert.Contains(TrustPolicyFailure.AnchorProfileNotAllowed, result.Failures);
    }

    [Fact]
    public void TurkiyeNesRejectsLeafPolicyMissingFromCatalog()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafPolicyOid: "1.2.3.4");

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.TurkiyeNes,
            anchorProfiles: [ValidationProfile.TurkiyeNes],
            catalogEntries: [EffectiveEntry(pki, NesPolicyOid)]));

        Assert.Equal(TrustPolicyStatus.Failed, result.PolicyStatus);
        Assert.Contains(TrustPolicyFailure.CertificatePolicyNotAllowed, result.Failures);
    }

    [Fact]
    public void TurkiyeNesRejectsPolicyOutsideEffectiveWindow()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafPolicyOid: NesPolicyOid);
        CertificatePolicyEntry expiredEntry = new(
            ValidationProfile.TurkiyeNes,
            NesPolicyOid,
            pki.ReferenceTimeUtc.AddYears(-2),
            pki.ReferenceTimeUtc.AddDays(-1),
            TimeSpan.FromHours(12));

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.TurkiyeNes,
            anchorProfiles: [ValidationProfile.TurkiyeNes],
            catalogEntries: [expiredEntry]));

        Assert.Equal(TrustPolicyStatus.Failed, result.PolicyStatus);
        Assert.Contains(TrustPolicyFailure.PolicyNotEffective, result.Failures);
    }

    [Fact]
    public void EidasAcceptsEidasAnchorEffectiveCatalogPolicyAndQcCompliance()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            leafPolicyOid: EidasPolicyOid,
            includeQcCompliance: true);
        CertificatePolicyEntry entry = EffectiveEntry(pki, EidasPolicyOid, ValidationProfile.Eidas);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.Eidas,
            anchorProfiles: [ValidationProfile.Eidas],
            catalogEntries: [entry]));

        Assert.Equal(TrustPolicyStatus.Passed, result.AnchorStatus);
        Assert.Equal(TrustPolicyStatus.Passed, result.PolicyStatus);
        Assert.Equal(EidasPolicyOid, result.MatchedPolicyOid);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void EidasRejectsTurkiyeNesOnlyAnchor()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            leafPolicyOid: EidasPolicyOid,
            includeQcCompliance: true);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.Eidas,
            anchorProfiles: [ValidationProfile.TurkiyeNes],
            catalogEntries: [EffectiveEntry(pki, EidasPolicyOid, ValidationProfile.Eidas)]));

        Assert.Equal(TrustPolicyStatus.Failed, result.AnchorStatus);
        Assert.Contains(TrustPolicyFailure.AnchorProfileNotAllowed, result.Failures);
    }

    [Fact]
    public void EidasRejectsLeafPolicyMissingFromEidasCatalog()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            leafPolicyOid: NesPolicyOid,
            includeQcCompliance: true);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.Eidas,
            anchorProfiles: [ValidationProfile.Eidas],
            catalogEntries: [EffectiveEntry(pki, EidasPolicyOid, ValidationProfile.Eidas)]));

        Assert.Equal(TrustPolicyStatus.Failed, result.PolicyStatus);
        Assert.Contains(TrustPolicyFailure.CertificatePolicyNotAllowed, result.Failures);
    }

    [Fact]
    public void EidasRejectsPolicyOutsideEffectiveWindow()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(
            leafPolicyOid: EidasPolicyOid,
            includeQcCompliance: true);
        CertificatePolicyEntry expiredEntry = new(
            ValidationProfile.Eidas,
            EidasPolicyOid,
            pki.ReferenceTimeUtc.AddYears(-2),
            pki.ReferenceTimeUtc.AddDays(-1),
            TimeSpan.FromHours(12));

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.Eidas,
            anchorProfiles: [ValidationProfile.Eidas],
            catalogEntries: [expiredEntry]));

        Assert.Equal(TrustPolicyStatus.Failed, result.PolicyStatus);
        Assert.Contains(TrustPolicyFailure.PolicyNotEffective, result.Failures);
    }

    [Fact]
    public void EidasRejectsMissingQcComplianceStatement()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafPolicyOid: EidasPolicyOid);

        TrustPolicyEvaluationResult result = new TrustPolicyEvaluator().Evaluate(CreateRequest(
            pki,
            ValidationProfile.Eidas,
            anchorProfiles: [ValidationProfile.Eidas],
            catalogEntries: [EffectiveEntry(pki, EidasPolicyOid, ValidationProfile.Eidas)]));

        Assert.Equal(TrustPolicyStatus.Failed, result.PolicyStatus);
        Assert.Contains(TrustPolicyFailure.QcStatementMissing, result.Failures);
    }

    private static TrustPolicyEvaluationRequest CreateRequest(
        TestCertificateAuthority pki,
        ValidationProfile profile,
        IEnumerable<ValidationProfile> anchorProfiles,
        IEnumerable<CertificatePolicyEntry> catalogEntries) =>
        new(
            CreateChain(pki),
            profile,
            new TrustStoreSnapshot("trust-test-v1", [new(Describe(pki.Root), anchorProfiles)]),
            new CertificatePolicyCatalog("policy-test-v1", catalogEntries),
            pki.ReferenceTimeUtc);

    private static CertificatePolicyEntry EffectiveEntry(
        TestCertificateAuthority pki,
        string oid,
        ValidationProfile profile = ValidationProfile.TurkiyeNes) =>
        new(
            profile,
            oid,
            pki.ReferenceTimeUtc.AddDays(-1),
            pki.ReferenceTimeUtc.AddDays(1),
            TimeSpan.FromHours(12));

    private static CertificateChainCandidate CreateChain(TestCertificateAuthority pki) =>
        new([Describe(pki.Leaf), Describe(pki.Intermediate), Describe(pki.Root)]);

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);
}
