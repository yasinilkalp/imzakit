using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Evaluation;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Revocation.Tests.Fixtures;
using ImzaKit.Testing.Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace ImzaKit.Revocation.Tests.Evaluation;

public sealed class OfflineRevocationEvaluatorTests
{
    [Fact]
    public void EvaluateReturnsUnavailableWhenNoEvidenceExists()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        OfflineRevocationResult result = Evaluate(pki, []);

        Assert.Equal(RevocationStatus.Unavailable, result.Status);
        Assert.Single(result.Certificates);
        Assert.Equal(RevocationStatus.Unavailable, result.Certificates[0].Status);
        Assert.Contains("RevocationDataUnavailable", result.Certificates[0].Findings);
    }

    [Fact]
    public void EmbeddedOcspWinsOverLocalOcspAndEmbeddedCrl()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence[] evidence = [
            Evidence(RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Local,
                RevocationEvidenceFixture.CreateOcsp(pki, revoked: true)),
            Evidence(RevocationEvidenceType.Crl, RevocationEvidenceSource.Embedded,
                RevocationEvidenceFixture.CreateCrl(pki, CrlReason.KeyCompromise)),
            Evidence(RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Embedded,
                RevocationEvidenceFixture.CreateOcsp(pki))];

        OfflineRevocationResult result = Evaluate(pki, evidence);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.Equal(RevocationEvidenceSource.Embedded, result.Certificates[0].EvidenceSource);
        Assert.Equal(RevocationEvidenceType.Ocsp, result.Certificates[0].EvidenceType);
    }

    [Fact]
    public void OnlineOcspWinsOverEmbeddedCrl()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence[] evidence = [
            Evidence(RevocationEvidenceType.Crl, RevocationEvidenceSource.Embedded,
                RevocationEvidenceFixture.CreateCrl(pki, CrlReason.KeyCompromise)),
            Evidence(RevocationEvidenceType.Ocsp, RevocationEvidenceSource.Online,
                RevocationEvidenceFixture.CreateOcsp(pki))];

        OfflineRevocationResult result = Evaluate(pki, evidence);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.Equal(RevocationEvidenceSource.Online, result.Certificates[0].EvidenceSource);
        Assert.Equal(RevocationEvidenceType.Ocsp, result.Certificates[0].EvidenceType);
    }

    [Fact]
    public void EvaluateReturnsStaleWhenNextUpdatePrecedesValidationTime()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = Evidence(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Embedded,
            RevocationEvidenceFixture.CreateOcsp(pki));

        OfflineRevocationResult result = Evaluate(
            pki,
            [evidence],
            pki.ReferenceTimeUtc.AddDays(1));

        Assert.Equal(RevocationStatus.Stale, result.Status);
        Assert.Contains("RevocationDataStale", result.Certificates[0].Findings);
    }

    [Fact]
    public void EvaluateMapsRevokedEvidenceToAggregateFailure()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        OfflineRevocationResult result = Evaluate(pki, [Evidence(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Embedded,
            RevocationEvidenceFixture.CreateOcsp(pki, revoked: true))]);

        Assert.Equal(RevocationStatus.Revoked, result.Status);
    }

    [Fact]
    public void EvaluateMapsCertificateHoldToSuspended()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        OfflineRevocationResult result = Evaluate(pki, [Evidence(
            RevocationEvidenceType.Crl,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateCrl(pki, CrlReason.CertificateHold))]);

        Assert.Equal(RevocationStatus.Suspended, result.Status);
    }

    [Fact]
    public void EvaluateIgnoresTargetMismatchAndReportsUnavailable()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        OfflineRevocationResult result = Evaluate(pki, [Evidence(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateOcsp(pki, wrongSerial: true))]);

        Assert.Equal(RevocationStatus.Unavailable, result.Status);
        Assert.Contains("RevocationEvidenceTargetMismatch", result.Certificates[0].Findings);
    }

    [Fact]
    public void EvaluateReturnsInvalidForEvidenceWithBadSignature()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        OfflineRevocationResult result = Evaluate(pki, [Evidence(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateOcsp(pki, invalidSignature: true))]);

        Assert.Equal(RevocationStatus.Invalid, result.Status);
        Assert.Contains("RevocationDataInvalid", result.Certificates[0].Findings);
    }

    private static OfflineRevocationResult Evaluate(
        TestCertificateAuthority pki,
        IEnumerable<RevocationEvidence> evidence,
        DateTimeOffset? validationTimeUtc = null) =>
        new OfflineRevocationEvaluator(new BouncyCastleRevocationEvidenceParser()).Evaluate(new(
            new CertificateChainCandidate([Describe(pki.Leaf), Describe(pki.Intermediate)]),
            new RevocationEvidenceSet(evidence),
            validationTimeUtc ?? pki.ReferenceTimeUtc,
            TimeSpan.FromMinutes(5)));

    private static RevocationEvidence Evidence(
        RevocationEvidenceType type,
        RevocationEvidenceSource source,
        byte[] encoded) => new(type, source, encoded);

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);
}
