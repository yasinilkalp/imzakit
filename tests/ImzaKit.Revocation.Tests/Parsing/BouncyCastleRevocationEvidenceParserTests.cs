using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;
using ImzaKit.Revocation.Parsing;
using ImzaKit.Revocation.Tests.Fixtures;
using ImzaKit.Testing.Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace ImzaKit.Revocation.Tests.Parsing;

public sealed class BouncyCastleRevocationEvidenceParserTests
{
    [Theory]
    [InlineData(RevocationEvidenceType.Ocsp)]
    [InlineData(RevocationEvidenceType.Crl)]
    public void ParseReturnsInvalidForMalformedEvidence(RevocationEvidenceType type)
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(type, RevocationEvidenceSource.Local, new byte[] { 0x30, 0x00 });

        ParsedRevocationEvidence result = new BouncyCastleRevocationEvidenceParser().Parse(
            evidence,
            Describe(pki.Leaf),
            Describe(pki.Intermediate));

        Assert.Equal(RevocationStatus.Invalid, result.Status);
        Assert.False(result.SignatureValid);
        Assert.False(result.TargetMatches);
    }

    [Fact]
    public void ParseAcceptsIssuerSignedGoodOcspForTargetCertificate()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Embedded,
            RevocationEvidenceFixture.CreateOcsp(pki));

        ParsedRevocationEvidence result = Parse(evidence, pki);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.True(result.TargetMatches);
        Assert.True(result.SignatureValid);
        Assert.True(result.ResponderAuthorized);
        Assert.Equal(pki.ReferenceTimeUtc.AddHours(-2), result.ThisUpdateUtc);
        Assert.Equal(pki.ReferenceTimeUtc.AddHours(10), result.NextUpdateUtc);
    }

    [Fact]
    public void ParseMapsRevokedOcspToRevoked()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateOcsp(pki, revoked: true));

        ParsedRevocationEvidence result = Parse(evidence, pki);

        Assert.Equal(RevocationStatus.Revoked, result.Status);
        Assert.Equal("KeyCompromise", result.RevocationReason);
    }

    [Fact]
    public void ParseRejectsOcspWithInvalidSignature()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateOcsp(pki, invalidSignature: true));

        ParsedRevocationEvidence result = Parse(evidence, pki);

        Assert.Equal(RevocationStatus.Invalid, result.Status);
        Assert.True(result.TargetMatches);
        Assert.False(result.SignatureValid);
        Assert.False(result.ResponderAuthorized);
    }

    [Theory]
    [InlineData(CrlReason.KeyCompromise, RevocationStatus.Revoked, "KeyCompromise")]
    [InlineData(CrlReason.CertificateHold, RevocationStatus.Suspended, "CertificateHold")]
    public void ParseMapsCrlReasonToStatus(int reason, RevocationStatus expected, string expectedReason)
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Crl,
            RevocationEvidenceSource.Local,
            RevocationEvidenceFixture.CreateCrl(pki, reason));

        ParsedRevocationEvidence result = Parse(evidence, pki);

        Assert.Equal(expected, result.Status);
        Assert.Equal(expectedReason, result.RevocationReason);
        Assert.True(result.SignatureValid);
    }

    [Fact]
    public void ParseMapsIssuerCrlWithoutLeafEntryToGood()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Crl,
            RevocationEvidenceSource.Embedded,
            RevocationEvidenceFixture.CreateCrl(pki));

        ParsedRevocationEvidence result = Parse(evidence, pki);

        Assert.Equal(RevocationStatus.Good, result.Status);
        Assert.True(result.TargetMatches);
        Assert.True(result.SignatureValid);
    }

    [Theory]
    [InlineData(RevocationEvidenceType.Ocsp)]
    [InlineData(RevocationEvidenceType.Crl)]
    public void ParseMarksEvidenceForAnotherSerialAsTargetMismatch(RevocationEvidenceType type)
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using TestCertificateAuthority otherPki = TestCertificateAuthority.Create();
        byte[] encoded = type == RevocationEvidenceType.Ocsp
            ? RevocationEvidenceFixture.CreateOcsp(pki, wrongSerial: true)
            : RevocationEvidenceFixture.CreateCrl(
                otherPki,
                CrlReason.KeyCompromise,
                mismatchedIssuerName: true);

        ParsedRevocationEvidence result = Parse(
            new RevocationEvidence(type, RevocationEvidenceSource.Local, encoded),
            pki);

        Assert.False(result.TargetMatches);
    }

    private static ParsedRevocationEvidence Parse(RevocationEvidence evidence, TestCertificateAuthority pki) =>
        new BouncyCastleRevocationEvidenceParser().Parse(
            evidence,
            Describe(pki.Leaf),
            Describe(pki.Intermediate));

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);
}
