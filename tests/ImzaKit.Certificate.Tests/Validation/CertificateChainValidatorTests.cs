using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Certificate.Validation;
using ImzaKit.Testing.Certificates;

namespace ImzaKit.Certificate.Tests.Validation;

public sealed class CertificateChainValidatorTests
{
    [Fact]
    public void ValidateAcceptsCompleteChainAtConfiguredUtcTime()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc));

        Assert.Equal(CertificateChainStatus.Valid, result.Status);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void ValidateRejectsCertificateAfterItsValidityWindow()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc.AddYears(2)));

        Assert.Equal(CertificateChainStatus.Invalid, result.Status);
        Assert.Contains(CertificateValidationFailure.Expired, result.Failures);
    }

    [Fact]
    public void ValidateRejectsCertificateBeforeItsValidityWindow()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc.AddYears(-1)));

        Assert.Equal(CertificateChainStatus.Invalid, result.Status);
        Assert.Contains(CertificateValidationFailure.NotYetValid, result.Failures);
    }

    [Fact]
    public void RequestRejectsNonUtcValidationTime()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        DateTimeOffset localTime = new(2026, 8, 23, 15, 0, 0, TimeSpan.FromHours(3));

        Assert.Throws<ArgumentException>(() =>
            new CertificateChainValidationRequest(CreateCandidate(pki), localTime));
    }

    [Fact]
    public void ValidateRejectsLeafSignedByDifferentIssuer()
    {
        using TestCertificateAuthority first = TestCertificateAuthority.Create();
        using TestCertificateAuthority second = TestCertificateAuthority.Create();
        CertificateChainCandidate mismatched = new([
            Describe(first.Leaf, CertificateSource.Embedded),
            Describe(second.Intermediate, CertificateSource.Embedded),
            Describe(second.Root, CertificateSource.Local)]);

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(mismatched, first.ReferenceTimeUtc));

        Assert.Equal(CertificateChainStatus.Invalid, result.Status);
        Assert.Contains(CertificateValidationFailure.InvalidSignature, result.Failures);
    }

    [Fact]
    public void ValidateRejectsIssuerThatIsNotACertificateAuthority()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(intermediateIsCa: false);

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc));

        Assert.Contains(CertificateValidationFailure.IssuerIsNotCa, result.Failures);
    }

    [Fact]
    public void ValidateRejectsIssuerWithoutKeyCertSignUsage()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(intermediateHasKeyCertSign: false);

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc));

        Assert.Contains(CertificateValidationFailure.IssuerKeyCertSignMissing, result.Failures);
    }

    [Fact]
    public void ValidateRejectsLeafWithoutDigitalSignatureUsage()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(leafHasDigitalSignature: false);

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc));

        Assert.Contains(CertificateValidationFailure.LeafDigitalSignatureMissing, result.Failures);
    }

    [Fact]
    public void ValidateRejectsSha1CertificateSignatures()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create(useSha1Signatures: true);

        CertificateChainValidationResult result = new CertificateChainValidator().Validate(
            new CertificateChainValidationRequest(CreateCandidate(pki), pki.ReferenceTimeUtc));

        Assert.Contains(CertificateValidationFailure.AlgorithmDisallowed, result.Failures);
    }

    private static CertificateChainCandidate CreateCandidate(TestCertificateAuthority pki) =>
        new([
            Describe(pki.Leaf, CertificateSource.Embedded),
            Describe(pki.Intermediate, CertificateSource.Embedded),
            Describe(pki.Root, CertificateSource.Local)]);

    private static CertificateDescriptor Describe(X509Certificate2 certificate, CertificateSource source) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), source);
}
