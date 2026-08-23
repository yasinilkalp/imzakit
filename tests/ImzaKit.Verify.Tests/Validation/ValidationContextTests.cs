using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Models;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class ValidationContextTests
{
    [Fact]
    public void ContextCopiesCertificateCollectionsAndPreservesVersionedInputs()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        List<CertificateDescriptor> embedded = [Describe(pki.Intermediate)];
        TrustStoreSnapshot trustStore = new(
            "trust-v1",
            [new(Describe(pki.Root), [ValidationProfile.GeneralX509])]);
        CertificatePolicyCatalog catalog = new("policy-v1", []);

        ValidationContext context = new(
            ValidationProfile.GeneralX509,
            pki.ReferenceTimeUtc,
            ValidationTimeSource.CurrentSystemTime,
            trustStore,
            catalog,
            embeddedIntermediates: embedded);
        embedded.Clear();

        Assert.Single(context.EmbeddedIntermediates);
        Assert.Equal("trust-v1", context.TrustStore.Version);
        Assert.Equal("policy-v1", context.PolicyCatalog.Version);
        Assert.Empty(context.LocalIntermediates);
        Assert.Empty(context.RevocationEvidence.Evidence);
    }

    [Fact]
    public void ContextRejectsNonUtcValidationTime()
    {
        DateTimeOffset local = new(2026, 8, 23, 15, 0, 0, TimeSpan.FromHours(3));

        Assert.Throws<ArgumentException>(() => new ValidationContext(
            ValidationProfile.GeneralX509,
            local,
            ValidationTimeSource.CurrentSystemTime,
            new TrustStoreSnapshot("trust-v1", []),
            new CertificatePolicyCatalog("policy-v1", [])));
    }

    [Fact]
    public void ExistingReportAndFindingConstructorsRemainSourceCompatible()
    {
        ValidationFinding finding = new("TrustNotEvaluated", "Trust was not evaluated.");
        PadesValidationReport report = new(
            ValidationStatus.Indeterminate,
            ValidationStatus.Passed,
            ValidationStatus.Passed,
            ValidationStatus.Indeterminate,
            "AA",
            [finding]);

        Assert.Equal(ValidationStatus.Indeterminate, report.Status);
        Assert.Null(report.ValidationProfile);
        Assert.Null(finding.ReasonCode);
    }

    [Fact]
    public void ReasonCodeContractContainsTheApprovedMachineReadableSet()
    {
        string[] expected = [
            "CertificateExpired", "CertificateNotYetValid", "CertificateChainIncomplete",
            "CertificateChainInvalid", "TrustAnchorNotFound", "CertificatePolicyNotAllowed",
            "RevocationDataUnavailable", "RevocationDataStale", "RevocationDataInvalid",
            "CertificateRevoked", "CertificateSuspended", "ValidationTimeUntrusted",
            "AlgorithmDisallowed"];

        Assert.Equal(expected, Enum.GetNames<ValidationReasonCode>());
    }

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);
}
