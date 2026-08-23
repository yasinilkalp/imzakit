using System.Security.Cryptography.X509Certificates;
using ImzaKit.Certificate.Models;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Tests.Models;

public sealed class TrustModelTests
{
    private static readonly DateTimeOffset FromUtc = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TrustStoreRejectsBlankVersion(string version)
    {
        Assert.Throws<ArgumentException>(() => new TrustStoreSnapshot(version, []));
    }

    [Fact]
    public void TrustStoreRejectsDuplicateCertificateAnchor()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        CertificateDescriptor root = Describe(pki.Root);

        Assert.Throws<ArgumentException>(() => new TrustStoreSnapshot(
            "trust-v1",
            [new(root, [ValidationProfile.GeneralX509]), new(root, [ValidationProfile.TurkiyeNes])]));
    }

    [Fact]
    public void TrustStoreCopiesAnchorAndProfileCollections()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        List<ValidationProfile> profiles = [ValidationProfile.GeneralX509];
        TrustAnchor anchor = new(Describe(pki.Root), profiles, "test-root");
        List<TrustAnchor> anchors = [anchor];
        TrustStoreSnapshot snapshot = new(" trust-v1 ", anchors);

        profiles.Add(ValidationProfile.TurkiyeNes);
        anchors.Clear();

        Assert.Equal("trust-v1", snapshot.Version);
        Assert.Single(snapshot.Anchors);
        Assert.Single(snapshot.Anchors[0].Profiles);
        Assert.Equal("test-root", snapshot.Anchors[0].Provenance);
    }

    [Theory]
    [InlineData("not-an-oid")]
    [InlineData("1..2")]
    [InlineData("3.1.2")]
    public void PolicyCatalogRejectsMalformedOid(string policyOid)
    {
        Assert.Throws<ArgumentException>(() => new CertificatePolicyCatalog(
            "policy-v1",
            [new(ValidationProfile.TurkiyeNes, policyOid, FromUtc, null, TimeSpan.FromHours(12))]));
    }

    [Fact]
    public void PolicyEntryRejectsNonUtcAndReversedValidityWindow()
    {
        DateTimeOffset local = new(2026, 1, 1, 3, 0, 0, TimeSpan.FromHours(3));
        Assert.Throws<ArgumentException>(() => new CertificatePolicyEntry(
            ValidationProfile.TurkiyeNes, "2.16.792.1", local, null, TimeSpan.Zero));
        Assert.Throws<ArgumentException>(() => new CertificatePolicyEntry(
            ValidationProfile.TurkiyeNes, "2.16.792.1", FromUtc, FromUtc.AddDays(-1), TimeSpan.Zero));
    }

    [Fact]
    public void PolicyCatalogRejectsDuplicateEntriesAndCopiesInput()
    {
        CertificatePolicyEntry entry = new(
            ValidationProfile.TurkiyeNes,
            "2.16.792.1.2.1.1.7.1",
            FromUtc,
            FromUtc.AddYears(1),
            TimeSpan.FromHours(12));
        List<CertificatePolicyEntry> entries = [entry];
        CertificatePolicyCatalog catalog = new(" policy-v1 ", entries);
        entries.Clear();

        Assert.Equal("policy-v1", catalog.Version);
        Assert.Single(catalog.Entries);
        Assert.Throws<ArgumentException>(() => new CertificatePolicyCatalog("policy-v1", [entry, entry]));
    }

    [Fact]
    public void PolicyEntryRejectsNegativeFreshnessTolerance()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CertificatePolicyEntry(
            ValidationProfile.GeneralX509,
            "2.5.29.32.0",
            FromUtc,
            null,
            TimeSpan.FromTicks(-1)));
    }

    private static CertificateDescriptor Describe(X509Certificate2 certificate) =>
        CertificateDescriptor.FromDer(certificate.Export(X509ContentType.Cert), CertificateSource.Local);
}
