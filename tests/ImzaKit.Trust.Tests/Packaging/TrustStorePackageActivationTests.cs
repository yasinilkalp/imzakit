using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Models;
using ImzaKit.Trust.Packaging;

namespace ImzaKit.Trust.Tests.Packaging;

public sealed class TrustStorePackageActivationTests
{
    [Fact]
    public void SignedPackageActivatesAtomicallyAndIgnoresSystemStore()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreManifest manifest = CreateManifest(1, "2026.08.1", pki.Root, removed: false);
        byte[] package = TrustStorePackageCodec.Sign(manifest, releaseKey);

        TrustStoreActivationService service = new(releaseKey);
        TrustStoreActivationResult result = service.Activate(package);

        Assert.Equal(TrustStoreActivationStatus.Activated, result.Status);
        Assert.Equal("2026.08.1", result.Snapshot!.Version);
        Assert.Equal("2026.08.1-policy", result.Catalog!.Version);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(pki.Root.Export(X509ContentType.Cert))),
            Assert.Single(result.Snapshot.Anchors).Certificate.Sha256Thumbprint);
        Assert.Equal(TrustAnchorRole.Root, result.Snapshot.Anchors[0].Role);
        Assert.Contains("2.16.792.1.2.1.1.7.1", result.Catalog.Entries.Select(entry => entry.PolicyOid));
        Assert.Equal("synthetic-test-root", result.Snapshot.Anchors[0].Provenance);
    }

    [Fact]
    public void InvalidSignatureAndStaleSequenceLeaveCurrentPackageUnchanged()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreActivationService service = new(releaseKey);
        TrustStoreActivationResult first = service.Activate(
            TrustStorePackageCodec.Sign(CreateManifest(1, "2026.08.1", pki.Root, removed: false), releaseKey));

        byte[] forged = TrustStorePackageCodec.Sign(CreateManifest(2, "2026.08.2", pki.Root, removed: false), stranger);
        TrustStoreActivationResult invalid = service.Activate(forged);
        TrustStoreActivationResult stale = service.Activate(
            TrustStorePackageCodec.Sign(CreateManifest(1, "2026.08.0", pki.Root, removed: false), releaseKey));

        Assert.Equal(TrustStoreActivationStatus.Activated, first.Status);
        Assert.Equal(TrustStoreActivationStatus.Rejected, invalid.Status);
        Assert.Equal("IMZAKIT.TRUST.INVALID_SIGNATURE", invalid.Reason);
        Assert.Equal(TrustStoreActivationStatus.Rejected, stale.Status);
        Assert.Equal("IMZAKIT.TRUST.STALE_VERSION", stale.Reason);
        Assert.Equal("2026.08.1", service.Current!.Version);
    }

    [Fact]
    public void RollbackRestoresPreviousVerifiedPackage()
    {
        using TestCertificateAuthority firstPki = TestCertificateAuthority.Create();
        using TestCertificateAuthority secondPki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreActivationService service = new(releaseKey);
        service.Activate(TrustStorePackageCodec.Sign(CreateManifest(1, "2026.08.1", firstPki.Root, removed: false), releaseKey));
        service.Activate(TrustStorePackageCodec.Sign(CreateManifest(2, "2026.08.2", secondPki.Root, removed: false), releaseKey));

        TrustStoreActivationResult rollback = service.Rollback();

        Assert.Equal(TrustStoreActivationStatus.RolledBack, rollback.Status);
        Assert.Equal("2026.08.1", service.Current!.Version);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(firstPki.Root.Export(X509ContentType.Cert))),
            Assert.Single(service.Current.Anchors).Certificate.Sha256Thumbprint);
    }

    [Fact]
    public void EmergencyRemovalDropsAnchorAndRecordsRationale()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreActivationService service = new(releaseKey);
        service.Activate(TrustStorePackageCodec.Sign(CreateManifest(1, "2026.08.1", pki.Root, removed: false), releaseKey));
        string thumbprint = Convert.ToHexString(SHA256.HashData(pki.Root.Export(X509ContentType.Cert)));

        TrustStoreActivationResult removed = service.EmergencyRemove(thumbprint, "compromised-test-root");

        Assert.Equal(TrustStoreActivationStatus.Removed, removed.Status);
        Assert.Empty(service.Current!.Anchors);
        Assert.Equal("compromised-test-root", removed.ChangeRationale);
        Assert.StartsWith("2026.08.1-removed-", service.Current.Version, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidationProfilesIncludeEidasForLaterPhase()
    {
        Assert.True(Enum.IsDefined(ValidationProfile.Eidas));
        Assert.True(Enum.IsDefined(ValidationProfile.TurkiyeNes));
        Assert.True(Enum.IsDefined(ValidationProfile.GeneralX509));
    }

    private static TrustStoreManifest CreateManifest(int sequence, string version, X509Certificate2 root, bool removed)
    {
        byte[] der = root.Export(X509ContentType.Cert);
        return new TrustStoreManifest(
            sequence,
            version,
            ValidationProfile.TurkiyeNes,
            "alg-2026.08",
            "ImzaKit Trust Maintainer",
            new DateTimeOffset(2026, 8, 24, 8, 0, 0, TimeSpan.Zero),
            "abc123def456",
            "https://github.com/yasinilkalp/imzakit",
            [
                new TrustStorePackageEntry(
                    "ImzaKit Test ESHS",
                    TrustAnchorRole.Root,
                    Convert.ToBase64String(der),
                    Convert.ToHexString(SHA256.HashData(der)),
                    new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero),
                    ["2.16.792.1.2.1.1.7.1"],
                    [ValidationProfile.TurkiyeNes],
                    "synthetic-test-root",
                    "initial-add",
                    removed)
            ]);
    }
}
