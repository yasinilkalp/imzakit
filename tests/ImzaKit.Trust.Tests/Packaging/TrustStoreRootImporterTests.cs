using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Models;
using ImzaKit.Trust.Packaging;

namespace ImzaKit.Trust.Tests.Packaging;

public sealed class TrustStoreRootImporterTests
{
    [Fact]
    public void DirectoryOfPemRootsBuildsSignedPackageWithoutUsingSystemStore()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string directory = Path.Combine(Path.GetTempPath(), "imzakit-eshs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(
                Path.Combine(directory, "synthetic-eshs.pem"),
                PemEncoding.WriteString("CERTIFICATE", pki.Root.Export(X509ContentType.Cert)));

            byte[] package = TrustStoreRootImporter.ImportFromDirectory(
                directory,
                releaseKey,
                new TrustStoreImportRequest(
                    Sequence: 1,
                    Version: "2026.08-lab",
                    ProviderName: "Lab ESHS",
                    Provenance: "lab-file-import",
                    SourceUri: "file://lab/eshs",
                    PolicyOids: ["2.16.792.1.2.1.1.7.1"]));

            Assert.True(TrustStorePackageCodec.TryVerify(package, releaseKey, out TrustStoreManifest? manifest));
            Assert.Equal("2026.08-lab", manifest!.Version);
            Assert.Equal(ValidationProfile.TurkiyeNes, manifest.Profile);
            Assert.Equal("lab-file-import", Assert.Single(manifest.Entries).Provenance);
            Assert.DoesNotContain("CurrentUser", manifest.Entries[0].Provenance, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("LocalMachine", manifest.Entries[0].Provenance, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void SystemStoreProvenanceAndEmptyDirectoryAreRejected()
    {
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string directory = Path.Combine(Path.GetTempPath(), "imzakit-eshs-empty-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            Assert.Throws<InvalidOperationException>(() =>
                TrustStoreRootImporter.ImportFromDirectory(
                    directory,
                    releaseKey,
                    new TrustStoreImportRequest(1, "v", "p", "lab", "file://x", ["1.2.3"])));
            Assert.Throws<ArgumentException>(() =>
                TrustStoreRootImporter.ImportFromDirectory(
                    directory,
                    releaseKey,
                    new TrustStoreImportRequest(1, "v", "p", "X509Store.LocalMachine", "file://x", ["1.2.3"])));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
