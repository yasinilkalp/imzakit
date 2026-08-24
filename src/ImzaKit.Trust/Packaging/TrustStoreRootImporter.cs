using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Packaging;

public sealed record TrustStoreImportRequest(
    int Sequence,
    string Version,
    string ProviderName,
    string Provenance,
    string SourceUri,
    IReadOnlyList<string> PolicyOids);

public static class TrustStoreRootImporter
{
    public static byte[] ImportFromDirectory(
        string directory,
        ECDsa releaseKey,
        TrustStoreImportRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(releaseKey);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Version);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.ProviderName);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Provenance);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.SourceUri);
        RejectSystemStore(request.Provenance);

        string[] files = Directory.Exists(directory)
            ? Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly)
                .Where(path => path.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".crt", StringComparison.OrdinalIgnoreCase) ||
                               path.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray()
            : [];
        if (files.Length == 0)
        {
            throw new InvalidOperationException("Trust Store import directory contains no certificate files.");
        }

        List<TrustStorePackageEntry> entries = [];
        foreach (string file in files)
        {
            using X509Certificate2 certificate = LoadCertificate(file);
            byte[] der = certificate.Export(X509ContentType.Cert);
            entries.Add(new TrustStorePackageEntry(
                request.ProviderName,
                TrustAnchorRole.Root,
                Convert.ToBase64String(der),
                Convert.ToHexString(SHA256.HashData(der)),
                certificate.NotBefore.ToUniversalTime(),
                certificate.NotAfter.ToUniversalTime(),
                request.PolicyOids,
                [ValidationProfile.TurkiyeNes],
                request.Provenance,
                "directory-import"));
        }

        TrustStoreManifest manifest = new(
            request.Sequence,
            request.Version,
            ValidationProfile.TurkiyeNes,
            "alg-imported",
            "ImzaKit Trust Maintainer",
            DateTimeOffset.UtcNow,
            "local-import",
            request.SourceUri,
            entries);
        return TrustStorePackageCodec.Sign(manifest, releaseKey);
    }

    private static void RejectSystemStore(string provenance)
    {
        if (provenance.Contains("X509Store", StringComparison.OrdinalIgnoreCase) ||
            provenance.Contains("LocalMachine", StringComparison.OrdinalIgnoreCase) ||
            provenance.Contains("CurrentUser", StringComparison.OrdinalIgnoreCase) ||
            provenance.Contains("system store", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("ESHS roots must not be imported from the OS certificate store.", nameof(provenance));
        }
    }

    private static X509Certificate2 LoadCertificate(string path)
    {
        string text = File.ReadAllText(path);
        return text.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal)
            ? X509Certificate2.CreateFromPem(text)
            : X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
    }
}
