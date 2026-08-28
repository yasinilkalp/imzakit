using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Core.Net;
using ImzaKit.Testing.Certificates;
using ImzaKit.Trust.Packaging;

namespace ImzaKit.Trust.Tests.Packaging;

public sealed class TrustStoreUpdateChannelTests
{
    [Fact]
    public async Task PullActivatesSignedPackageFromHttpsChannel()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] package = TrustStorePackageCodec.Sign(
            CreateManifest(1, "2026.08.1", pki.Root),
            releaseKey);
        Uri source = new("https://trust.example/imzakit/2026.08.1.json");
        TrustStoreActivationService service = new(releaseKey);
        TrustStoreUpdateChannel channel = new(service, new ScriptedFetcher((_, _) => package));

        TrustStoreActivationResult result = await channel.PullAsync(source, CancellationToken.None);

        Assert.Equal(TrustStoreActivationStatus.Activated, result.Status);
        Assert.Equal("2026.08.1", service.Current!.Version);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(pki.Root.Export(X509ContentType.Cert))),
            Assert.Single(service.Current.Anchors).Certificate.Sha256Thumbprint);
    }

    [Fact]
    public async Task PullAfterEmergencyRemovalRejectsPackageThatReintroducesTombstone()
    {
        using TestCertificateAuthority compromisedPki = TestCertificateAuthority.Create();
        using TestCertificateAuthority replacementPki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreActivationService service = new(releaseKey);
        Uri source = new("https://trust.example/imzakit/current.json");
        byte[] initial = TrustStorePackageCodec.Sign(
            CreateManifest(1, "2026.08.1", compromisedPki.Root),
            releaseKey);
        byte[] stale = TrustStorePackageCodec.Sign(
            CreateManifest(2, "2026.08.2", compromisedPki.Root),
            releaseKey);
        byte[] rotated = TrustStorePackageCodec.Sign(
            CreateManifest(2, "2026.08.2", replacementPki.Root),
            releaseKey);
        Queue<byte[]> packages = new([initial, stale, rotated]);
        TrustStoreUpdateChannel channel = new(service, new ScriptedFetcher(Respond));

        await channel.PullAsync(source, CancellationToken.None);
        string compromised = Convert.ToHexString(SHA256.HashData(compromisedPki.Root.Export(X509ContentType.Cert)));
        service.EmergencyRemove(compromised, "compromised-channel-root");
        TrustStoreActivationResult rejected = await channel.PullAsync(source, CancellationToken.None);
        TrustStoreActivationResult accepted = await channel.PullAsync(source, CancellationToken.None);

        Assert.Equal(TrustStoreActivationStatus.Rejected, rejected.Status);
        Assert.Equal("IMZAKIT.TRUST.TOMBSTONED_ANCHOR", rejected.Reason);
        Assert.Equal(TrustStoreActivationStatus.Activated, accepted.Status);
        Assert.Equal("2026.08.2", service.Current!.Version);
        Assert.Empty(service.Tombstones);

        byte[] Respond(Uri _, byte[] __) => packages.Dequeue();
    }

    [Fact]
    public async Task PullRejectsUnsignedChannelPayload()
    {
        using TestCertificateAuthority pki = TestCertificateAuthority.Create();
        using ECDsa releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustStoreActivationService service = new(releaseKey);
        byte[] forged = TrustStorePackageCodec.Sign(
            CreateManifest(1, "2026.08.1", pki.Root),
            stranger);
        TrustStoreUpdateChannel channel = new(service, new ScriptedFetcher((_, _) => forged));

        TrustStoreActivationResult result = await channel.PullAsync(
            new Uri("https://trust.example/imzakit/forged.json"),
            CancellationToken.None);

        Assert.Equal(TrustStoreActivationStatus.Rejected, result.Status);
        Assert.Equal("IMZAKIT.TRUST.INVALID_SIGNATURE", result.Reason);
        Assert.Null(service.Current);
    }

    private static TrustStoreManifest CreateManifest(int sequence, string version, X509Certificate2 root)
    {
        byte[] der = root.Export(X509ContentType.Cert);
        return new TrustStoreManifest(
            sequence,
            version,
            ImzaKit.Trust.Models.ValidationProfile.TurkiyeNes,
            "alg-2026.08",
            "ImzaKit Trust Maintainer",
            new DateTimeOffset(2026, 8, 29, 0, 0, 0, TimeSpan.Zero),
            "abc123def456",
            "https://github.com/yasinilkalp/imzakit",
            [
                new TrustStorePackageEntry(
                    "ImzaKit Test ESHS",
                    ImzaKit.Trust.Models.TrustAnchorRole.Root,
                    Convert.ToBase64String(der),
                    Convert.ToHexString(SHA256.HashData(der)),
                    new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero),
                    ["2.16.792.1.2.1.1.7.1"],
                    [ImzaKit.Trust.Models.ValidationProfile.TurkiyeNes],
                    "synthetic-test-root",
                    "channel-update")
            ]);
    }

    private sealed class ScriptedFetcher(Func<Uri, byte[], byte[]> respond) : IExternalResourceFetcher
    {
        public Task<ExternalResourceFetchResult> FetchAsync(
            ExternalResourceFetchRequest request,
            CancellationToken cancellationToken)
        {
            Assert.Equal("GET", request.Method, StringComparer.OrdinalIgnoreCase);
            Assert.Contains("application/json", request.AllowedResponseContentTypes);
            return Task.FromResult(new ExternalResourceFetchResult(respond(request.Uri, request.Body), "application/json"));
        }
    }
}
