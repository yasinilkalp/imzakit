using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Desktop.Tests.Pkcs11;

public sealed class TokenCertificateCatalogTests
{
    [Fact]
    public void EmptyProvidersYieldEmptyList()
    {
        IReadOnlyList<DesktopCertificateItem> items = TokenCertificateCatalog.List([]);
        Assert.Empty(items);
    }

    [Fact]
    public void DiscoverFailureYieldsEmptyListWithoutThrowing()
    {
        IReadOnlyList<DesktopCertificateItem> items = TokenCertificateCatalog.List(
            [new NamedPkcs11Provider("broken", new ThrowingDiscoverProvider())]);
        Assert.Empty(items);
    }

    [Fact]
    public void ListsCertificatesWithoutLogin()
    {
        using ListingProvider provider = new();
        IReadOnlyList<DesktopCertificateItem> items = TokenCertificateCatalog.List(
            [new NamedPkcs11Provider("AKİS", provider)]);

        Assert.False(provider.LoggedIn);
        Assert.Single(items);
        Assert.Equal("AKİS", items[0].ProviderName);
        Assert.Equal(7UL, items[0].SlotId);
        Assert.Equal("CN=Desktop Catalog", items[0].Subject);
        Assert.True(provider.SessionClosed);
    }

    private sealed class ThrowingDiscoverProvider : IPkcs11Provider
    {
        public void Initialize() { }
        public IReadOnlyList<Pkcs11Token> DiscoverTokens() =>
            throw new Pkcs11ProviderException(Pkcs11ErrorCode.DriverError);
        public ulong OpenSession(ulong slotId) => 1;
        public void Login(ulong session, ReadOnlySpan<char> pin) { }
        public IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session) => [];
        public ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId) => null;
        public byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> data) => [];
        public void Logout(ulong session) { }
        public void CloseSession(ulong session) { }
        public void FinalizeProvider() { }
    }

    private sealed class ListingProvider : IPkcs11Provider, IDisposable
    {
        private readonly System.Security.Cryptography.X509Certificates.X509Certificate2 _certificate;
        public bool LoggedIn { get; private set; }
        public bool SessionClosed { get; private set; }
        public Pkcs11Certificate Certificate { get; }

        public ListingProvider()
        {
            using System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048);
            System.Security.Cryptography.X509Certificates.CertificateRequest request = new(
                "CN=Desktop Catalog",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            _certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
            Certificate = new([1], "label", _certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
        }

        public void Initialize() { }
        public IReadOnlyList<Pkcs11Token> DiscoverTokens() =>
            [new Pkcs11Token(7, "token", "m", "model", "****1")];
        public ulong OpenSession(ulong slotId) => 11;
        public void Login(ulong session, ReadOnlySpan<char> pin) => LoggedIn = true;
        public IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session) => [Certificate];
        public ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId) => null;
        public byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> data) => [];
        public void Logout(ulong session) { }
        public void CloseSession(ulong session) => SessionClosed = true;
        public void FinalizeProvider() { }
        public void Dispose() => _certificate.Dispose();
    }
}
