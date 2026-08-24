using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;
using ImzaKit.Pkcs11.Signing;

namespace ImzaKit.Pkcs11.Tests.Native;

public sealed class NativePkcs11ProviderTests
{
    [Fact]
    public void DiscoverTokensMasksSerialAndListsOnlyPresentSlots()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);

        provider.Initialize();
        IReadOnlyList<Pkcs11Token> tokens = provider.DiscoverTokens();

        Pkcs11Token token = Assert.Single(tokens);
        Assert.Equal(7UL, token.SlotId);
        Assert.Equal("AKIS", token.Label);
        Assert.Equal("KamuSM", token.Manufacturer);
        Assert.Equal("Model", token.Model);
        Assert.Equal("****7890", token.MaskedSerialNumber);
        Assert.Equal(1, api.InitializeCalls);
    }

    [Fact]
    public void InitializeIsIdempotentAtProviderLevel()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);

        provider.Initialize();
        provider.Initialize();

        Assert.Equal(1, api.InitializeCalls);
    }

    [Fact]
    public void FindCertificatesReturnsOnlyX509WithSignablePrivateKey()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        ulong session = provider.OpenSession(7);

        IReadOnlyList<Pkcs11Certificate> certificates = provider.FindCertificates(session);

        Pkcs11Certificate certificate = Assert.Single(certificates);
        Assert.Equal([1, 2], certificate.CkaId);
        Assert.Equal("NES", certificate.Label);
        Assert.Equal(api.SignableCertificateDer, certificate.DerEncoded);
        Assert.False(api.PrivateKeyValueWasRead);
    }

    [Fact]
    public void PrivateKeyIsMatchedByCkaIdFirst()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        ulong session = provider.OpenSession(7);

        ulong? handle = provider.FindPrivateKey(session, [1, 2]);

        Assert.Equal(21UL, handle);
    }

    [Fact]
    public void PrivateKeyFallsBackToRsaModulusWhenCkaIdDiffers()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new("CN=ImzaKit Fallback", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = certificate.Export(X509ContentType.Cert);
        byte[] modulus = rsa.ExportParameters(includePrivateParameters: false).Modulus
            ?? throw new InvalidOperationException("RSA modulus was missing.");
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateModulusFallbackFixture(der, modulus);
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        ulong session = provider.OpenSession(7);

        IReadOnlyList<Pkcs11Certificate> certificates = provider.FindCertificates(session);
        ulong? handle = provider.FindPrivateKey(session, certificates[0].CkaId);

        Assert.Equal([0xAA], Assert.Single(certificates).CkaId);
        Assert.Equal(42UL, handle);
        Assert.False(api.PrivateKeyValueWasRead);
    }

    [Fact]
    public void SignUsesSha256RsaPkcsAndReturnsCardSignature()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        ulong session = provider.OpenSession(7);

        byte[] signature = provider.SignRsaPkcs1Sha256(session, 21, [9, 9, 9]);

        Assert.Equal([0x55, 0x66], signature);
        Assert.Equal(Pkcs11NativeConstants.CkmSha256RsaPkcs, api.LastSignMechanism);
    }

    [Theory]
    [InlineData(Pkcs11ErrorCode.PinIncorrect, "secret-pin")]
    [InlineData(Pkcs11ErrorCode.PinLocked, "secret-pin")]
    public void LoginFailuresAreDistinctAndNeverEchoPin(Pkcs11ErrorCode code, string pin)
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        api.LoginFailure = code;
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        ulong session = provider.OpenSession(7);

        Pkcs11ProviderException exception = Assert.Throws<Pkcs11ProviderException>(
            () => provider.Login(session, pin.AsSpan()));

        Assert.Equal(code, exception.Code);
        Assert.DoesNotContain(pin, exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(pin, exception.ToString(), StringComparison.Ordinal);
        Assert.NotNull(api.LastLoginPinBuffer);
        Assert.All(api.LastLoginPinBuffer!, value => Assert.Equal(0, value));
    }

    [Fact]
    public void TokenRemovalAndUnsupportedMechanismHaveDedicatedCodes()
    {
        FakePkcs11NativeApi removed = FakePkcs11NativeApi.CreateAkisFixture();
        removed.SignFailure = Pkcs11ErrorCode.TokenRemoved;
        using NativePkcs11Provider removedProvider = new(removed);
        removedProvider.Initialize();
        ulong session = removedProvider.OpenSession(7);
        Pkcs11ProviderException removedException = Assert.Throws<Pkcs11ProviderException>(
            () => removedProvider.SignRsaPkcs1Sha256(session, 21, [1]));
        Assert.Equal(Pkcs11ErrorCode.TokenRemoved, removedException.Code);

        FakePkcs11NativeApi mechanism = FakePkcs11NativeApi.CreateAkisFixture();
        mechanism.SignFailure = Pkcs11ErrorCode.MechanismUnsupported;
        using NativePkcs11Provider mechanismProvider = new(mechanism);
        mechanismProvider.Initialize();
        session = mechanismProvider.OpenSession(7);
        Pkcs11ProviderException mechanismException = Assert.Throws<Pkcs11ProviderException>(
            () => mechanismProvider.SignRsaPkcs1Sha256(session, 21, [1]));
        Assert.Equal(Pkcs11ErrorCode.MechanismUnsupported, mechanismException.Code);
    }

    [Fact]
    public void FinalizeProviderClosesOutstandingSessions()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);
        provider.Initialize();
        provider.OpenSession(7);
        provider.OpenSession(7);

        provider.FinalizeProvider();

        Assert.Equal(0, api.OpenSessionCount);
        Assert.Equal(1, api.FinalizeCalls);
    }

    [Fact]
    public void SingleThreadedAkisAccessDoesNotOverlapNativeCalls()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        api.CallDelay = TimeSpan.FromMilliseconds(10);
        using NativePkcs11Provider provider = new(api, NativePkcs11ProviderOptions.ForAkis());
        provider.Initialize();

        Parallel.For(0, 8, _ => provider.DiscoverTokens());

        Assert.Equal(1, api.MaxConcurrentCalls);
    }

    [Fact]
    public void EtokenOptionsUseSingleThreadedAccessLikeAkis()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        api.CallDelay = TimeSpan.FromMilliseconds(10);
        using NativePkcs11Provider provider = new(api, NativePkcs11ProviderOptions.ForEtoken());
        provider.Initialize();

        Parallel.For(0, 8, _ => provider.DiscoverTokens());

        Assert.Equal(1, api.MaxConcurrentCalls);
    }

    [Fact]
    public void SigningServiceCleansUpAfterNativeAdapterSuccess()
    {
        FakePkcs11NativeApi api = FakePkcs11NativeApi.CreateAkisFixture();
        using NativePkcs11Provider provider = new(api);
        Pkcs11SigningResult result = new Pkcs11SigningService(provider).Sign(
            7, [1, 2], "1234".AsSpan(), [1, 2, 3]);

        Assert.Equal(Pkcs11SigningStatus.Succeeded, result.Status);
        Assert.Equal([0x55, 0x66], result.Signature);
        Assert.Equal(0, api.OpenSessionCount);
        Assert.Equal(1, api.FinalizeCalls);
        Assert.DoesNotContain("1234", string.Join('|', api.Calls), StringComparison.Ordinal);
    }

    [Fact]
    public void CatalogRegistersMultipleNamedProviders()
    {
        using Pkcs11ProviderCatalog catalog = new();
        catalog.Register("akis", new NativePkcs11Provider(FakePkcs11NativeApi.CreateAkisFixture()));
        catalog.Register("lab", new NativePkcs11Provider(FakePkcs11NativeApi.CreateAkisFixture()));

        Assert.Equal(2, catalog.Names.Count);
        Assert.NotNull(catalog.GetRequired("akis"));
        Assert.NotNull(catalog.GetRequired("AKIS"));
    }

    [Fact]
    public void CorruptNativeModuleIsDriverErrorWithoutClaimingHardwareSuccess()
    {
        string root = Path.Combine(Path.GetTempPath(), "imzakit-pkcs11-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, "akisp11.dll");
        File.WriteAllBytes(path, [0x00, 0x01, 0x02]);

        try
        {
            Pkcs11ProviderException exception = Assert.Throws<Pkcs11ProviderException>(
                () => Pkcs11NativeLibraryLoader.Load(path, [root]));
            Assert.Equal(Pkcs11ErrorCode.DriverError, exception.Code);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
