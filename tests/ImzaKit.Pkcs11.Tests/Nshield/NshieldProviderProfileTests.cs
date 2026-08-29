using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Native;
using ImzaKit.Pkcs11.Nshield;

namespace ImzaKit.Pkcs11.Tests.Nshield;

public sealed class NshieldProviderProfileTests
{
    [Fact]
    public void CapturesNshieldPkcs11ProviderContract()
    {
        Assert.Equal("nShield", NshieldProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", NshieldProviderProfile.SigningMechanism);
        Assert.True(NshieldProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(NshieldProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst, NshieldProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(AkisProviderProfile.RequiresSingleThreadedProviderAccess, NshieldProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(["cknfast.dll", "libcknfast.so"], NshieldProviderProfile.SupportedLibraryFileNames);
        Assert.DoesNotContain("cryptoki.dll", NshieldProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("cknfcew.dll", NshieldProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"%ProgramFiles%\nCipher\nfast\bin", NshieldProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains(@"%ProgramFiles%\Entrust\nShield\nfast\bin", NshieldProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains("/opt/nfast/toolkits/pkcs11", NshieldProviderProfile.RecommendedAllowlistRoots);
        Assert.DoesNotContain(NshieldProviderProfile.RecommendedAllowlistRoots, root =>
            root.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForNshieldMatchesAkisSafeDefaults()
    {
        NativePkcs11ProviderOptions nshield = NativePkcs11ProviderOptions.ForNshield();
        NativePkcs11ProviderOptions akis = NativePkcs11ProviderOptions.ForAkis();
        Assert.Equal(akis.RequiresSingleThreadedProviderAccess, nshield.RequiresSingleThreadedProviderAccess);
        Assert.Equal(akis.MatchPrivateKeyByCkaIdFirst, nshield.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(akis.AllowPublicKeyFallback, nshield.AllowPublicKeyFallback);
        Assert.Equal(akis.ExcludeCertificatesWithoutSignableKey, nshield.ExcludeCertificatesWithoutSignableKey);
    }
}
