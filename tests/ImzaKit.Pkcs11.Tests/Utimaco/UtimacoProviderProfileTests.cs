using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Native;
using ImzaKit.Pkcs11.Utimaco;

namespace ImzaKit.Pkcs11.Tests.Utimaco;

public sealed class UtimacoProviderProfileTests
{
    [Fact]
    public void CapturesUtimacoPkcs11ProviderContract()
    {
        Assert.Equal("Utimaco", UtimacoProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", UtimacoProviderProfile.SigningMechanism);
        Assert.True(UtimacoProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(UtimacoProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst, UtimacoProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(AkisProviderProfile.RequiresSingleThreadedProviderAccess, UtimacoProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(
            ["cs_pkcs11_R2.dll", "cs_pkcs11_R3.dll", "libcs_pkcs11_R2.so", "libcs_pkcs11_R3.so"],
            UtimacoProviderProfile.SupportedLibraryFileNames);
        Assert.DoesNotContain("cs_pkcs11.dll", UtimacoProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("cryptoki.dll", UtimacoProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"%ProgramFiles%\Utimaco\CryptoServer\Lib", UtimacoProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains("/opt/utimaco/pkcs11", UtimacoProviderProfile.RecommendedAllowlistRoots);
        Assert.DoesNotContain(UtimacoProviderProfile.RecommendedAllowlistRoots, root =>
            root.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForUtimacoMatchesAkisSafeDefaults()
    {
        NativePkcs11ProviderOptions utimaco = NativePkcs11ProviderOptions.ForUtimaco();
        NativePkcs11ProviderOptions akis = NativePkcs11ProviderOptions.ForAkis();
        Assert.Equal(akis.RequiresSingleThreadedProviderAccess, utimaco.RequiresSingleThreadedProviderAccess);
        Assert.Equal(akis.MatchPrivateKeyByCkaIdFirst, utimaco.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(akis.AllowPublicKeyFallback, utimaco.AllowPublicKeyFallback);
        Assert.Equal(akis.ExcludeCertificatesWithoutSignableKey, utimaco.ExcludeCertificatesWithoutSignableKey);
    }
}
