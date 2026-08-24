using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Etoken;

public sealed class EtokenProviderProfileTests
{
    [Fact]
    public void CapturesSecondVerifiedWindowsProviderContract()
    {
        Assert.Equal("eToken", EtokenProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", EtokenProviderProfile.SigningMechanism);
        Assert.True(EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(EtokenProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst, EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(AkisProviderProfile.RequiresSingleThreadedProviderAccess, EtokenProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(["eTPKCS11.dll"], EtokenProviderProfile.SupportedLibraryFileNames);
        Assert.DoesNotContain("eToken.dll", EtokenProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"%ProgramFiles%\SafeNet\Authentication\SAC\x64", EtokenProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains(@"%ProgramFiles%\Thales\SafeNet Authentication Client", EtokenProviderProfile.RecommendedAllowlistRoots);
        Assert.DoesNotContain(EtokenProviderProfile.RecommendedAllowlistRoots, root =>
            root.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForEtokenMatchesAkisSafeDefaults()
    {
        NativePkcs11ProviderOptions etoken = NativePkcs11ProviderOptions.ForEtoken();
        NativePkcs11ProviderOptions akis = NativePkcs11ProviderOptions.ForAkis();
        Assert.Equal(akis.RequiresSingleThreadedProviderAccess, etoken.RequiresSingleThreadedProviderAccess);
        Assert.Equal(akis.MatchPrivateKeyByCkaIdFirst, etoken.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(akis.AllowPublicKeyFallback, etoken.AllowPublicKeyFallback);
        Assert.Equal(akis.ExcludeCertificatesWithoutSignableKey, etoken.ExcludeCertificatesWithoutSignableKey);
    }
}
