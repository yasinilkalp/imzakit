using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Hsm;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Hsm;

public sealed class HsmProviderProfileTests
{
    [Fact]
    public void CapturesFirstHsmPkcs11ProviderContract()
    {
        Assert.Equal("HSM", HsmProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", HsmProviderProfile.SigningMechanism);
        Assert.True(HsmProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(HsmProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst, HsmProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(AkisProviderProfile.RequiresSingleThreadedProviderAccess, HsmProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Equal(["softhsm2-x64.dll", "softhsm2.dll", "libsofthsm2.so"], HsmProviderProfile.SupportedLibraryFileNames);
        Assert.DoesNotContain("cryptoki.dll", HsmProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("eTPKCS11.dll", HsmProviderProfile.SupportedLibraryFileNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"%ProgramFiles%\SoftHSM2", HsmProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains("/usr/lib/softhsm", HsmProviderProfile.RecommendedAllowlistRoots);
        Assert.Contains("/usr/lib64/softhsm", HsmProviderProfile.RecommendedAllowlistRoots);
        Assert.DoesNotContain(HsmProviderProfile.RecommendedAllowlistRoots, root =>
            root.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForHsmMatchesAkisSafeDefaults()
    {
        NativePkcs11ProviderOptions hsm = NativePkcs11ProviderOptions.ForHsm();
        NativePkcs11ProviderOptions akis = NativePkcs11ProviderOptions.ForAkis();
        Assert.Equal(akis.RequiresSingleThreadedProviderAccess, hsm.RequiresSingleThreadedProviderAccess);
        Assert.Equal(akis.MatchPrivateKeyByCkaIdFirst, hsm.MatchPrivateKeyByCkaIdFirst);
        Assert.Equal(akis.AllowPublicKeyFallback, hsm.AllowPublicKeyFallback);
        Assert.Equal(akis.ExcludeCertificatesWithoutSignableKey, hsm.ExcludeCertificatesWithoutSignableKey);
    }
}
