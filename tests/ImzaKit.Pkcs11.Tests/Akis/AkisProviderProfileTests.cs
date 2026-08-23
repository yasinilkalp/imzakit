using ImzaKit.Pkcs11.Akis;

namespace ImzaKit.Pkcs11.Tests.Akis;

public sealed class AkisProviderProfileTests
{
    [Fact]
    public void CapturesVerifiedFirstProviderQuirks()
    {
        Assert.Equal("AKİS", AkisProviderProfile.Name);
        Assert.Equal("CKM_SHA256_RSA_PKCS", AkisProviderProfile.SigningMechanism);
        Assert.True(AkisProviderProfile.MatchPrivateKeyByCkaIdFirst);
        Assert.True(AkisProviderProfile.RequiresSingleThreadedProviderAccess);
        Assert.Contains("akisp11.dll", AkisProviderProfile.SupportedLibraryFileNames);
        Assert.Contains("libakisp11.so", AkisProviderProfile.SupportedLibraryFileNames);
    }
}
