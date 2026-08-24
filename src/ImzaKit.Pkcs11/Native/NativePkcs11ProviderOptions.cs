using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;

namespace ImzaKit.Pkcs11.Native;

public sealed class NativePkcs11ProviderOptions
{
    public bool RequiresSingleThreadedProviderAccess { get; init; } = true;
    public bool MatchPrivateKeyByCkaIdFirst { get; init; } = true;
    public bool AllowPublicKeyFallback { get; init; } = true;
    public bool ExcludeCertificatesWithoutSignableKey { get; init; } = true;

    public static NativePkcs11ProviderOptions ForAkis() => new()
    {
        RequiresSingleThreadedProviderAccess = AkisProviderProfile.RequiresSingleThreadedProviderAccess,
        MatchPrivateKeyByCkaIdFirst = AkisProviderProfile.MatchPrivateKeyByCkaIdFirst,
        AllowPublicKeyFallback = true,
        ExcludeCertificatesWithoutSignableKey = true
    };

    public static NativePkcs11ProviderOptions ForEtoken() => new()
    {
        RequiresSingleThreadedProviderAccess = EtokenProviderProfile.RequiresSingleThreadedProviderAccess,
        MatchPrivateKeyByCkaIdFirst = EtokenProviderProfile.MatchPrivateKeyByCkaIdFirst,
        AllowPublicKeyFallback = true,
        ExcludeCertificatesWithoutSignableKey = true
    };
}
