using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Hsm;
using ImzaKit.Pkcs11.Nshield;
using ImzaKit.Pkcs11.Utimaco;

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

    public static NativePkcs11ProviderOptions ForHsm() => new()
    {
        RequiresSingleThreadedProviderAccess = HsmProviderProfile.RequiresSingleThreadedProviderAccess,
        MatchPrivateKeyByCkaIdFirst = HsmProviderProfile.MatchPrivateKeyByCkaIdFirst,
        AllowPublicKeyFallback = true,
        ExcludeCertificatesWithoutSignableKey = true
    };

    public static NativePkcs11ProviderOptions ForNshield() => new()
    {
        RequiresSingleThreadedProviderAccess = NshieldProviderProfile.RequiresSingleThreadedProviderAccess,
        MatchPrivateKeyByCkaIdFirst = NshieldProviderProfile.MatchPrivateKeyByCkaIdFirst,
        AllowPublicKeyFallback = true,
        ExcludeCertificatesWithoutSignableKey = true
    };

    public static NativePkcs11ProviderOptions ForUtimaco() => new()
    {
        RequiresSingleThreadedProviderAccess = UtimacoProviderProfile.RequiresSingleThreadedProviderAccess,
        MatchPrivateKeyByCkaIdFirst = UtimacoProviderProfile.MatchPrivateKeyByCkaIdFirst,
        AllowPublicKeyFallback = true,
        ExcludeCertificatesWithoutSignableKey = true
    };
}
