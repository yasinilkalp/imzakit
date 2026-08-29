namespace ImzaKit.Pkcs11.Nshield;

public sealed record NshieldProviderProfile
{
    public static string Name => "nShield";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } =
        ["cknfast.dll", "libcknfast.so"];
    public static IReadOnlyList<string> RecommendedAllowlistRoots { get; } =
    [
        @"%ProgramFiles%\nCipher\nfast\bin",
        @"%ProgramFiles%\Entrust\nShield\nfast\bin",
        "/opt/nfast/toolkits/pkcs11"
    ];
}
