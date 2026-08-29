namespace ImzaKit.Pkcs11.Utimaco;

public sealed record UtimacoProviderProfile
{
    public static string Name => "Utimaco";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } =
        ["cs_pkcs11_R2.dll", "cs_pkcs11_R3.dll", "libcs_pkcs11_R2.so", "libcs_pkcs11_R3.so"];
    public static IReadOnlyList<string> RecommendedAllowlistRoots { get; } =
    [
        @"%ProgramFiles%\Utimaco\CryptoServer\Lib",
        "/opt/utimaco/pkcs11"
    ];
}
