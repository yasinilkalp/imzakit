namespace ImzaKit.Pkcs11.Etoken;

public sealed record EtokenProviderProfile
{
    public static string Name => "eToken";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } = ["eTPKCS11.dll"];
    public static IReadOnlyList<string> RecommendedAllowlistRoots { get; } =
    [
        @"%ProgramFiles%\SafeNet\Authentication\SAC\x64",
        @"%ProgramFiles%\Thales\SafeNet Authentication Client"
    ];
}
