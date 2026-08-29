namespace ImzaKit.Pkcs11.Hsm;

public sealed record HsmProviderProfile
{
    public static string Name => "HSM";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } =
        ["softhsm2-x64.dll", "softhsm2.dll", "libsofthsm2.so"];
    public static IReadOnlyList<string> RecommendedAllowlistRoots { get; } =
    [
        @"%ProgramFiles%\SoftHSM2",
        "/usr/lib/softhsm",
        "/usr/lib64/softhsm"
    ];
}
