namespace ImzaKit.Pkcs11.Akis;

public sealed record AkisProviderProfile
{
    public static string Name => "AKİS";
    public static string SigningMechanism => "CKM_SHA256_RSA_PKCS";
    public static bool MatchPrivateKeyByCkaIdFirst => true;
    public static bool RequiresSingleThreadedProviderAccess => true;
    public static IReadOnlyList<string> SupportedLibraryFileNames { get; } = ["akisp11.dll", "libakisp11.so"];
}
