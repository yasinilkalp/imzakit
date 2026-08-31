using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;

namespace ImzaKit.Hosts.Desktop.Pkcs11;

public static class DesktopPkcs11ModuleLocator
{
    public static IReadOnlyList<string> DefaultAkisRoots { get; } =
        [Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\AKIS")];

    public static IReadOnlyList<string> DefaultEtokenRoots { get; } =
        EtokenProviderProfile.RecommendedAllowlistRoots
            .Select(Environment.ExpandEnvironmentVariables)
            .ToArray();

    public static IReadOnlyList<string> FindExistingModules(
        IReadOnlyList<string> akisRoots,
        IReadOnlyList<string> etokenRoots)
    {
        ArgumentNullException.ThrowIfNull(akisRoots);
        ArgumentNullException.ThrowIfNull(etokenRoots);
        List<string> paths = [];
        AddExisting(paths, akisRoots, AkisProviderProfile.SupportedLibraryFileNames);
        AddExisting(paths, etokenRoots, EtokenProviderProfile.SupportedLibraryFileNames);
        return paths;
    }

    private static void AddExisting(
        List<string> paths,
        IReadOnlyList<string> roots,
        IReadOnlyList<string> fileNames)
    {
        foreach (string root in roots)
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            foreach (string fileName in fileNames)
            {
                string candidate = Path.GetFullPath(Path.Combine(root, fileName));
                if (File.Exists(candidate) && !paths.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                {
                    paths.Add(candidate);
                }
            }
        }
    }
}
