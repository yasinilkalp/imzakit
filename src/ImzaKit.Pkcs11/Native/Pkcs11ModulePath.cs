namespace ImzaKit.Pkcs11.Native;

public static class Pkcs11ModulePath
{
    public static string ResolveAllowed(
        string path,
        IReadOnlyList<string> allowedDirectoryRoots,
        IReadOnlyList<string> allowedFileNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(allowedDirectoryRoots);
        ArgumentNullException.ThrowIfNull(allowedFileNames);

        if (!Path.IsPathFullyQualified(path))
        {
            throw new ArgumentException("PKCS#11 module path must be an absolute path.", nameof(path));
        }

        string fullPath = Path.GetFullPath(path);
        string fileName = Path.GetFileName(fullPath);
        if (!allowedFileNames.Any(name => string.Equals(name, fileName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("PKCS#11 module file name is not allowed.", nameof(path));
        }

        if (!allowedDirectoryRoots.Any(root => IsUnderRoot(fullPath, root)))
        {
            throw new ArgumentException("PKCS#11 module path is outside the allowlist.", nameof(path));
        }

        return fullPath;
    }

    private static bool IsUnderRoot(string fullPath, string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        string fullRoot = Path.GetFullPath(root);
        string prefix = fullRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}
