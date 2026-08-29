using System.Text.RegularExpressions;

namespace ImzaKit.ASiC;

internal static partial class AsicPaths
{
    public const string MimeTypeEntry = "mimetype";
    public const string MetaInf = "META-INF";
    public const string ManifestFile = "ASiCManifest.xml";

    public static string ValidateDataName(string name, bool allowDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        string[] segments = Split(name);
        if (!allowDirectory && segments.Length != 1)
        {
            throw new InvalidOperationException("ASiC-S data objects must be a single root file.");
        }

        if (string.Equals(name.Replace('\\', '/'), MimeTypeEntry, StringComparison.OrdinalIgnoreCase)
            || string.Equals(segments[0], MetaInf, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("ASiC data object name collides with reserved container paths.");
        }

        return string.Join('/', segments);
    }

    public static string ValidateSignatureFileName(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (fileName.Contains('/') || fileName.Contains('\\'))
        {
            throw new InvalidOperationException("ASiC signature file names cannot contain a path.");
        }

        if (!SignatureFilePattern().IsMatch(fileName))
        {
            throw new InvalidOperationException(
                "ASiC signature file must match signature*.p7s or signatures*.xml.");
        }

        return fileName;
    }

    public static string ValidateZipEntryName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (name.Contains('\\', StringComparison.Ordinal) || name.Contains('\0'))
        {
            throw new InvalidDataException("ASiC ZIP entry path is not allowed.");
        }

        if (name.StartsWith('/') || name.Contains(':', StringComparison.Ordinal))
        {
            throw new InvalidDataException("ASiC ZIP entry path is not allowed.");
        }

        string[] segments = Split(name);
        return string.Join('/', segments);
    }

    public static bool IsMetaInf(string name) =>
        name.StartsWith(MetaInf + "/", StringComparison.OrdinalIgnoreCase);

    public static string MetaInfFile(string fileName) => MetaInf + "/" + fileName;

    private static string[] Split(string name)
    {
        string normalized = name.Replace('\\', '/');
        string[] parts = normalized.Split('/');
        if (parts.Length == 0)
        {
            throw new InvalidDataException("ASiC ZIP entry path is not allowed.");
        }

        foreach (string part in parts)
        {
            if (part.Length == 0 || part is "." or ".." || !SegmentPattern().IsMatch(part))
            {
                throw CreatePathError(name);
            }
        }

        return parts;
    }

    private static Exception CreatePathError(string name)
    {
        if (name.Contains("..", StringComparison.Ordinal) || name.Contains(':') || name.StartsWith('/') || name.Contains('\\'))
        {
            return new InvalidDataException("ASiC ZIP entry path is not allowed.");
        }

        return new InvalidOperationException("ASiC path is not allowed.");
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SegmentPattern();

    [GeneratedRegex(@"^(signature\d*\.p7s|signatures\d*\.xml)$", RegexOptions.CultureInvariant)]
    private static partial Regex SignatureFilePattern();
}
