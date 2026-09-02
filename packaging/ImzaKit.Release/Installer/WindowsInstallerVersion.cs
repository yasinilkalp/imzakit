using System.Globalization;
using System.Text.RegularExpressions;

namespace ImzaKit.Release.Installer;

public static class WindowsInstallerVersion
{
    private static readonly Regex SemVer = new(
        @"^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<label>[A-Za-z]+)\.(?<prerelease>\d+))?$",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture);

    public static string FromSemVer(string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        Match match = SemVer.Match(version);
        if (!match.Success)
        {
            throw new ArgumentException("Unsupported installer version.", nameof(version));
        }

        string major = match.Groups["major"].Value;
        string minor = match.Groups["minor"].Value;
        string build = match.Groups["prerelease"].Success
            ? match.Groups["prerelease"].Value
            : match.Groups["patch"].Value;
        return string.Create(CultureInfo.InvariantCulture, $"{major}.{minor}.{build}");
    }
}
