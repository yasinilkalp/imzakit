using ImzaKit.Release.Installer;

namespace ImzaKit.Release.Tests.Installer;

public sealed class WindowsInstallerVersionTests
{
    [Theory]
    [InlineData("1.0.0-alpha.14", "1.0.14")]
    [InlineData("1.0.0-alpha.13", "1.0.13")]
    [InlineData("1.0.0", "1.0.0")]
    [InlineData("2.0.0-beta.1", "2.0.1")]
    public void MapsSemVerToMajorMinorBuild(string semver, string expected)
    {
        Assert.Equal(expected, WindowsInstallerVersion.FromSemVer(version: semver));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.0")]
    [InlineData("1.0.0-alpha")]
    [InlineData("1.0.0.1")]
    public void RejectsUnsupportedVersions(string version)
    {
        Assert.Throws<ArgumentException>(() => WindowsInstallerVersion.FromSemVer(version));
    }
}
