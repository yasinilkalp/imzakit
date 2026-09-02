using ImzaKit.Release.Signing;

namespace ImzaKit.Release.Tests.Signing;

public sealed class ReleaseArtifactKindParserTests
{
    [Theory]
    [InlineData(null, ReleaseArtifactKind.NugetPackage)]
    [InlineData("nuget", ReleaseArtifactKind.NugetPackage)]
    [InlineData("agent", ReleaseArtifactKind.AgentPeOrInstaller)]
    [InlineData("desktop", ReleaseArtifactKind.DesktopPeOrInstaller)]
    [InlineData("manifest", ReleaseArtifactKind.UpdateManifest)]
    public void ParsesKnownKinds(string? value, ReleaseArtifactKind expected)
    {
        Assert.Equal(expected, ReleaseArtifactKindParser.Parse(value));
    }

    [Fact]
    public void RejectsUnknownKind()
    {
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => ReleaseArtifactKindParser.Parse("msi"));
        Assert.Contains("Unknown --kind", ex.Message, StringComparison.Ordinal);
    }
}
