using ImzaKit.Release.Signing;

namespace ImzaKit.Release.Tests.Signing;

public sealed class ReleaseArtifactKindParserTests
{
    [Theory]
    [InlineData(null, ReleaseArtifactKind.NugetPackage)]
    [InlineData("nuget", ReleaseArtifactKind.NugetPackage)]
    [InlineData("agent", ReleaseArtifactKind.AgentPeOrInstaller)]
    [InlineData("manifest", ReleaseArtifactKind.UpdateManifest)]
    public void ParsesKnownKinds(string? value, ReleaseArtifactKind expected)
    {
        Assert.Equal(expected, ReleaseArtifactKindParser.Parse(value));
    }

    [Fact]
    public void RejectsUnknownKind()
    {
        InvalidOperationException unknown = Assert.Throws<InvalidOperationException>(
            () => ReleaseArtifactKindParser.Parse("msi"));
        InvalidOperationException desktop = Assert.Throws<InvalidOperationException>(
            () => ReleaseArtifactKindParser.Parse("desktop"));
        Assert.Contains("Unknown --kind", unknown.Message, StringComparison.Ordinal);
        Assert.Contains("Unknown --kind", desktop.Message, StringComparison.Ordinal);
    }
}
