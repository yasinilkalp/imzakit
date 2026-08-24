using ImzaKit.Release.Licensing;
using ImzaKit.Release.Sbom;

namespace ImzaKit.Release.Tests.Sbom;

public sealed class LicenseAllowListAndSbomTests
{
    [Theory]
    [InlineData("Apache-2.0", LicenseDecision.Allowed)]
    [InlineData("MIT", LicenseDecision.Allowed)]
    [InlineData("BSD-2-Clause", LicenseDecision.Allowed)]
    [InlineData("BSD-3-Clause", LicenseDecision.Allowed)]
    [InlineData("ISC", LicenseDecision.Allowed)]
    [InlineData("GPL-3.0", LicenseDecision.Denied)]
    [InlineData("AGPL-3.0", LicenseDecision.Denied)]
    [InlineData("SSPL-1.0", LicenseDecision.Denied)]
    [InlineData("LGPL-2.1", LicenseDecision.ReviewRequired)]
    [InlineData("MPL-2.0", LicenseDecision.ReviewRequired)]
    public void LicenseAllowListMatchesAdr001(string spdx, LicenseDecision expected)
    {
        Assert.Equal(expected, LicenseAllowList.Evaluate(spdx));
    }

    [Fact]
    public void RuntimeSbomRejectsDeniedLicensesAndOmitsTestOnlyPackages()
    {
        SoftwareComponent[] components =
        [
            new("ImzaKit", "1.0.0-alpha.4", "Apache-2.0", "pkg:nuget/ImzaKit@1.0.0-alpha.4"),
            new("BouncyCastle.Cryptography", "2.7.0", "MIT", "pkg:nuget/BouncyCastle.Cryptography@2.7.0"),
            new("PdfPig", "0.1.15", "Apache-2.0", "pkg:nuget/PdfPig@0.1.15", SoftwareComponentScope.Test)
        ];

        CycloneDxSbom sbom = CycloneDxSbomGenerator.Create("ImzaKit", "1.0.0-alpha.4", components);
        string json = CycloneDxSbomGenerator.Serialize(sbom);

        Assert.Equal("CycloneDX", sbom.BomFormat);
        Assert.Equal("1.6", sbom.SpecVersion);
        Assert.DoesNotContain("PdfPig", json, StringComparison.Ordinal);
        Assert.Contains("BouncyCastle.Cryptography", json, StringComparison.Ordinal);
        Assert.Contains("Apache-2.0", json, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() =>
            CycloneDxSbomGenerator.Create("ImzaKit", "1.0.0-alpha.4",
            [
                new("evil", "1.0.0", "GPL-3.0", "pkg:nuget/evil@1.0.0")
            ]));
    }
}
