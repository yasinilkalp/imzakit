using ImzaKit.Release.Licensing;

namespace ImzaKit.Release.Sbom;

public enum SoftwareComponentScope
{
    Runtime,
    Test
}

public sealed record SoftwareComponent(
    string Name,
    string Version,
    string License,
    string PackageUrl,
    SoftwareComponentScope Scope = SoftwareComponentScope.Runtime);

public sealed record CycloneDxSbom(
    string BomFormat,
    string SpecVersion,
    string SerialNumber,
    string Name,
    string Version,
    IReadOnlyList<SoftwareComponent> Components);

public static class CycloneDxSbomGenerator
{
    public static CycloneDxSbom Create(string name, string version, IEnumerable<SoftwareComponent> components)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentNullException.ThrowIfNull(components);
        SoftwareComponent[] runtime = [.. components.Where(component => component.Scope == SoftwareComponentScope.Runtime)];
        if (runtime.Length == 0)
        {
            throw new InvalidOperationException("Runtime SBOM cannot be empty.");
        }

        foreach (SoftwareComponent component in runtime)
        {
            if (LicenseAllowList.Evaluate(component.License) != LicenseDecision.Allowed)
            {
                throw new InvalidOperationException($"License {component.License} is not allowed for {component.Name}.");
            }
        }

        return new CycloneDxSbom(
            "CycloneDX",
            "1.6",
            "urn:uuid:" + Guid.NewGuid().ToString("D"),
            name,
            version,
            runtime);
    }

    public static string Serialize(CycloneDxSbom sbom)
    {
        ArgumentNullException.ThrowIfNull(sbom);
        var payload = new
        {
            bomFormat = sbom.BomFormat,
            specVersion = sbom.SpecVersion,
            serialNumber = sbom.SerialNumber,
            version = 1,
            metadata = new { component = new { name = sbom.Name, version = sbom.Version, licenses = new[] { new { license = new { id = "Apache-2.0" } } } } },
            components = sbom.Components.Select(component => new
            {
                name = component.Name,
                version = component.Version,
                purl = component.PackageUrl,
                licenses = new[] { new { license = new { id = component.License } } }
            })
        };
        return System.Text.Json.JsonSerializer.Serialize(payload);
    }
}
