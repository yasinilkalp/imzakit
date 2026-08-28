using System.Text;
using System.Text.Json;
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
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("bomFormat", sbom.BomFormat);
            writer.WriteString("specVersion", sbom.SpecVersion);
            writer.WriteString("serialNumber", sbom.SerialNumber);
            writer.WriteNumber("version", 1);
            writer.WritePropertyName("metadata");
            writer.WriteStartObject();
            writer.WritePropertyName("component");
            writer.WriteStartObject();
            writer.WriteString("name", sbom.Name);
            writer.WriteString("version", sbom.Version);
            WriteLicenseArray(writer, "Apache-2.0");
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WritePropertyName("components");
            writer.WriteStartArray();
            foreach (SoftwareComponent component in sbom.Components)
            {
                writer.WriteStartObject();
                writer.WriteString("name", component.Name);
                writer.WriteString("version", component.Version);
                writer.WriteString("purl", component.PackageUrl);
                WriteLicenseArray(writer, component.License);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteLicenseArray(Utf8JsonWriter writer, string spdx)
    {
        writer.WritePropertyName("licenses");
        writer.WriteStartArray();
        writer.WriteStartObject();
        writer.WritePropertyName("license");
        writer.WriteStartObject();
        writer.WriteString("id", spdx);
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteEndArray();
    }
}
