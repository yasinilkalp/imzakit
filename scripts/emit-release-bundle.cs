#:project ../packaging/ImzaKit.Release/ImzaKit.Release.csproj

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ImzaKit.Release.Provenance;
using ImzaKit.Release.Sbom;
using ImzaKit.Release.Signing;

if (args.Contains("--compile-check", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("RELEASE_BUNDLE_COMPILE_OK");
    return 0;
}

string? package = ReadOption(args, "--package");
string? output = ReadOption(args, "--output");
string? version = ReadOption(args, "--version");
string? commit = ReadOption(args, "--commit");
string product = ReadOption(args, "--product") ?? "ImzaKit";
string builderId = ReadOption(args, "--builder-id")
    ?? "https://github.com/yasinilkalp/imzakit/.github/workflows/publish.yml";
ReleaseArtifactKind kind = ParseKind(ReadOption(args, "--kind"));

if (string.IsNullOrWhiteSpace(package) ||
    string.IsNullOrWhiteSpace(output) ||
    string.IsNullOrWhiteSpace(version) ||
    string.IsNullOrWhiteSpace(commit))
{
    Console.Error.WriteLine("Usage: --package <nupkg> --output <dir> --version <semver> --commit <sha>");
    return 2;
}

if (!File.Exists(package))
{
    Console.Error.WriteLine("Package is missing: " + package);
    return 3;
}

string? pfx = Environment.GetEnvironmentVariable("IMZAKIT_AUTHENTICODE_PFX");
string? ecdsa = Environment.GetEnvironmentVariable("IMZAKIT_RELEASE_ECDSA_KEY");
ReleaseSigningMaterials materials = new(
    AuthenticodeCertificatePresent: !string.IsNullOrWhiteSpace(pfx) && File.Exists(pfx),
    ReleaseEcdsaKeyPresent: !string.IsNullOrWhiteSpace(ecdsa));
try
{
    ReleaseSigningPolicy.AssertCanPublish(version, kind, materials);
}
catch (InvalidOperationException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}

ECDsa? releaseKey = null;
if (!string.IsNullOrWhiteSpace(ecdsa))
{
    releaseKey = ECDsa.Create();
    releaseKey.ImportPkcs8PrivateKey(Convert.FromBase64String(ecdsa.Trim()), out _);
}

try
{
    byte[] artifact = File.ReadAllBytes(package);
    ReleasePublishBundle bundle = ReleasePublishBundleFactory.Create(
        product,
        version,
        commit,
        artifact,
        RuntimeComponents(version),
        builderId,
        releaseKey);
    Directory.CreateDirectory(output);
    File.WriteAllText(Path.Combine(output, "sbom.cdx.json"), bundle.SbomJson);
    if (bundle.Provenance is not null)
    {
        File.WriteAllText(
            Path.Combine(output, "provenance.json"),
            WriteProvenanceJson(bundle.Provenance));
    }

    Console.WriteLine("RELEASE_BUNDLE_OK " + Path.Combine(output, "sbom.cdx.json"));
    return 0;
}
finally
{
    releaseKey?.Dispose();
}

static string? ReadOption(string[] arguments, string name)
{
    int index = Array.FindIndex(arguments, argument => string.Equals(argument, name, StringComparison.Ordinal));
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}

static ReleaseArtifactKind ParseKind(string? value) => value switch
{
    null or "nuget" => ReleaseArtifactKind.NugetPackage,
    "agent" => ReleaseArtifactKind.AgentPeOrInstaller,
    "manifest" => ReleaseArtifactKind.UpdateManifest,
    _ => throw new InvalidOperationException("Unknown --kind: " + value)
};

static string WriteProvenanceJson(ReleaseProvenance provenance)
{
    using MemoryStream stream = new();
    using (Utf8JsonWriter writer = new(stream))
    {
        writer.WriteStartObject();
        writer.WriteString("product", provenance.Product);
        writer.WriteString("version", provenance.Version);
        writer.WriteString("gitCommit", provenance.GitCommit);
        writer.WriteString("artifactSha256", provenance.ArtifactSha256);
        writer.WriteString("builderId", provenance.BuilderId);
        writer.WriteString("issuedAtUtc", provenance.IssuedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        writer.WriteString("signature", provenance.Signature);
        writer.WriteEndObject();
    }

    return Encoding.UTF8.GetString(stream.ToArray());
}

static SoftwareComponent[] RuntimeComponents(string version) =>
[
    new("ImzaKit", version, "Apache-2.0", "pkg:nuget/ImzaKit@" + version),
    new("BouncyCastle.Cryptography", "2.7.0", "MIT", "pkg:nuget/BouncyCastle.Cryptography@2.7.0"),
    new(
        "Microsoft.Extensions.DependencyInjection.Abstractions",
        "10.0.11",
        "MIT",
        "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@10.0.11"),
    new(
        "System.Security.Cryptography.Pkcs",
        "10.0.11",
        "MIT",
        "pkg:nuget/System.Security.Cryptography.Pkcs@10.0.11")
];
