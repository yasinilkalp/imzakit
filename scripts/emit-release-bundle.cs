#:project ../packaging/ImzaKit.Release/ImzaKit.Release.csproj

using System.Security.Cryptography;
using System.Text;
using ImzaKit.Release.Installer;
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
ReleaseArtifactKind kind = ReleaseArtifactKindParser.Parse(ReadOption(args, "--kind"));

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

if (kind is ReleaseArtifactKind.AgentPeOrInstaller)
{
    try
    {
        AuthenticodeGate.RequireFile(package, required: true);
    }
    catch (InvalidOperationException exception)
    {
        Console.Error.WriteLine(exception.Message);
        return 1;
    }
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
    File.WriteAllBytes(Path.Combine(output, "sbom.cdx.json"), Encoding.UTF8.GetBytes(bundle.SbomJson));
    if (bundle.Provenance is not null)
    {
        File.WriteAllText(
            Path.Combine(output, "provenance.json"),
            ReleaseProvenanceJson.Write(bundle.Provenance));
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

static SoftwareComponent[] RuntimeComponents(string version) =>
[
    new("ImzaKit", version, "Apache-2.0", "pkg:nuget/ImzaKit@" + version),
    new("BouncyCastle.Cryptography", "2.7.0", "MIT", "pkg:nuget/BouncyCastle.Cryptography@2.7.0"),
    new(
        "Microsoft.Extensions.DependencyInjection.Abstractions",
        "10.0.14",
        "MIT",
        "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@10.0.14"),
    new(
        "System.Security.Cryptography.Pkcs",
        "10.0.14",
        "MIT",
        "pkg:nuget/System.Security.Cryptography.Pkcs@10.0.14"),
    new(
        "System.Security.Cryptography.Xml",
        "10.0.14",
        "MIT",
        "pkg:nuget/System.Security.Cryptography.Xml@10.0.14")
];
