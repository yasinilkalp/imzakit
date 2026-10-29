#:project ../packaging/ImzaKit.Release/ImzaKit.Release.csproj

using System.Security.Cryptography;
using ImzaKit.Release.Provenance;

string? package = ReadOption(args, "--package");
string? sbom = ReadOption(args, "--sbom");
string? provenancePath = ReadOption(args, "--provenance");
string? publicKey = ReadOption(args, "--public-key");
string? commit = ReadOption(args, "--commit");
string? version = ReadOption(args, "--version");

if (string.IsNullOrWhiteSpace(package) ||
    string.IsNullOrWhiteSpace(sbom) ||
    string.IsNullOrWhiteSpace(provenancePath) ||
    string.IsNullOrWhiteSpace(publicKey))
{
    Console.Error.WriteLine(
        "Usage: --package <nupkg> --sbom <sbom.cdx.json> --provenance <provenance.json> --public-key <pem> [--commit <sha>] [--version <semver>]");
    return 2;
}

foreach (string path in new[] { package, sbom, provenancePath, publicKey })
{
    if (!File.Exists(path))
    {
        Console.Error.WriteLine("File is missing: " + path);
        return 3;
    }
}

ReleaseProvenance provenance;
try
{
    provenance = ReleaseProvenanceJson.Read(File.ReadAllText(provenancePath));
}
catch (InvalidDataException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}

using ECDsa releasePublicKey = ECDsa.Create();
releasePublicKey.ImportFromPem(File.ReadAllText(publicKey));
if (!ReleaseProvenanceFactory.Verify(
    provenance,
    releasePublicKey,
    SHA256.HashData(File.ReadAllBytes(package)),
    SHA256.HashData(File.ReadAllBytes(sbom))))
{
    Console.Error.WriteLine("IMZAKIT.RELEASE.PROVENANCE_INVALID");
    return 1;
}

if (commit is not null && !string.Equals(provenance.GitCommit, commit, StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("IMZAKIT.RELEASE.PROVENANCE_COMMIT_MISMATCH");
    return 1;
}

if (version is not null && !string.Equals(provenance.Version, version, StringComparison.Ordinal))
{
    Console.Error.WriteLine("IMZAKIT.RELEASE.PROVENANCE_VERSION_MISMATCH");
    return 1;
}

Console.WriteLine($"PROVENANCE_OK {provenance.Product} {provenance.Version} {provenance.GitCommit}");
return 0;

static string? ReadOption(string[] arguments, string name)
{
    int index = Array.FindIndex(arguments, argument => string.Equals(argument, name, StringComparison.Ordinal));
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}
