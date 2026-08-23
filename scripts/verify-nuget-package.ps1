param(
    [string]$PackageDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\packages'),
    [string]$Version = '1.0.0-alpha.1'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$expectedModules = @(
    'ImzaKit.Agent', 'ImzaKit.Api', 'ImzaKit.Cms', 'ImzaKit.Core',
    'ImzaKit.Cryptography', 'ImzaKit.DependencyInjection', 'ImzaKit.PAdES',
    'ImzaKit.Pkcs11', 'ImzaKit.Verify'
)
$expectedDependencies = [ordered]@{
    'BouncyCastle.Cryptography' = '2.7.0'
    'Microsoft.Extensions.DependencyInjection.Abstractions' = '10.0.11'
    'System.Security.Cryptography.Pkcs' = '10.0.11'
}

$packages = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter '*.nupkg' |
    Where-Object { $_.Extension -eq '.nupkg' })
$symbols = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter '*.snupkg')
if ($packages.Count -ne 1) { throw "Expected one nupkg, found $($packages.Count)." }
if ($symbols.Count -ne 1) { throw "Expected one snupkg, found $($symbols.Count)." }

function Read-Nuspec([System.IO.Compression.ZipArchive]$archive) {
    $entry = $archive.Entries | Where-Object FullName -Like '*.nuspec' | Select-Object -First 1
    if (-not $entry) { throw 'Package nuspec is missing.' }
    $reader = [System.IO.StreamReader]::new($entry.Open())
    try { return [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
}

$packageArchive = [System.IO.Compression.ZipFile]::OpenRead($packages[0].FullName)
try {
    $nuspec = Read-Nuspec $packageArchive
    $metadata = $nuspec.package.metadata
    if ($metadata.id -ne 'ImzaKit') { throw "Unexpected package ID: $($metadata.id)" }
    if ($metadata.version -ne $Version) { throw "Unexpected version: $($metadata.version)" }
    if ($metadata.license.'#text' -ne 'Apache-2.0') { throw 'Apache-2.0 license is missing.' }
    if ($metadata.repository.url -ne 'https://github.com/yasinilkalp/imzakit') { throw 'Repository URL is invalid.' }
    if ($metadata.readme -ne 'README.md' -or -not ($packageArchive.Entries.FullName -contains 'README.md')) { throw 'README is missing.' }

    $actualDlls = @($packageArchive.Entries.FullName |
        Where-Object { $_ -like 'lib/net10.0/ImzaKit.*.dll' } |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) } |
        Sort-Object -Unique)
    $expectedDlls = @($expectedModules | Sort-Object)
    if (Compare-Object $expectedDlls $actualDlls) { throw "Module DLL set is invalid: $($actualDlls -join ', ')" }

    $dependencies = @($metadata.dependencies.group.dependency)
    if ($dependencies | Where-Object { $_.id -like 'ImzaKit.*' }) { throw 'Internal ImzaKit package dependency found.' }
    foreach ($pair in $expectedDependencies.GetEnumerator()) {
        $dependency = $dependencies | Where-Object id -EQ $pair.Key
        if (@($dependency).Count -ne 1 -or $dependency.version -ne $pair.Value) {
            throw "Dependency mismatch: $($pair.Key) $($dependency.version)"
        }
    }
    if ($dependencies.Count -ne $expectedDependencies.Count) { throw "Unexpected dependency count: $($dependencies.Count)" }
} finally { $packageArchive.Dispose() }

$symbolArchive = [System.IO.Compression.ZipFile]::OpenRead($symbols[0].FullName)
try {
    $actualPdbs = @($symbolArchive.Entries.FullName |
        Where-Object { $_ -like 'lib/net10.0/ImzaKit.*.pdb' } |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) } |
        Sort-Object -Unique)
    $expectedPdbs = @($expectedModules | Sort-Object)
    if (Compare-Object $expectedPdbs $actualPdbs) { throw "Module PDB set is invalid: $($actualPdbs -join ', ')" }
} finally { $symbolArchive.Dispose() }

Write-Output "NuGet package verification passed: ImzaKit $Version"
