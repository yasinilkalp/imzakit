param(
    [string]$WorkflowPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.github\workflows\publish.yml')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $WorkflowPath -PathType Leaf)) {
    throw "Publish workflow is missing: $WorkflowPath"
}

$workflow = Get-Content -LiteralPath $WorkflowPath -Raw
$requiredPatterns = [ordered]@{
    'tag trigger' = '(?m)^\s+tags:\s*\r?$'
    'manual trigger' = '(?m)^\s+workflow_dispatch:\s*\r?$'
    'version from tag' = 'IMZAKIT_VERSION'
    'Release build' = 'dotnet build ImzaKit\.slnx -c Release'
    'test suite' = 'dotnet test ImzaKit\.slnx -c Release --no-build'
    'single package build' = 'dotnet pack packaging/ImzaKit/ImzaKit\.csproj -c Release --no-build --output artifacts/packages'
    'release bundle emit' = 'scripts/emit-release-bundle\.cs'
    'desktop installer emit' = 'scripts/emit-desktop-installer\.cs'
    'desktop kind' = '--kind desktop'
    'sbom artifact' = 'artifacts/packages/sbom\.cdx\.json'
    'provenance key env' = 'IMZAKIT_RELEASE_ECDSA_KEY'
    'authenticode pfx secret' = 'secrets\.IMZAKIT_AUTHENTICODE_PFX'
    'authenticode password secret' = 'secrets\.IMZAKIT_AUTHENTICODE_PFX_PASSWORD'
    'windows desktop job' = 'windows-latest'
    'setup exe name' = 'ImzaKit\.Desktop-win-x64\.setup\.exe'
    'gh release' = 'gh release create'
    'package contract' = 'scripts/verify-nuget-package\.ps1'
    'OIDC permission' = '(?m)^\s+id-token:\s*write\s*$'
    'packages write permission' = '(?m)^\s+packages:\s+write\s*$'
    'contents write on publish' = '(?m)^\s+contents:\s+write\s*$'
    'NuGet OIDC login' = 'uses:\s*NuGet/login@v1'
    'NuGet profile' = '(?m)^\s+user:\s*Kodekibi\s*$'
    'temporary API key output' = 'steps\.login\.outputs\.NUGET_API_KEY'
    'GitHub Packages token' = 'secrets\.GITHUB_TOKEN'
    'GitHub Packages source' = 'nuget\.pkg\.github\.com'
    'package path from version' = 'ImzaKit\.\$\{\{ env\.IMZAKIT_VERSION \}\}\.nupkg'
    'NuGet.org source' = 'https://api\.nuget\.org/v3/index\.json'
    'needs desktop' = 'needs:\s*\[verify-pack, desktop\]'
    'wix 5.0.2 tool' = 'dotnet tool install --global wix --version 5\.0\.2'
    'wix 5 bootstrapper extension' = 'WixToolset\.BootstrapperApplications\.wixext/5\.0\.2'
    'bundle uses bootstrapper extension' = '-ext WixToolset\.BootstrapperApplications\.wixext'
    'bundle bindpath finds msi' = '-bindpath artifacts/desktop'
    'signtool from Windows Kits' = 'Windows Kits\\10\\bin'
}

if ($workflow -match 'WixToolset\.Bal\.wixext') {
    throw 'Publish workflow must pin WixToolset.BootstrapperApplications.wixext/5.0.2; Bal.wixext is an alias that installs WiX 7 on unversioned add.'
}

if ($workflow -match '(?m)& signtool ') {
    throw 'Publish workflow must resolve signtool.exe from Windows Kits; it is not on PATH on windows-latest.'
}

foreach ($requirement in $requiredPatterns.GetEnumerator()) {
    if ($workflow -notmatch $requirement.Value) {
        throw "Publish workflow requirement is missing: $($requirement.Key)"
    }
}

if ($workflow -match 'secrets\.NUGET_API_KEY') {
    throw 'Publish workflow must not depend on a long-lived NuGet API key secret.'
}

if ($workflow -match '--skip-duplicate') {
    throw 'Publish workflow must fail when the package version already exists.'
}

if ($workflow -match '(?i)(api[_-]?key|nuget[_-]?key)\s*:\s*[''\"][^$]') {
    throw 'Publish workflow appears to contain a literal API key.'
}

if ($workflow -match 'ImzaKit\.1\.0\.0-alpha\.13\.nupkg') {
    throw 'Publish workflow must not hardcode 1.0.0-alpha.13 package paths.'
}

Write-Output 'Publish workflow verification passed.'
