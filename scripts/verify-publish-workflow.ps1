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
    'Release build' = 'dotnet build ImzaKit\.slnx -c Release'
    'test suite' = 'dotnet test ImzaKit\.slnx -c Release --no-build'
    'single package build' = 'dotnet pack packaging/ImzaKit/ImzaKit\.csproj -c Release --no-build --output artifacts/packages'
    'package contract' = 'scripts/verify-nuget-package\.ps1'
    'OIDC permission' = '(?m)^\s+id-token:\s*write\s*$'
    'NuGet OIDC login' = 'uses:\s*NuGet/login@v1'
    'NuGet profile' = '(?m)^\s+user:\s*Kodekibi\s*$'
    'temporary API key output' = 'steps\.login\.outputs\.NUGET_API_KEY'
    'alpha.6 package path' = 'artifacts/packages/ImzaKit\.1\.0\.0-alpha\.6\.nupkg'
    'NuGet.org source' = 'https://api\.nuget\.org/v3/index\.json'
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

Write-Output 'Publish workflow verification passed.'
