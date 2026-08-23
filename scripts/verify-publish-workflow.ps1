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
    'NuGet secret' = 'secrets\.NUGET_API_KEY'
    'NuGet.org source' = 'https://api\.nuget\.org/v3/index\.json'
    'duplicate protection' = '--skip-duplicate'
}

foreach ($requirement in $requiredPatterns.GetEnumerator()) {
    if ($workflow -notmatch $requirement.Value) {
        throw "Publish workflow requirement is missing: $($requirement.Key)"
    }
}

if ($workflow -match '(?i)(api[_-]?key|nuget[_-]?key)\s*:\s*[''\"][^$]') {
    throw 'Publish workflow appears to contain a literal API key.'
}

Write-Output 'Publish workflow verification passed.'
