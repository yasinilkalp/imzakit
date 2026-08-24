[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$required = @(
    'LICENSE',
    'NOTICE',
    'CONTRIBUTING.md',
    'CODE_OF_CONDUCT.md',
    'SECURITY.md',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/feature_request.yml',
    '.github/ISSUE_TEMPLATE/config.yml'
)

foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $path) -PathType Leaf)) {
        throw "Required open-source file is missing: $path"
    }
}

$checks = [ordered]@{
    'CONTRIBUTING.md' = @('dotnet restore', 'dotnet test', 'pull request')
    'CODE_OF_CONDUCT.md' = @('Contributor Covenant', 'enforcement')
    'SECURITY.md' = @('1.0.0-alpha.6', 'Security advisory', 'public issue')
    '.github/ISSUE_TEMPLATE/bug_report.yml' = @('name:', 'description:', 'reproduction', 'environment')
    '.github/ISSUE_TEMPLATE/feature_request.yml' = @('name:', 'description:', 'use case', 'scope')
    '.github/ISSUE_TEMPLATE/config.yml' = @('blank_issues_enabled: false', 'Security advisory')
}

foreach ($entry in $checks.GetEnumerator()) {
    $text = Get-Content -LiteralPath (Join-Path $root $entry.Key) -Raw
    foreach ($pattern in $entry.Value) {
        if ($text.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "$($entry.Key) is missing required content: $pattern"
        }
    }
}

Write-Host 'Open-source readiness verification passed.' -ForegroundColor Green
