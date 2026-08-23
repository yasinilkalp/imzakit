[CmdletBinding()]
param([string]$WorkflowPath = (Join-Path $PSScriptRoot '..\.github\workflows\pages.yml'))

$ErrorActionPreference = 'Stop'
$resolvedWorkflowPath = [System.IO.Path]::GetFullPath($WorkflowPath)
if (-not (Test-Path -LiteralPath $resolvedWorkflowPath -PathType Leaf)) {
    throw "Pages workflow is missing: $resolvedWorkflowPath"
}

$workflow = Get-Content -LiteralPath $resolvedWorkflowPath -Raw
$required = @(
    'branches: [main]',
    'workflow_dispatch:',
    'contents: read',
    'pages: write',
    'id-token: write',
    'concurrency:',
    'actions/configure-pages@v5',
    'actions/upload-pages-artifact@v3',
    'path: site',
    'actions/deploy-pages@v4',
    'environment:',
    'name: github-pages',
    'scripts/verify-landing-page.ps1',
    'scripts/verify-open-source-readiness.ps1'
)
foreach ($pattern in $required) {
    if ($workflow.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Pages workflow is missing required content: $pattern"
    }
}

$forbidden = [ordered]@{
    'pull_request_target trigger' = 'pull_request_target'
    'secret reference' = 'secrets\.'
    'write-all permission' = 'write-all'
    'package installation' = '(npm|pnpm|yarn|apt-get|choco)\s+(install|add)'
    'arbitrary download' = '(curl|wget|Invoke-WebRequest)\s+'
}
foreach ($entry in $forbidden.GetEnumerator()) {
    if ($workflow -match $entry.Value) {
        throw "Pages workflow contains forbidden $($entry.Key)."
    }
}

Write-Host 'Pages workflow verification passed.' -ForegroundColor Green
