param(
    [string]$ModulePath = $env:IMZAKIT_AKIS_MODULE
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    $default = Join-Path ${env:ProgramFiles} 'AKIS\akisp11.dll'
    if (Test-Path -LiteralPath $default) {
        $ModulePath = $default
    }
}

if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath)) {
    Write-Output 'AKIS_HARDWARE_SKIPPED: no PKCS#11 module. Set IMZAKIT_AKIS_MODULE to an allowlisted akisp11.dll path.'
    exit 2
}

Write-Output "AKIS module: $ModulePath"
Write-Output 'PIN is never accepted as a command-line argument. The Windows native PIN dialog must be used.'
Write-Output 'Physical card evidence is recorded in docs/evidence/akis-hardware-checklist.md after a successful PAdES B-B round-trip.'
Write-Output "Repository: $repoRoot"
exit 0
