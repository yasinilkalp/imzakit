param(
    [string]$ModulePath = $env:IMZAKIT_ETOKEN_MODULE
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    $default = Join-Path ${env:ProgramFiles} 'SafeNet\Authentication\SAC\x64\eTPKCS11.dll'
    if (Test-Path -LiteralPath $default) {
        $ModulePath = $default
    }
}

if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath)) {
    Write-Output 'ETOKEN_HARDWARE_SKIPPED: no PKCS#11 module. Set IMZAKIT_ETOKEN_MODULE to an allowlisted eTPKCS11.dll path.'
    exit 2
}

Write-Output "eToken module: $ModulePath"
Write-Output 'PIN is never accepted as a command-line argument. The Windows native PIN dialog must be used.'
Write-Output 'Physical token evidence is recorded in docs/evidence/etoken-hardware-checklist.md after a successful PAdES B-B round-trip.'
Write-Output "Repository: $repoRoot"
exit 0
