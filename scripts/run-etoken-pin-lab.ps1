param(
    [string]$ModulePath = $env:IMZAKIT_ETOKEN_MODULE
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding
$repoRoot = Split-Path -Parent $PSScriptRoot

$labCandidates = @(
    (Join-Path ${env:ProgramFiles} 'SafeNet\Authentication\SAC\x64\eTPKCS11.dll'),
    (Join-Path ${env:ProgramFiles} 'Thales\SafeNet Authentication Client\eTPKCS11.dll'),
    (Join-Path $env:WINDIR 'System32\eTPKCS11.dll')
)

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    foreach ($candidate in $labCandidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            $ModulePath = $candidate
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath)) {
    Write-Output 'ETOKEN_PIN_LAB_SKIPPED: no eTPKCS11.dll. Set IMZAKIT_ETOKEN_MODULE.'
    exit 2
}

$resolved = [System.IO.Path]::GetFullPath($ModulePath)
$fileName = [System.IO.Path]::GetFileName($resolved)
if (-not [string]::Equals($fileName, 'eTPKCS11.dll', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Output "ETOKEN_PIN_LAB_REJECTED: module file name must be eTPKCS11.dll (got '$fileName')."
    exit 1
}

Write-Output '=== eToken CredUI PIN lab ==='
Write-Output "Module: $resolved"
Write-Output 'PIN is never accepted as a command-line argument or environment variable.'
Write-Output 'A Windows dialog will open. Do not type the PIN in this terminal.'
Write-Output 'After a successful sign, a second dialog asks for an incorrect PIN (Cancel to skip).'

$env:IMZAKIT_ETOKEN_MODULE = $resolved
$lab = Join-Path $repoRoot 'scripts\etoken-pin-lab.cs'
dotnet run --file $lab
exit $LASTEXITCODE
