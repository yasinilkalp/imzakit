param(
    [string]$ModulePath = $env:IMZAKIT_ETOKEN_MODULE
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding
$repoRoot = Split-Path -Parent $PSScriptRoot

$agentDefaultRoots = @(
    (Join-Path ${env:ProgramFiles} 'SafeNet\Authentication\SAC\x64'),
    (Join-Path ${env:ProgramFiles} 'Thales\SafeNet Authentication Client')
)
$labCandidates = @(
    (Join-Path $agentDefaultRoots[0] 'eTPKCS11.dll'),
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
    Write-Output 'ETOKEN_HARDWARE_SKIPPED: no PKCS#11 module. Install SafeNet Authentication Client or set IMZAKIT_ETOKEN_MODULE to an eTPKCS11.dll path.'
    Write-Output 'PIN is never accepted as a command-line argument or environment variable.'
    Write-Output 'Record evidence in docs/evidence/etoken-hardware-checklist.md after a physical lab run.'
    exit 2
}

$resolved = [System.IO.Path]::GetFullPath($ModulePath)
$fileName = [System.IO.Path]::GetFileName($resolved)
if (-not [string]::Equals($fileName, 'eTPKCS11.dll', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Output "ETOKEN_HARDWARE_REJECTED: module file name must be eTPKCS11.dll (got '$fileName')."
    exit 1
}

$os = [System.Environment]::OSVersion.VersionString
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($resolved)
$hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
$commit = ''
Push-Location $repoRoot
try {
    $commit = (git rev-parse --short HEAD 2>$null)
} finally {
    Pop-Location
}

Write-Output '=== eToken hardware lab environment ==='
Write-Output "Repository: $repoRoot"
Write-Output "Commit: $commit"
Write-Output "OS: $os"
Write-Output "Architecture: $arch"
Write-Output "Module: $resolved"
$underAgentRoot = $false
foreach ($root in $agentDefaultRoots) {
    $prefix = [System.IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if ($resolved.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $underAgentRoot = $true
        break
    }
}
if (-not $underAgentRoot) {
    Write-Output "AllowlistNote: path is outside Agent default SafeNet/Thales Program Files roots. Lab discovery uses the module directory; production Agent still requires an explicit extra allowlist root (SEC-009). System32 is not a default Agent root."
}
Write-Output "FileVersion: $($fileInfo.FileVersion)"
Write-Output "ProductVersion: $($fileInfo.ProductVersion)"
Write-Output "ModuleSHA256: $hash"
Write-Output 'PIN is never accepted as a command-line argument. Use the Windows native PIN dialog for login and sign steps.'
Write-Output 'Physical token evidence is recorded in docs/evidence/etoken-hardware-checklist.md. Do not commit PIN, certificates, or signed PDFs.'
Write-Output 'MVP exit gate remains the AKIS card lab; this list does not unlock Faz 1.'
Write-Output ''
Write-Output 'Running PIN-less token discovery (FR-030 / TST-021)...'

$env:IMZAKIT_ETOKEN_MODULE = $resolved
$testProject = Join-Path $repoRoot 'tests\ImzaKit.Pkcs11.Tests\ImzaKit.Pkcs11.Tests.csproj'
dotnet test $testProject -c Release -p:ETOKEN_HARDWARE_LAB=true --filter 'FullyQualifiedName~EtokenHardwareLabTests' --tl:off
if ($LASTEXITCODE -ne 0) {
    Write-Output 'ETOKEN_HARDWARE_DISCOVERY_FAILED: insert a SafeNet/Thales eToken and re-run. Sign/PIN steps remain manual on the checklist.'
    exit $LASTEXITCODE
}

Write-Output ''
Write-Output 'PIN-less discovery and public X.509 read passed. For CKA_ID match, token sign, and PAdES: powershell -File scripts/run-etoken-pin-lab.ps1'
exit 0
