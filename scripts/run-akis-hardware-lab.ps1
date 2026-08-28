param(
    [string]$ModulePath = $env:IMZAKIT_AKIS_MODULE
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding
$repoRoot = Split-Path -Parent $PSScriptRoot

$agentDefaultRoot = Join-Path ${env:ProgramFiles} 'AKIS'
$labCandidates = @(
    (Join-Path $agentDefaultRoot 'akisp11.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'AKIS\akisp11.dll'),
    (Join-Path $env:WINDIR 'System32\akisp11.dll')
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
    Write-Output 'AKIS_HARDWARE_SKIPPED: no PKCS#11 module. Install AKİS middleware or set IMZAKIT_AKIS_MODULE to an akisp11.dll path.'
    Write-Output 'Looked in %ProgramFiles%\AKIS, %ProgramFiles(x86)%\AKIS, and %WINDIR%\System32.'
    Write-Output 'PIN is never accepted as a command-line argument or environment variable.'
    Write-Output 'Record evidence in docs/evidence/akis-hardware-checklist.md after a physical lab run.'
    exit 2
}

$resolved = [System.IO.Path]::GetFullPath($ModulePath)
$fileName = [System.IO.Path]::GetFileName($resolved)
if (-not [string]::Equals($fileName, 'akisp11.dll', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Output "AKIS_HARDWARE_REJECTED: module file name must be akisp11.dll (got '$fileName')."
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

Write-Output '=== AKİS hardware lab environment ==='
Write-Output "Repository: $repoRoot"
Write-Output "Commit: $commit"
Write-Output "OS: $os"
Write-Output "Architecture: $arch"
Write-Output "Module: $resolved"
$underAgentRoot = $resolved.StartsWith(
    ([System.IO.Path]::GetFullPath($agentDefaultRoot).TrimEnd('\') + '\'),
    [System.StringComparison]::OrdinalIgnoreCase)
if (-not $underAgentRoot) {
    Write-Output "AllowlistNote: path is outside the Agent default root ($agentDefaultRoot). Lab discovery uses the module directory; production Agent still requires an explicit extra allowlist root (SEC-009). System32 is not a default Agent root."
}
Write-Output "FileVersion: $($fileInfo.FileVersion)"
Write-Output "ProductVersion: $($fileInfo.ProductVersion)"
Write-Output "ModuleSHA256: $hash"
Write-Output 'PIN is never accepted as a command-line argument. Use the Windows native PIN dialog for login and sign steps.'
Write-Output 'Physical card evidence is recorded in docs/evidence/akis-hardware-checklist.md. Do not commit PIN, certificates, or signed PDFs.'
Write-Output ''
Write-Output 'Running PIN-less token discovery (TST-001 / FR-022)...'

$env:IMZAKIT_AKIS_MODULE = $resolved
$testProject = Join-Path $repoRoot 'tests\ImzaKit.Pkcs11.Tests\ImzaKit.Pkcs11.Tests.csproj'
dotnet test $testProject -c Release -p:AKIS_HARDWARE_LAB=true --filter 'FullyQualifiedName~AkisHardwareLabTests' --tl:off
if ($LASTEXITCODE -ne 0) {
    Write-Output 'AKIS_HARDWARE_DISCOVERY_FAILED: no token readable via akisp11.dll.'
    Write-Output 'If the reader shows SafeNet Token JC / eToken, this is not an AKİS card — use docs/evidence/etoken-hardware-checklist.md and eTPKCS11.dll.'
    Write-Output 'Insert a KamuSM AKİS card and re-run. Optional probe: dotnet run --file scripts/akis-pkcs11-probe.cs'
    exit $LASTEXITCODE
}

Write-Output ''
Write-Output 'Discovery passed. Complete sections 3–6 of docs/evidence/akis-hardware-checklist.md with CredUI PIN (never argv).'
exit 0
