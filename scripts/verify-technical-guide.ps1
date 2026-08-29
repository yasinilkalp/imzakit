[CmdletBinding()]
param(
    [string]$GuidePath = (Join-Path $PSScriptRoot '..\docs\imzakit-teknik-kullanim-rehberi.html')
)

$ErrorActionPreference = 'Stop'
$resolvedGuidePath = [System.IO.Path]::GetFullPath($GuidePath)

if (-not (Test-Path -LiteralPath $resolvedGuidePath -PathType Leaf)) {
    throw "Technical guide is missing: $resolvedGuidePath"
}

$html = Get-Content -LiteralPath $resolvedGuidePath -Raw
$requiredPatterns = [ordered]@{
    'HTML5 doctype' = '<!doctype html>'
    'Turkish document language' = 'lang="tr"'
    'Published package version' = 'ImzaKit 1.0.0-alpha.12'
    'NuGet install command' = 'dotnet add package ImzaKit --version 1.0.0-alpha.12'
    'Sixteen-module inventory' = '16 modül'
    'Timestamp module' = 'ImzaKit.Timestamp'
    'CAdES module' = 'ImzaKit.CAdES'
    'XAdES module' = 'ImzaKit.XAdES'
    'ASiC module' = 'ImzaKit.ASiC'
    'Core module' = 'ImzaKit.Core'
    'Cryptography module' = 'ImzaKit.Cryptography'
    'CMS module' = 'ImzaKit.Cms'
    'PAdES module' = 'ImzaKit.PAdES'
    'PKCS11 module' = 'ImzaKit.Pkcs11'
    'Verify module' = 'ImzaKit.Verify'
    'Agent module' = 'ImzaKit.Agent'
    'API module' = 'ImzaKit.Api'
    'Dependency injection module' = 'ImzaKit.DependencyInjection'
    'Certificate module' = 'ImzaKit.Certificate'
    'Trust module' = 'ImzaKit.Trust'
    'Revocation module' = 'ImzaKit.Revocation'
    'Core DI registration' = 'AddImzaKitCore'
    'PKCS11 DI registration' = 'AddImzaKitPkcs11'
    'PAdES validation' = 'PadesValidator.Validate'
    'Validation context' = 'ValidationContext'
    'General X509 profile' = 'GeneralX509'
    'Turkiye NES profile' = 'TurkiyeNes'
    'Unavailable revocation reason' = 'RevocationDataUnavailable'
    'Turkish offline validation heading' = 'Çevrimdışı güven doğrulaması'
    'Turkish limitations heading' = 'Sınırlamalar'
    'English offline validation heading' = 'Offline trust validation'
    'English limitations heading' = 'Limitations'
    'PAdES preparation' = 'PadesSignaturePreparer'
    'PAdES completion' = 'PadesSignatureCompleter.Complete'
    'PKCS11 provider contract' = 'IPkcs11Provider'
    'In-process orchestrator' = 'InProcessPadesSigningOrchestrator'
    'Preflight limits' = 'PdfPreflightLimits.Default'
    'Operation state model' = 'SignatureOperationState'
    'Search control' = 'id="guide-search"'
    'Module filter metadata' = 'data-module='
    'Copy control metadata' = 'data-copy'
    'Expandable API details' = '<details'
    'Theme persistence' = 'localStorage'
    'Reduced motion support' = 'prefers-reduced-motion'
    'Print stylesheet' = '@media print'
}

$missing = foreach ($entry in $requiredPatterns.GetEnumerator()) {
    if ($html.IndexOf($entry.Value, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $entry.Key
    }
}

if ($missing.Count -gt 0) {
    throw "Technical guide is missing required content: $($missing -join ', ')"
}

if ($html -match '<script\s+[^>]*src\s*=' -or $html -match '<link\s+[^>]*rel\s*=\s*["'']stylesheet["'']') {
    throw 'Technical guide must not depend on external scripts or stylesheets.'
}

Write-Host 'Technical guide verification passed.' -ForegroundColor Green
