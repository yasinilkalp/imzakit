[CmdletBinding()]
param(
    [string]$SitePath = (Join-Path $PSScriptRoot '..\site\index.html'),
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..')
)

$ErrorActionPreference = 'Stop'
$resolvedSitePath = [System.IO.Path]::GetFullPath($SitePath)
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)

if (-not (Test-Path -LiteralPath $resolvedSitePath -PathType Leaf)) {
    throw "Landing page is missing: $resolvedSitePath"
}

$html = Get-Content -LiteralPath $resolvedSitePath -Raw
$required = [ordered]@{
    'HTML5 doctype' = '<!doctype html>'
    'Default Turkish language' = 'lang="tr"'
    'Turkish hero' = 'Yerel e-imza standartları, tek NuGet kurulumu.'
    'English hero' = 'Local e-signature standards, one NuGet install.'
    'Primary CTA' = 'NuGet ile Başla'
    'Secondary CTA' = 'GitHub''da İncele'
    'Package command' = 'dotnet add package ImzaKit --version 1.0.0-alpha.4'
    'Twelve-module inventory' = '12'
    'Certificate module' = 'ImzaKit.Certificate'
    'Trust module' = 'ImzaKit.Trust'
    'Revocation module' = 'ImzaKit.Revocation'
    'Validation context' = 'ValidationContext'
    'General X509 profile' = 'GeneralX509'
    'Turkiye NES profile' = 'TurkiyeNes'
    'Unavailable revocation reason' = 'RevocationDataUnavailable'
    'Core registration' = 'AddImzaKitCore'
    'PKCS11 registration' = 'AddImzaKitPkcs11'
    'Language control' = 'id="language-toggle"'
    'Mobile menu state' = 'aria-expanded="false"'
    'Module filter' = 'data-module='
    'Copy action' = 'data-copy'
    'Reduced motion' = 'prefers-reduced-motion'
    'No-script fallback' = '<noscript>'
    'GitHub repository' = 'https://github.com/yasinilkalp/imzakit'
    'NuGet package' = 'https://www.nuget.org/packages/ImzaKit/1.0.0-alpha.4'
    'Technical guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/docs/imzakit-teknik-kullanim-rehberi.html'
    'Security policy' = 'https://github.com/yasinilkalp/imzakit/blob/main/SECURITY.md'
    'Contribution guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/CONTRIBUTING.md'
    'Skip link' = 'class="skip"'
    'Main landmark' = '<main'
    'Navigation landmark' = '<nav'
    'Footer landmark' = '<footer'
}

$missing = foreach ($entry in $required.GetEnumerator()) {
    if ($html.IndexOf($entry.Value, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $entry.Key
    }
}
if ($missing.Count -gt 0) {
    throw "Landing page is missing required content: $($missing -join ', ')"
}

$forbiddenPatterns = [ordered]@{
    'external script' = '<script\s+[^>]*src\s*='
    'external stylesheet' = '<link\s+[^>]*rel\s*=\s*["'']stylesheet["'']'
    'CSS import' = '@import'
    'remote CSS asset' = 'url\(\s*["'']?https?://'
    'remote image' = '<img\s+[^>]*src\s*=\s*["'']https?://'
    'analytics' = 'google-analytics|googletagmanager|gtag\(|plausible\.io|analytics\.'
    'inline event handler' = '\son(click|change|input|submit)\s*='
}
foreach ($entry in $forbiddenPatterns.GetEnumerator()) {
    if ($html -match $entry.Value) {
        throw "Landing page contains forbidden $($entry.Key)."
    }
}

$moduleCount = [regex]::Matches($html, '<article\s+[^>]*data-module\s*=', 'IgnoreCase').Count
if ($moduleCount -ne 12) {
    throw "Landing page must contain exactly 12 module cards; found $moduleCount."
}

$h1Count = [regex]::Matches($html, '<h1(?:\s|>)', 'IgnoreCase').Count
if ($h1Count -ne 1) {
    throw "Landing page must contain exactly one h1; found $h1Count."
}

if ($html -match '(?:href|src)\s*=\s*["'']\.\./') {
    throw 'Landing page must use absolute GitHub URLs for files outside the Pages artifact.'
}

$readmePath = Join-Path $root 'README.md'
$reportPath = Join-Path $root 'reports\imzakit-gelistirme-durum.html'
if (-not (Test-Path -LiteralPath $readmePath) -or -not (Test-Path -LiteralPath $reportPath)) {
    throw 'README or live status report is missing.'
}
$readme = Get-Content -LiteralPath $readmePath -Raw
$report = Get-Content -LiteralPath $reportPath -Raw
foreach ($pattern in @('https://yasinilkalp.github.io/imzakit/', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md')) {
    if ($readme.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "README is missing landing-page integration content: $pattern"
    }
}
foreach ($pattern in @('Açık kaynak landing page', 'GitHub Pages', 'landing page verification passed')) {
    if ($report.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Status report is missing landing-page integration content: $pattern"
    }
}

Write-Host 'Landing page verification passed.' -ForegroundColor Green
