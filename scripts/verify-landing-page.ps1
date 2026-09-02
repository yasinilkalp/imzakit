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
    'Turkish hero start' = 'Yerel e-imza standartları,'
    'Turkish hero highlight' = 'tek NuGet kurulumu.'
    'English hero start' = 'Local e-signature standards,'
    'English hero highlight' = 'one NuGet install.'
    'Primary CTA' = 'NuGet ile Başla'
    'Secondary CTA' = 'GitHub''da İncele'
    'Package command' = 'dotnet add package ImzaKit --version 1.0.0-alpha.14'
    'Plain-language workflow start' = 'Belgeyi hazırla'
    'Plain-language workflow sign' = 'Kartla imzala'
    'Plain-language workflow verify' = 'Sonucu doğrula'
    'Private key promise' = 'Özel anahtar karttan çıkmaz'
    'Supported PDF format' = 'PDF'
    'Supported XML format' = 'XML'
    'Open source promise' = 'Apache-2.0'
    'Language control' = 'id="language-toggle"'
    'Mobile menu state' = 'aria-expanded="false"'
    'Copy action' = 'data-copy'
    'Reduced motion' = 'prefers-reduced-motion'
    'No-script fallback' = '<noscript>'
    'GitHub repository' = 'https://github.com/yasinilkalp/imzakit'
    'NuGet package' = 'https://www.nuget.org/packages/ImzaKit/1.0.0-alpha.14'
    'Technical guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/docs/imzakit-teknik-kullanim-rehberi.html'
    'Security policy' = 'https://github.com/yasinilkalp/imzakit/blob/main/SECURITY.md'
    'Contribution guide' = 'https://github.com/yasinilkalp/imzakit/blob/main/CONTRIBUTING.md'
    'Windows app heading' = 'Windows uygulaması'
    'Windows app English' = 'Sign a PDF with'
    'Desktop setup download' = 'setup.exe indir'
    'GitHub Releases latest' = 'https://github.com/yasinilkalp/imzakit/releases/latest'
    'Desktop not in NuGet' = 'NuGet paketinde yoktur'
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

$workflowStepCount = [regex]::Matches($html, '<article\s+[^>]*class=["''][^"'']*step[^"'']*["'']', 'IgnoreCase').Count
if ($workflowStepCount -ne 3) {
    throw "Landing page must contain exactly three plain-language workflow steps; found $workflowStepCount."
}

if ($html -match 'data-module=|data-filter=') {
    throw 'Landing page must not expose the technical module filter.'
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

$siteDirectory = Split-Path -Parent $resolvedSitePath
$exeFiles = @(Get-ChildItem -LiteralPath $siteDirectory -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue)
if ($exeFiles.Count -gt 0) {
    throw "Landing page site directory must not contain .exe binaries."
}

Write-Host 'Landing page verification passed.' -ForegroundColor Green
