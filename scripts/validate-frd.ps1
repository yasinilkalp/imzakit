$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$frdRoot = Join-Path $repoRoot 'frd'
$errors = [System.Collections.Generic.List[string]]::new()

function Add-Failure([string]$message) {
    $errors.Add($message)
}

$sourceFiles = Get-ChildItem -LiteralPath $frdRoot -Recurse -File -Filter '*.md' |
    Where-Object { $_.FullName -notlike '*gereksinim-izlenebilirlik-matrisi.md' -and $_.FullName -notlike '*kararlar*' }

$definitions = @{}
foreach ($file in $sourceFiles) {
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++
        if ($line -match '^\s*- \*\*((?:FR|NFR|SEC|VAL|API|TST)-\d{3})(?: [^*]+)?:\*\*') {
            $id = $Matches[1]
            if ($definitions.ContainsKey($id)) {
                Add-Failure "Duplicate requirement definition: $id"
            } else {
                $definitions[$id] = "$($file.FullName):$lineNumber"
            }
        }
    }
}

$matrixPath = Join-Path $frdRoot 'ekler\gereksinim-izlenebilirlik-matrisi.md'
$matrixText = Get-Content -LiteralPath $matrixPath -Raw
foreach ($needle in @(
    'ImzaKit.Certificate.Tests',
    'ImzaKit.Trust.Tests',
    'ImzaKit.Revocation.Tests',
    'verify-nuget-package.ps1',
    '1.0.0-alpha.4',
    '12 DLL'
)) {
    if ($matrixText.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Add-Failure "Traceability matrix is missing Alpha.4 evidence: $needle"
    }
}
$matrixIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($line in Get-Content -LiteralPath $matrixPath) {
    if ($line -match '^\|\s*((?:FR|NFR|SEC|VAL|API)-\d{3})\s*\|') {
        if (-not $matrixIds.Add($Matches[1])) {
            Add-Failure "Duplicate traceability row: $($Matches[1])"
        }
        $cells = $line.Split('|')
        if ($cells.Count -lt 11 -or [string]::IsNullOrWhiteSpace($cells[7]) -or [string]::IsNullOrWhiteSpace($cells[8])) {
            Add-Failure "Traceability row has empty test/evidence: $($Matches[1])"
        }
    }
}

foreach ($id in $definitions.Keys | Where-Object { $_ -notlike 'TST-*' }) {
    if (-not $matrixIds.Contains($id)) { Add-Failure "Requirement missing from traceability matrix: $id" }
}
foreach ($id in $matrixIds) {
    if (-not $definitions.ContainsKey($id)) { Add-Failure "Traceability row has no source definition: $id" }
}

$forbidden = '(?i)\bTBD\b|\bTODO\b|sonra belirlenecek|kararlaştırılacak'
foreach ($file in Get-ChildItem -LiteralPath $frdRoot -Recurse -File -Filter '*.md') {
    if ($file.FullName -like '*README.md') { continue }
    $matches = Select-String -LiteralPath $file.FullName -Pattern $forbidden
    foreach ($match in $matches) { Add-Failure "Unresolved placeholder: $($file.FullName):$($match.LineNumber)" }
}

$requiredText = @{
    'kararlar\ADR-001-acik-kaynak-ve-lisans.md' = @('Apache License 2.0')
    'kararlar\ADR-002-dotnet-platform-tabani.md' = @('.NET 10 LTS')
    'kararlar\ADR-003-agent-loopback-guven-modeli.md' = @('Ed25519', '120 saniye', '30 gün', 'mTLS')
    'kararlar\ADR-006-mvp-kapsami-ve-revocation.md' = @('REVOCATION_DATA_UNAVAILABLE', 'Faz 2')
    'kararlar\ADR-007-saklama-ve-audit.md' = @('24 saat', '7 gün', '120 saniye')
}
foreach ($entry in $requiredText.GetEnumerator()) {
    $text = Get-Content -LiteralPath (Join-Path $frdRoot $entry.Key) -Raw
    foreach ($needle in $entry.Value) {
        if (-not $text.Contains($needle)) { Add-Failure "Missing decision value '$needle' in $($entry.Key)" }
    }
}

foreach ($file in Get-ChildItem -LiteralPath $frdRoot -Recurse -File -Filter '*.md') {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($match in [regex]::Matches($text, '\[[^\]]+\]\(([^)]+)\)')) {
        $target = $match.Groups[1].Value
        if ($target -match '^(https?://|#|mailto:)') { continue }
        $target = $target.Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($target)) { continue }
        $resolved = [System.IO.Path]::GetFullPath((Join-Path $file.DirectoryName $target))
        if (-not (Test-Path -LiteralPath $resolved)) { Add-Failure "Broken local link in $($file.FullName): $target" }
    }
}

$openApiPath = Join-Path $frdRoot 'api-ve-akislar\openapi.yaml'
$openApi = Get-Content -LiteralPath $openApiPath -Raw
if ($openApi -notmatch '(?m)^openapi:\s*3\.1\.0\s*$') { Add-Failure 'OpenAPI version is not 3.1.0' }
$operationIds = [regex]::Matches($openApi, '(?m)^\s+operationId:\s*(\S+)\s*$') | ForEach-Object { $_.Groups[1].Value }
if (($operationIds | Sort-Object -Unique).Count -ne $operationIds.Count) { Add-Failure 'Duplicate OpenAPI operationId' }
$schemas = [regex]::Matches($openApi, '(?m)^    ([A-Za-z][A-Za-z0-9]+):\s*$') | ForEach-Object { $_.Groups[1].Value }
$refs = [regex]::Matches($openApi, "#/components/schemas/([A-Za-z][A-Za-z0-9]+)") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
foreach ($ref in $refs) {
    if ($schemas -notcontains $ref) { Add-Failure "Unresolved OpenAPI schema ref: $ref" }
}

if ($errors.Count -gt 0) {
    Write-Host 'FRD validation failed:' -ForegroundColor Red
    foreach ($failure in $errors) { Write-Host "- $failure" -ForegroundColor Red }
    exit 1
}

Write-Host 'FRD validation passed' -ForegroundColor Green
exit 0
