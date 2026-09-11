#Requires -Version 5.1
<#
.SYNOPSIS
  Open the manifest diff viewer in the default browser with embedded diff data.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DiffJsonPath,

    [string]$ViewerDir,

    [switch]$KeepFileContent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DiffJsonPath)) {
    throw "Diff JSON not found: $DiffJsonPath"
}

if (-not $ViewerDir) {
    $ViewerDir = $PSScriptRoot
}

$indexPath = Join-Path $ViewerDir 'index.html'
$stylesPath = Join-Path $ViewerDir 'styles.css'
$appPath = Join-Path $ViewerDir 'app.js'
$highlightPath = Join-Path $ViewerDir 'highlight.js'

foreach ($required in @($indexPath, $stylesPath, $appPath, $highlightPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Viewer asset missing: $required"
    }
}

function Remove-DiffFileContent {
    param([object]$Entry)

    if (-not $Entry) { return }
    foreach ($name in @('content', 'fromContent', 'toContent')) {
        if ($Entry.PSObject.Properties[$name]) {
            $Entry.PSObject.Properties.Remove($name)
        }
    }
}

function Get-ViewerDiffObject {
    param(
        [object]$Diff,
        [switch]$KeepContent
    )

    if ($KeepContent) { return $Diff }

    $clone = $Diff | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json

    foreach ($bucket in @('added', 'removed', 'modified')) {
        $list = $clone.files.$bucket
        if ($list) {
            foreach ($entry in @($list)) {
                Remove-DiffFileContent -Entry $entry
            }
        }
    }

    return $clone
}

function ConvertTo-HtmlEmbeddedJson {
    param([string]$Json)
    # Keep HTML parsers from closing the script block early.
    return ($Json -replace '</', '<\/')
}

$diff = Get-Content -LiteralPath $DiffJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$viewerDiff = Get-ViewerDiffObject -Diff $diff -KeepContent:$KeepFileContent
$viewerJson = ConvertTo-HtmlEmbeddedJson -Json ($viewerDiff | ConvertTo-Json -Depth 64 -Compress)

$styles = Get-Content -LiteralPath $stylesPath -Raw -Encoding UTF8
$appJs = Get-Content -LiteralPath $appPath -Raw -Encoding UTF8
$highlightJs = Get-Content -LiteralPath $highlightPath -Raw -Encoding UTF8
$html = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8

# Inline style/script need CSP nonces (index.html uses script-src/style-src 'self' for external assets).
$nonceBytes = New-Object byte[] 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
$cspNonce = [Convert]::ToBase64String($nonceBytes)
$csp = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none'; style-src 'nonce-$cspNonce'; script-src 'nonce-$cspNonce'"
$html = [regex]::Replace(
    $html,
    '<meta http-equiv="Content-Security-Policy" content="[^"]*">',
    "<meta http-equiv=`"Content-Security-Policy`" content=`"$csp`">",
    1
)

$html = $html -replace '<link rel="stylesheet" href="styles.css">', "<style nonce=`"$cspNonce`">`n$styles`n</style>"
$html = $html -replace '<script src="highlight.js"></script>\s*<script src="app.js"></script>', @"
<script type="application/json" id="manifest-diff-data">$viewerJson</script>
<script nonce="$cspNonce">
$highlightJs
</script>
<script nonce="$cspNonce">
$appJs
</script>
"@

$sessionPath = Join-Path $ViewerDir 'session.html'
[System.IO.File]::WriteAllText($sessionPath, $html, [System.Text.UTF8Encoding]::new($false))

Start-Process -FilePath $sessionPath
Write-Output $sessionPath
