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

foreach ($required in @($indexPath, $stylesPath, $appPath)) {
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
        [switch]$KeepContent,
        [int]$MaxRowsPerBucket = 400
    )

    if ($KeepContent) { return $Diff }

    $clone = $Diff | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json
    $truncated = $false

    foreach ($bucket in @('added', 'removed', 'modified')) {
        $list = $clone.files.$bucket
        if ($list -and @($list).Count -gt $MaxRowsPerBucket) {
            $clone.files.$bucket = @(@($list) | Select-Object -First $MaxRowsPerBucket)
            $truncated = $true
        }
        if ($list) {
            foreach ($entry in @($clone.files.$bucket)) {
                Remove-DiffFileContent -Entry $entry
            }
        }
    }

    foreach ($section in @('registry', 'tasks')) {
        foreach ($bucket in @('added', 'removed', 'modified', 'volatileOnly')) {
            $prop = $clone.$section.PSObject.Properties[$bucket]
            if (-not $prop) { continue }
            $list = $prop.Value
            if ($list -and @($list).Count -gt $MaxRowsPerBucket) {
                $clone.$section.$bucket = @(@($list) | Select-Object -First $MaxRowsPerBucket)
                $truncated = $true
            }
        }
    }

    if ($clone.sysmon -and $clone.sysmon.added -and @($clone.sysmon.added).Count -gt $MaxRowsPerBucket) {
        $clone.sysmon.added = @(@($clone.sysmon.added) | Select-Object -First $MaxRowsPerBucket)
        $truncated = $true
    }

    if ($truncated) {
        if (-not $clone.meta) { $clone | Add-Member -NotePropertyName meta -NotePropertyValue ([pscustomobject]@{}) -Force }
        $note = "Viewer lists capped at $MaxRowsPerBucket rows per bucket. Full counts are in summary cards and diff JSON on disk."
        if ($clone.meta.PSObject.Properties['warnings']) {
            $clone.meta.warnings = @($clone.meta.warnings) + @($note)
        } else {
            $clone.meta | Add-Member -NotePropertyName warnings -NotePropertyValue @($note) -Force
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
$html = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8

$html = $html -replace '<link rel="stylesheet" href="styles.css">', "<style>`n$styles`n</style>"
$html = $html -replace '<script src="app.js"></script>', @"
<script type="application/json" id="manifest-diff-data">$viewerJson</script>
<script>
$appJs
</script>
"@

$sessionPath = Join-Path $ViewerDir 'session.html'
[System.IO.File]::WriteAllText($sessionPath, $html, [System.Text.UTF8Encoding]::new($false))

Start-Process -FilePath $sessionPath
Write-Output $sessionPath
