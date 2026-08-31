#Requires -Version 5.1
<#
.SYNOPSIS
  Hash and optionally embed content for a explicit path list (post USN/Sysmon enrich).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PathsFile,

    [Parameter(Mandatory)]
    [string]$OutFile,

    [int]$HashMaxMb = 50,
    [int]$ContentMaxKb = 51200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$hashMaxBytes = [int64]$HashMaxMb * 1MB
$contentMaxBytes = [int64]$ContentMaxKb * 1KB
$files = New-Object System.Collections.Generic.List[object]

function Get-FileContentPayload {
    param(
        [System.IO.FileInfo]$Item,
        [int64]$MaxBytes
    )

    if ($Item.Length -gt $MaxBytes) {
        return @{ c = 'too_large' }
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Item.FullName)
        $hasNull = $false
        foreach ($b in $bytes) {
            if ($b -eq 0) { $hasNull = $true; break }
        }

        if (-not $hasNull) {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            $bad = 0
            foreach ($ch in $text.ToCharArray()) {
                $code = [int][char]$ch
                if ($code -lt 9 -or ($code -gt 13 -and $code -lt 32)) { $bad++ }
            }
            if ($text.Length -eq 0 -or ($bad / [Math]::Max($text.Length, 1)) -lt 0.05) {
                return @{ c = 'text'; d = $text }
            }
        }

        return @{ c = 'base64'; d = [Convert]::ToBase64String($bytes) }
    } catch {
        return @{ c = 'access_denied' }
    }
}

function Add-FileEntry {
    param([System.IO.FileInfo]$Item)

    if (-not $Item) { return }
    $entry = [ordered]@{
        p = $Item.FullName
        s = $Item.Length
        m = $Item.LastWriteTimeUtc.ToString('o')
        src = 'enrich'
    }
    if ($Item.Length -le $hashMaxBytes) {
        try {
            $entry.h = (Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            $entry.h = 'ACCESS_DENIED'
        }
    } else {
        $entry.h = 'SKIPPED_LARGE'
    }

    if ($Item.Length -le $contentMaxBytes) {
        $payload = Get-FileContentPayload -Item $Item -MaxBytes $contentMaxBytes
        $entry.c = $payload.c
        if ($payload.d) { $entry.d = $payload.d }
    } else {
        $entry.c = 'too_large'
    }

    $files.Add([pscustomobject]$entry) | Out-Null
}

if (-not (Test-Path -LiteralPath $PathsFile)) {
    throw "Paths file not found: $PathsFile"
}

$paths = Get-Content -LiteralPath $PathsFile -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$seen = @{}

foreach ($path in $paths) {
    if ($seen.ContainsKey($path)) { continue }
    $seen[$path] = $true
    try {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Add-FileEntry -Item (Get-Item -LiteralPath $path -Force)
        }
    } catch { }
}

$result = [ordered]@{
    enrichedAt = (Get-Date).ToUniversalTime().ToString('o')
    requested  = @($paths).Count
    scanned    = $files.Count
    files      = @($files)
}

$result | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "TARGETED_SCAN $OutFile requested=$($paths.Count) scanned=$($files.Count)"
