#Requires -Version 5.1
<#
.SYNOPSIS
  Download Sysmon from Microsoft, verify Authenticode, optionally check SHA-256, and record the version.

.DESCRIPTION
  Microsoft does not permit third parties to redistribute Sysinternals executables.
  This script fetches Sysmon.zip from download.sysinternals.com, extracts Sysmon64.exe,
  checks the Microsoft Authenticode signature, and writes tools\Sysmon64.exe.

  Optional pin: if tools\Sysmon64.sha256 exists and contains a SHA-256 hex digest,
  the extracted binary must match it.

.NOTES
  Sysinternals license FAQ:
  https://learn.microsoft.com/en-us/sysinternals/license-faq
  Sysmon download page:
  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [string]$DownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}

$toolsDir = Join-Path $ProjectRoot 'tools'
$zipPath = Join-Path $toolsDir 'Sysmon.zip'
$destExe = Join-Path $toolsDir 'Sysmon64.exe'
$versionFile = Join-Path $toolsDir 'Sysmon.version'
$pinFile = Join-Path $toolsDir 'Sysmon64.sha256'

function Get-PinnedSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        if ($t -match '([A-Fa-f0-9]{64})') { return $Matches[1].ToLowerInvariant() }
    }
    return $null
}

function Test-MicrosoftAuthenticode {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode status for $(Split-Path -Leaf $Path) is $($sig.Status), expected Valid."
    }
    $subject = [string]$sig.SignerCertificate.Subject
    if ($subject -notmatch 'O=Microsoft Corporation') {
        throw "Authenticode signer is not Microsoft Corporation: $subject"
    }
    return $sig
}

if (-not (Test-Path -LiteralPath $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}

if ((Test-Path -LiteralPath $destExe) -and -not $Force) {
    $existing = Test-MicrosoftAuthenticode -Path $destExe
    $vi = (Get-Item -LiteralPath $destExe).VersionInfo
    $hash = (Get-FileHash -LiteralPath $destExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $pin = Get-PinnedSha256 -Path $pinFile
    if ($pin -and $pin -ne $hash) {
        throw "Existing tools\Sysmon64.exe SHA-256 $hash does not match pin $pin. Re-run with -Force after reviewing the pin."
    }
    $ver = if ($vi.FileVersion) { $vi.FileVersion } else { $vi.ProductVersion }
    @"
fileVersion=$ver
productVersion=$($vi.ProductVersion)
sha256=$hash
signer=$($existing.SignerCertificate.Subject)
source=existing
"@ | Set-Content -LiteralPath $versionFile -Encoding UTF8
    Write-Host "Sysmon already present: $destExe"
    Write-Host "  File version: $ver"
    Write-Host "  SHA-256: $hash"
    return
}

Write-Host "Downloading Sysmon from Microsoft: $DownloadUrl"
$tmpZip = Join-Path ([IO.Path]::GetTempPath()) ("Sysmon-" + [guid]::NewGuid().ToString('n') + ".zip")
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("Sysmon-" + [guid]::NewGuid().ToString('n'))
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tmpZip -UseBasicParsing
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpDir -Force

    $extracted = Get-ChildItem -LiteralPath $tmpDir -Filter 'Sysmon64.exe' -Recurse | Select-Object -First 1
    if (-not $extracted) {
        throw 'Sysmon.zip did not contain Sysmon64.exe.'
    }

    $sig = Test-MicrosoftAuthenticode -Path $extracted.FullName
    $hash = (Get-FileHash -LiteralPath $extracted.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $pin = Get-PinnedSha256 -Path $pinFile
    if ($pin -and $pin -ne $hash) {
        throw @"
Sysmon64.exe SHA-256 mismatch.
  downloaded: $hash
  pinned:     $pin
Update tools\Sysmon64.sha256 only after reviewing a new Microsoft Sysmon release.
"@
    }

    Copy-Item -LiteralPath $extracted.FullName -Destination $destExe -Force
    Copy-Item -LiteralPath $tmpZip -Destination $zipPath -Force

    $vi = (Get-Item -LiteralPath $destExe).VersionInfo
    $ver = if ($vi.FileVersion) { $vi.FileVersion } else { $vi.ProductVersion }
    @"
fileVersion=$ver
productVersion=$($vi.ProductVersion)
sha256=$hash
signer=$($sig.SignerCertificate.Subject)
source=$DownloadUrl
downloadedUtc=$((Get-Date).ToUniversalTime().ToString('o'))
"@ | Set-Content -LiteralPath $versionFile -Encoding UTF8

    Write-Host "Installed Sysmon64.exe -> $destExe"
    Write-Host "  File version: $ver"
    Write-Host "  SHA-256: $hash"
    Write-Host "  Signer: $($sig.SignerCertificate.Subject)"
    if (-not $pin) {
        Write-Host '  SHA-256 pin: not configured (tools\Sysmon64.sha256). Authenticode was verified.'
    }
}
finally {
    Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
