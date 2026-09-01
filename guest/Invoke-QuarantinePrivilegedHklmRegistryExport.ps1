#Requires -Version 5.1
<#
.SYNOPSIS
  SYSTEM-privileged wrapper for HKLM reg.exe export (QuarantineLabPrivilegedExport task).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$guestDir = Split-Path -Parent $OutFile
$exportScript = Join-Path $guestDir 'Export-QuarantineGuestHklmRegistryCli.ps1'
if (-not (Test-Path -LiteralPath $exportScript)) {
    throw "HKLM export script not found: $exportScript"
}

$outDir = Join-Path $guestDir 'hklm-registry-cli'
$metaFile = Join-Path $outDir 'hklm-registry-meta.json'

& $exportScript -OutDir $outDir -OutMetaFile $metaFile
if (-not (Test-Path -LiteralPath $metaFile)) {
    throw "HKLM export did not write meta: $metaFile"
}

Copy-Item -LiteralPath $metaFile -Destination $OutFile -Force
Write-Output "HKLM_PRIV_EXPORT_OK $OutFile"
