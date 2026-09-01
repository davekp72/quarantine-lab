#Requires -Version 5.1
<#
.SYNOPSIS
  SYSTEM-privileged wrapper for admin smoke test (used by QuarantineLabPrivilegedExport task).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$guestDir = Split-Path -Parent $OutFile
$smokeScript = Join-Path $guestDir 'Invoke-QuarantineLabManifestSmokeTest.ps1'
if (-not (Test-Path -LiteralPath $smokeScript)) {
    throw "Smoke script not found: $smokeScript"
}

$tag = (Get-Date -Format 'yyyyMMdd-HHmmss')
if ($OutFile -match 'smoke-admin-(.+)\.result\.txt$') {
    $tag = $Matches[1]
}

& $smokeScript -Part Admin -Tag $tag -ResultFile $OutFile
if (-not (Test-Path -LiteralPath $OutFile)) {
    throw "Admin smoke did not write result file: $OutFile"
}

Write-Output "SMOKE_ADMIN_PRIV_OK $OutFile"
