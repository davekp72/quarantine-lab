#Requires -Version 5.1
<#
.SYNOPSIS
  Run the admin smoke test elevated via schtasks (invoked with -File from host guestcontrol).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$JobFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $JobFile)) {
    throw "Job file not found: $JobFile"
}

$job = Get-Content -LiteralPath $JobFile -Raw -Encoding UTF8 | ConvertFrom-Json
$guestDir = Split-Path -Parent $JobFile
$elevatedRunner = Join-Path $guestDir 'Invoke-QuarantineGuestElevated.ps1'

if (-not (Test-Path -LiteralPath $elevatedRunner)) {
    throw "Elevated runner not found: $elevatedRunner"
}
if (-not (Test-Path -LiteralPath $job.smokeScript)) {
    throw "Smoke script not found: $($job.smokeScript)"
}

& $elevatedRunner `
    -ScriptPath ([string]$job.smokeScript) `
    -ScriptArguments @('-Part', 'Admin', '-Tag', ([string]$job.tag), '-ResultFile', ([string]$job.resultFile)) `
    -TaskUser ([string]$job.taskUser) `
    -TaskPassword ([string]$job.taskPassword) `
    -TimeoutSeconds 180
