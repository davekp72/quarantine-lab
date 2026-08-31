#Requires -Version 5.1
<#
.SYNOPSIS
  SYSTEM worker: run a manifest export script described in privileged-job.json.
#>
[CmdletBinding()]
param(
    [string]$JobFile = 'C:\Users\Public\Quarantine\privileged-job.json',
    [string]$DoneFile = 'C:\Users\Public\Quarantine\privileged-job.done'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (Test-Path -LiteralPath $DoneFile) {
    Remove-Item -LiteralPath $DoneFile -Force
}

if (-not (Test-Path -LiteralPath $JobFile)) {
    throw "Job file missing: $JobFile"
}

$job = Get-Content -LiteralPath $JobFile -Raw -Encoding UTF8 | ConvertFrom-Json
$scriptPath = [string]$job.scriptPath
$outFile = [string]$job.outFile
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Script missing: $scriptPath"
}
if ([string]::IsNullOrWhiteSpace($outFile)) {
    throw 'Job missing outFile.'
}

& $scriptPath -OutFile $outFile | Out-Null
if (-not (Test-Path -LiteralPath $outFile)) {
    throw "Export did not create: $outFile"
}

Set-Content -LiteralPath $DoneFile -Value (Get-Date).ToUniversalTime().ToString('o') -Encoding ASCII
Write-Output "PRIVILEGED_EXPORT_OK $outFile"
