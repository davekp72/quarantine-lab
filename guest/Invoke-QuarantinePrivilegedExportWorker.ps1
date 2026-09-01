#Requires -Version 5.1
<#
.SYNOPSIS
  SYSTEM worker: run one or more manifest export scripts from privileged-job.json.
  Picks up privileged-job-upload-*.json dropped by the host (no guestcontrol Move-Item).
#>
[CmdletBinding()]
param(
    [string]$JobFile = 'C:\Users\Public\Quarantine\privileged-job.json',
    [string]$DoneFile = 'C:\Users\Public\Quarantine\privileged-job.done'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$guestDir = Split-Path -Parent $JobFile
if ([string]::IsNullOrWhiteSpace($guestDir)) {
    $guestDir = 'C:\Users\Public\Quarantine'
}

$upload = Get-ChildItem -LiteralPath $guestDir -Filter 'privileged-job-upload-*.json' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($upload) {
    if (Test-Path -LiteralPath $DoneFile) {
        Remove-Item -LiteralPath $DoneFile -Force
    }
    if (Test-Path -LiteralPath $JobFile) {
        Remove-Item -LiteralPath $JobFile -Force
    }
    Move-Item -LiteralPath $upload.FullName -Destination $JobFile -Force
}

if (-not (Test-Path -LiteralPath $JobFile)) {
    exit 0
}

$job = Get-Content -LiteralPath $JobFile -Raw -Encoding UTF8 | ConvertFrom-Json

$steps = New-Object System.Collections.Generic.List[object]
if ($job.PSObject.Properties['steps'] -and $job.steps) {
    foreach ($step in @($job.steps)) {
        $steps.Add($step) | Out-Null
    }
} elseif ($job.scriptPath) {
    $steps.Add([pscustomobject]@{ scriptPath = [string]$job.scriptPath; outFile = [string]$job.outFile }) | Out-Null
}

if ($steps.Count -eq 0) {
    throw 'Privileged job has no steps.'
}

$completed = 0
foreach ($step in $steps) {
    $scriptPath = [string]$step.scriptPath
    $outFile = [string]$step.outFile
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Privileged job step missing scriptPath.'
    }
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Script missing: $scriptPath"
    }
    if ([string]::IsNullOrWhiteSpace($outFile)) {
        throw "Privileged job step missing outFile for: $scriptPath"
    }

    & $scriptPath -OutFile $outFile | Out-Null
    if (-not (Test-Path -LiteralPath $outFile)) {
        throw "Export did not create: $outFile"
    }
    $completed++
    Write-Output "PRIVILEGED_EXPORT_OK $outFile"
}

Set-Content -LiteralPath $DoneFile -Value (Get-Date).ToUniversalTime().ToString('o') -Encoding ASCII
Write-Output "PRIVILEGED_BATCH_OK steps=$completed"
