#Requires -Version 5.1
<#
.SYNOPSIS
  Copy Regshot CMD + config to the quarantine guest.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not (Get-Command Copy-QuarantineVMGuestFile -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $projectRoot 'QuarantineVM.psm1') -Force
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $projectRoot 'config\quarantine-vm.json'
}

function Wait-QuarantineGuestDeployReady {
    param(
        [string]$ConfigPath,
        [int]$TimeoutSeconds = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if (Test-QuarantineVMGuestControl -ConfigPath $ConfigPath) { return }
        } catch {
            if ($_.Exception.Message -match 'not ready|poweroff|not running|E_ACCESSDENIED') {
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }
    throw 'Guest control did not become ready within timeout.'
}

Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
$cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
$guestDir = if ($cfg.regshot -and $cfg.regshot.guestDir) {
    [string]$cfg.regshot.guestDir
} else {
    'C:\Users\Public\Quarantine\regshot'
}

$hostTools = Join-Path $projectRoot 'tools\regshot'
if (-not (Test-Path -LiteralPath $hostTools)) {
    New-Item -ItemType Directory -Path $hostTools -Force | Out-Null
}

$cmdNames = @(
    'Regshot_cmd-x64-Unicode.exe',
    'Regshot_cmd-x64-ANSI.exe',
    'RegShot_CMD.exe',
    'Regshot-x64-Unicode.exe',
    'Regshot-x64-ANSI.exe'
)
$toCopy = @()
foreach ($name in $cmdNames) {
    $p = Join-Path $hostTools $name
    if (Test-Path -LiteralPath $p) { $toCopy += $p }
}

$iniHost = Join-Path $projectRoot 'config\regshot\quarantine-lab.ini'
if (Test-Path -LiteralPath $iniHost) { $toCopy += $iniHost }

if ($toCopy.Count -eq 0 -and -not $SkipVerify) {
    throw @"
No Regshot binaries in tools/regshot/.
Download RegShot CMD from https://sourceforge.net/projects/regshot/files/regcmd/
Optional GUI: https://github.com/Seabreg/Regshot
Then run: .\quarantine-vm.ps1 regshot copy
"@
}

Wait-QuarantineGuestDeployReady -ConfigPath $ConfigPath | Out-Null

foreach ($file in $toCopy) {
    Copy-QuarantineVMGuestFile -Path $file -ConfigPath $ConfigPath -TargetDirectory $guestDir
}

Copy-QuarantineVMGuestFile -Path (Join-Path $projectRoot 'manifest\Invoke-QuarantineGuestRegshot.ps1') `
    -ConfigPath $ConfigPath -TargetDirectory (Split-Path $guestDir -Parent)

Write-Host "Regshot deployed to guest: $guestDir"
if (-not ($toCopy | Where-Object { $_ -match 'Regshot_cmd|RegShot_CMD' })) {
    Write-Warning 'RegShot CMD not copied — automated manifest registry diff requires Regshot_cmd-x64-*.exe.'
}
