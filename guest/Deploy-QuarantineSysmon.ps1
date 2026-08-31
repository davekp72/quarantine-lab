#Requires -Version 5.1
<#
.SYNOPSIS
  Copy Sysmon config + installer to guest and run install as lab admin.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$SysmonHostZip,
    [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not (Get-Command Copy-QuarantineVMGuestFile -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $projectRoot 'QuarantineVM.psm1')
}
# Do not Import-Module QuarantineManifest.psm1 here — -Force reload breaks the caller session.

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

if (-not $cfg.sysmon) {
    throw 'sysmon section missing from config/quarantine-vm.json'
}

$hostConfigRel = $cfg.sysmon.hostConfigPath
$hostConfig = if ([IO.Path]::IsPathRooted($hostConfigRel)) {
    $hostConfigRel
} else {
    Join-Path $projectRoot ($hostConfigRel -replace '\\', [IO.Path]::DirectorySeparatorChar)
}

$guestDir = $cfg.sysmon.guestDir
$guestConfigName = $cfg.sysmon.guestConfigName
$installScript = Join-Path $PSScriptRoot 'Install-QuarantineSysmon.ps1'

if (-not (Test-Path -LiteralPath $hostConfig)) {
    throw "Sysmon config not found on host: $hostConfig"
}
if (-not (Test-Path -LiteralPath $installScript)) {
    throw "Install script not found: $installScript"
}

Wait-QuarantineGuestDeployReady -ConfigPath $ConfigPath

Copy-QuarantineVMGuestFile -Path $hostConfig -ConfigPath $ConfigPath -TargetDirectory $guestDir
Copy-QuarantineVMGuestFile -Path $installScript -ConfigPath $ConfigPath -TargetDirectory $guestDir

$guestExe = if ($cfg.sysmon.guestSysmonExe) { $cfg.sysmon.guestSysmonExe } else { Join-Path $guestDir 'Sysmon64.exe' }
$guestExeName = Split-Path -Leaf $guestExe
$hostExe = $null
if ($cfg.sysmon.hostSysmonExe) {
    $hostExe = if ([IO.Path]::IsPathRooted($cfg.sysmon.hostSysmonExe)) {
        $cfg.sysmon.hostSysmonExe
    } else {
        Join-Path $projectRoot ($cfg.sysmon.hostSysmonExe -replace '\\', [IO.Path]::DirectorySeparatorChar)
    }
}

if ($hostExe -and (Test-Path -LiteralPath $hostExe)) {
    Copy-QuarantineVMGuestFile -Path $hostExe -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Write-Host "Copied Sysmon binary to guest: $guestExeName"
} elseif (-not (Test-Path -LiteralPath $guestExe)) {
    foreach ($candidate in @(
        (Join-Path $projectRoot 'tools\Sysmon64.exe'),
        (Join-Path $projectRoot 'sysmon\Sysmon64.exe')
    )) {
        if (Test-Path -LiteralPath $candidate) {
            Copy-QuarantineVMGuestFile -Path $candidate -ConfigPath $ConfigPath -TargetDirectory $guestDir
            Write-Host "Copied Sysmon binary to guest from $candidate"
            break
        }
    }
}

if ($SysmonHostZip) {
    if (-not (Test-Path -LiteralPath $SysmonHostZip)) {
        throw "Sysmon zip not found: $SysmonHostZip"
    }
    Copy-QuarantineVMGuestFile -Path $SysmonHostZip -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Write-Host "Copied Sysmon zip to guest. Extract Sysmon64.exe to $guestDir on the guest if needed."
}

if ($SkipInstall) {
    Write-Host "Files copied to guest:$guestDir"
    Write-Host "Run as admin in guest: powershell -ExecutionPolicy Bypass -File $guestDir\Install-QuarantineSysmon.ps1"
    return
}

$guestExePath = Join-Path $guestDir $guestExeName
if (-not (Test-Path -LiteralPath $guestExePath)) {
    throw @"
Sysmon64.exe not found in guest after copy.

Place Sysmon64.exe on the host at one of:
  config sysmon.hostSysmonExe (e.g. tools\Sysmon64.exe)
  $projectRoot\tools\Sysmon64.exe

Then rerun: .\quarantine-vm.ps1 sysmon install
"@
}

$guestInstall = Join-Path $guestDir (Split-Path -Leaf $installScript)
$output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 180000 `
    -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -Command @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestInstall)

if ($output) { $output | ForEach-Object { Write-Host $_ } }
Write-Host 'Sysmon deploy complete. Take a Clean snapshot after verifying events in Event Viewer.'
