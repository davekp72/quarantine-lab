#Requires -Version 5.1
<#
.SYNOPSIS
  Copy Sysmon config + binaries to the guest. Apply config manually in elevated guest PowerShell (one-time).
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$SysmonHostZip,
    [switch]$ShowGuestInstructions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not (Get-Command Copy-QuarantineVMGuestFile -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $projectRoot 'QuarantineVM.psm1')
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

function Write-QuarantineSysmonGuestInstructions {
    param(
        [Parameter(Mandatory)][string]$GuestDir,
        [Parameter(Mandatory)][string]$GuestConfigName
    )

    $guestExe = Join-Path $guestDir 'Sysmon64.exe'
    $guestConfig = Join-Path $guestDir $GuestConfigName
    $guestInstall = Join-Path $guestDir 'Install-QuarantineSysmon.ps1'

    Write-Host ''
    Write-Host 'Next: one-time step in the guest (elevated PowerShell / Administrator):'
    Write-Host ''
    Write-Host "  & '$guestExe' -c '$guestConfig'"
    Write-Host ''
    Write-Host 'If Sysmon is not installed yet, use the installer script instead:'
    Write-Host ''
    Write-Host "  & '$guestInstall'"
    Write-Host ''
    Write-Host 'Verify:'
    Write-Host '  Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5'
    Write-Host ''
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
$guestConfigName = if ($cfg.sysmon.PSObject.Properties['guestConfigName']) { [string]$cfg.sysmon.guestConfigName } else { 'quarantine-lab.xml' }
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
$fallbackConfig = Join-Path $projectRoot 'config\sysmon\quarantine-lab-fallback.xml'
if (Test-Path -LiteralPath $fallbackConfig) {
    Copy-QuarantineVMGuestFile -Path $fallbackConfig -ConfigPath $ConfigPath -TargetDirectory $guestDir
}

$hostSysmonExeRel = if ($cfg.sysmon.PSObject.Properties['hostSysmonExe']) { [string]$cfg.sysmon.hostSysmonExe } else { '' }
$hostExe = $null
if ($hostSysmonExeRel) {
    $hostExe = if ([IO.Path]::IsPathRooted($hostSysmonExeRel)) {
        $hostSysmonExeRel
    } else {
        Join-Path $projectRoot ($hostSysmonExeRel -replace '\\', [IO.Path]::DirectorySeparatorChar)
    }
}

$binaryCopied = $false
if ($hostExe -and (Test-Path -LiteralPath $hostExe)) {
    Copy-QuarantineVMGuestFile -Path $hostExe -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Write-Host "Copied Sysmon binary to guest from $hostExe"
    $binaryCopied = $true
} else {
    foreach ($candidate in @(
        (Join-Path $projectRoot 'tools\Sysmon64.exe'),
        (Join-Path $projectRoot 'sysmon\Sysmon64.exe')
    )) {
        if (Test-Path -LiteralPath $candidate) {
            Copy-QuarantineVMGuestFile -Path $candidate -ConfigPath $ConfigPath -TargetDirectory $guestDir
            Write-Host "Copied Sysmon binary to guest from $candidate"
            $binaryCopied = $true
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

if (-not $binaryCopied) {
    Write-Warning "Sysmon64.exe was not copied from the host. Place tools\Sysmon64.exe on the host or copy Sysmon64.exe to $guestDir in the guest."
}

Write-Host "Sysmon files copied to guest: $guestDir"

if ($ShowGuestInstructions) {
    Write-QuarantineSysmonGuestInstructions -GuestDir $guestDir -GuestConfigName $guestConfigName
}
