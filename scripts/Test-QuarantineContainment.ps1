#Requires -Version 5.1
<#
.SYNOPSIS
  Host-side containment self-test for a Quarantine Lab install.

.DESCRIPTION
  Checks config isolation flags, gateway traffic mode, and (when VMs exist)
  basic VirtualBox state. This is a confidence check, not a proof of
  containment. See docs/THREAT_MODEL.md.

.EXAMPLE
  .\scripts\Test-QuarantineContainment.ps1
  .\scripts\Test-QuarantineContainment.ps1 -Strict
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $Root 'config\quarantine-vm.json'
}

$issues = New-Object System.Collections.Generic.List[string]
$notes = New-Object System.Collections.Generic.List[string]

function Add-Issue([string]$Message) { [void]$issues.Add($Message) }
function Add-Note([string]$Message) { [void]$notes.Add($Message) }

Write-Host '==> Quarantine Lab containment self-test' -ForegroundColor Cyan
Write-Host 'VirtualBox is the primary escape boundary. This check cannot prove isolation.' -ForegroundColor Yellow

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath (copy config\quarantine-vm.example.json first)"
}

$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$iso = $cfg.isolation
if ($iso) {
    if ($iso.disableDragDrop -ne $true) { Add-Issue 'isolation.disableDragDrop should be true' }
    if ($iso.disableUsb -ne $true) { Add-Issue 'isolation.disableUsb should be true' }
    if ($iso.disableSharedFolders -ne $true) { Add-Issue 'isolation.disableSharedFolders should be true (inbox is temporary)' }
    $clip = [string]$iso.clipboardMode
    if ($iso.disableClipboard -eq $true -or $clip -eq 'disabled' -or [string]::IsNullOrWhiteSpace($clip)) {
        Add-Note 'Clipboard disabled (default; host-to-guest paste needs -GuestAdditions)'
    } elseif ($clip -ne 'hosttoguest') {
        Add-Issue "Clipboard mode is '$clip'; prefer disabled (default) or hosttoguest with -GuestAdditions"
    } else {
        Add-Note 'Residual surface: host-to-guest clipboard is enabled (Guest Additions fallback)'
    }
} else {
    Add-Issue 'isolation section missing from config'
}

$inbox = $cfg.inbox
if ($inbox -and $inbox.readOnly -ne $true) {
    Add-Issue 'inbox.readOnly should be true'
} else {
    Add-Note 'Inbox: agent copies samples to C:\Users\Public\Quarantine\inbox (VBOXSVR only with -GuestAdditions)'
}

$gw = $null
if ($cfg.network -and $cfg.network.gateway) { $gw = $cfg.network.gateway }
$mode = if ($cfg.network) { [string]$cfg.network.mode } else { '' }
if ($mode -and $mode -ne 'gateway') {
    Add-Issue "network.mode is '$mode'; analysis path should be gateway"
}
$traffic = if ($gw) { [string]$gw.trafficMode } else { '' }
if (-not $traffic) { $traffic = 'fakenet' }
if ($traffic -eq 'permissive') {
    Add-Note 'Gateway trafficMode=permissive — controlled WAN is intentional; this is not FakeNet'
} elseif ($traffic -ne 'fakenet') {
    Add-Issue "Unexpected gateway.trafficMode '$traffic' (expected fakenet or permissive)"
} else {
    Add-Note 'FakeNet mode: guest should not have real WAN'
}

$payload = if ($cfg.payload) { [string]$cfg.payload.username } else { 'analyst' }
Add-Note "Do not use personal accounts in the guest. Payload user in config: $payload"

$module = Join-Path $Root 'QuarantineVM.psm1'
if (Test-Path -LiteralPath $module) {
    Import-Module $module -Force
    try {
        Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
        $guestName = [string]$cfg.vmName
        $gwName = if ($gw) { [string]$gw.vmName } else { 'Quarantine-Gateway' }
        foreach ($pair in @(@{ n = $guestName; label = 'Windows guest' }, @{ n = $gwName; label = 'Gateway' })) {
            if (-not $pair.n) { continue }
            try {
                $state = Get-QuarantineVMState -VmName $pair.n
                Write-Host ("  {0} ({1}): {2}" -f $pair.label, $pair.n, $state)
            } catch {
                Add-Note ("{0} VM '{1}' not found yet — create it during quick start" -f $pair.label, $pair.n)
                if ($Strict) { Add-Issue ("{0} VM missing: {1}" -f $pair.label, $pair.n) }
            }
        }
    } catch {
        Add-Note "Could not query VirtualBox state: $($_.Exception.Message)"
        if ($Strict) { Add-Issue $_.Exception.Message }
    }
}

$sysmon = Join-Path $Root 'tools\Sysmon64.exe'
if (Test-Path -LiteralPath $sysmon) {
    Write-Host "  Sysmon host binary: $sysmon"
} else {
    Add-Note 'tools\Sysmon64.exe missing — run .\scripts\Get-Sysmon.ps1'
    if ($Strict) { Add-Issue 'Sysmon64.exe not downloaded' }
}

Write-Host ''
Write-Host 'Notes:' -ForegroundColor Cyan
$notes | ForEach-Object { Write-Host "  - $_" }

if ($issues.Count -gt 0) {
    Write-Host ''
    Write-Host 'Issues:' -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    exit 1
}

Write-Host ''
Write-Host 'Containment self-test passed (config checks). Run .\Invoke-QuarantineLabSmokeTest.ps1 with the guest up for guest markers.' -ForegroundColor Green
Write-Host 'Next: create CleanSession, then launch an analysis. See README Quick start.'
