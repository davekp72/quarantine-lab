#Requires -Version 5.1
<#
.SYNOPSIS
  FirstLogon bootstrap while signed in as built-in Administrator.

.DESCRIPTION
  Lab guest control uses RID 500 Administrator (always elevated). This script
  keeps that account enabled and runs Invoke-QuarantineFirstLogon.ps1.
  It does not create or switch to another local admin username.
#>
[CmdletBinding()]
param(
    [string]$LabAdmin = 'Administrator',
    [string]$LabPassword = '__GUEST_PASSWORD__',
    [string]$PublicDir = 'C:\Users\Public\Quarantine'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Public\finish-labadmin.log'

function Write-LabLog([string]$Message) {
    $line = '{0} {1}' -f (Get-Date -Format 'o'), $Message
    Write-Host $line
    try { Add-Content -LiteralPath $log -Value $line -Encoding UTF8 } catch { }
}

Write-LabLog ("Finish-LabAdmin start user={0}" -f $env:USERNAME)

try {
    & net.exe user Administrator /active:yes | ForEach-Object { Write-LabLog $_ }
} catch { Write-LabLog $_ }

# Ensure AutoLogon stays on Administrator for a few logons (guestcontrol / GA install).
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
try {
    New-Item -Path $winlogon -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name 'AutoAdminLogon' -PropertyType String -Value '1' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name 'DefaultUserName' -PropertyType String -Value 'Administrator' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name 'DefaultPassword' -PropertyType String -Value $LabPassword -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name 'DefaultDomainName' -PropertyType String -Value '.' -Force | Out-Null
    New-ItemProperty -Path $winlogon -Name 'AutoLogonCount' -PropertyType DWord -Value 3 -Force | Out-Null
    Write-LabLog 'Winlogon AutoAdminLogon kept on Administrator'
} catch {
    Write-LabLog ("Winlogon AutoAdminLogon failed: " + $_.Exception.Message)
}

$first = Join-Path $PSScriptRoot 'Invoke-QuarantineFirstLogon.ps1'
if (-not (Test-Path -LiteralPath $first)) {
    foreach ($root in @('A:\', 'D:\', 'E:\', 'F:\')) {
        $probe = Join-Path $root 'Invoke-QuarantineFirstLogon.ps1'
        if (Test-Path -LiteralPath $probe) { $first = $probe; break }
        $probe = Join-Path $root 'Quarantine\Invoke-QuarantineFirstLogon.ps1'
        if (Test-Path -LiteralPath $probe) { $first = $probe; break }
    }
}
if (Test-Path -LiteralPath $first) {
    Write-LabLog "Running $first"
    try {
        & $first -LabAdmin $LabAdmin -PublicDir $PublicDir
    } catch {
        Write-LabLog ("FirstLogon script error: " + $_.Exception.Message)
    }
} else {
    Write-LabLog 'Invoke-QuarantineFirstLogon.ps1 not found on media'
}

Write-LabLog 'Finish-LabAdmin done (staying on Administrator — no reboot to another user)'
