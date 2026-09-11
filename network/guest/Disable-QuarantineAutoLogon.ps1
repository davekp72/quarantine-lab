#Requires -Version 5.1
<#
.SYNOPSIS
  Disable Windows administrator autologon before taking the Clean baseline.
.DESCRIPTION
  Unattended setup may log on once (AutoLogonCount=1). Run this elevated in the
  guest before .\quarantine-vm.ps1 baseline so the frozen image does not store
  a plaintext DefaultPassword.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '0' -Type String
Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $winlogon -Name AutoLogonCount -ErrorAction SilentlyContinue
Write-Host 'AutoLogon disabled (AutoAdminLogon=0, DefaultPassword removed).'
