#Requires -Version 5.1
<#
.SYNOPSIS
  Configure guest Windows for quarantine networking: system proxy, PAC, strict outbound firewall.
.DESCRIPTION
  Run inside the quarantine VM as Administrator (once after Windows install).
  Then shut down and run .\quarantine-vm.ps1 baseline on the host to freeze into Clean.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Configure-QuarantineGuestNetwork.ps1
#>
[CmdletBinding()]
param(
    [string]$ProxyHost = '10.0.2.2',
    [int]$ProxyPort = 8080,
    [int]$PacPort = 8081,
    [string]$DnsServer = '10.0.2.3'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'Run this script as Administrator inside the guest VM.'
}

$PacUrl = "http://${ProxyHost}:${PacPort}/quarantine.pac"
Write-Host "Configuring quarantine guest network..."
Write-Host "  PAC: $PacUrl"
Write-Host "  Proxy: ${ProxyHost}:${ProxyPort}"
Write-Host "  DNS: $DnsServer"

# System proxy + PAC (WinINET / system-wide for many apps)
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value "${ProxyHost}:${ProxyPort}"
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -Value $PacUrl
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyOverride -Value '<local>'

# Machine-level proxy (optional; helps services that read system policy)
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
if (-not (Test-Path -LiteralPath $policyPath)) {
    New-Item -Path $policyPath -Force | Out-Null
}
Set-ItemProperty -Path $policyPath -Name ProxySettingsPerUser -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value "${ProxyHost}:${ProxyPort}"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -Value $PacUrl

# DNS on active adapter (VirtualBox NAT default)
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
    Write-Host "  DNS set on adapter: $($adapter.Name)"
} else {
    Write-Warning 'No active network adapter found; set DNS manually to 10.0.2.3'
}

# Strict outbound firewall: default block, allow proxy + DNS only
$groupName = 'Quarantine Lab Outbound'
Get-NetFirewallRule -DisplayGroup $groupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Block -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName 'Quarantine Allow Proxy' -DisplayGroup $groupName `
    -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $ProxyHost -RemotePort $ProxyPort | Out-Null
New-NetFirewallRule -DisplayName 'Quarantine Allow DNS' -DisplayGroup $groupName `
    -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DnsServer -RemotePort 53 | Out-Null

Write-Host @'

Guest quarantine network configured.

Next steps on the HOST:
  1. Shut down this VM
  2. .\quarantine-vm.ps1 network quarantine   (or keep intnet for offline work)
  3. .\quarantine-vm.ps1 baseline             (freeze firewall + proxy into Clean)

Test from guest (after host enables quarantine network):
  - Internet HTTP(S) should work via proxy
  - ping 192.168.x.x should fail
'@
