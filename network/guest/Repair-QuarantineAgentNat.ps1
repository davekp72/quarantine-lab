#Requires -Version 5.1
<#
.SYNOPSIS
  Repair VBox NAT NIC so host agent port-forward (127.0.0.1:9443) works in gateway dual-NIC mode.
.DESCRIPTION
  Sets static 10.0.2.15/24 on the second/up NAT-like adapter with no default route,
  allows DHCP outbound, and restarts QuarantineLabAgent.
  Run elevated inside the lab guest.
#>
[CmdletBinding()]
param(
    [string]$NatIP = '10.0.2.15',
    [int]$NatPrefix = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run as Administrator inside the guest VM.'
}

$up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object ifIndex)
if ($up.Count -lt 2) {
    throw "Need dual-NIC (intnet+NAT); found $($up.Count) Up adapter(s)."
}

# VBox NIC2 is usually the higher ifIndex; prefer adapter with APIPA or 10.0.2.x / not 10.66.x
$nat = $null
foreach ($a in $up) {
    $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty IPAddress)
    if ($ips | Where-Object { $_ -like '10.0.2.*' -or $_ -like '169.254.*' }) {
        $nat = $a
        break
    }
}
if (-not $nat) {
    $nat = $up | Where-Object {
        $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty IPAddress)
        -not ($ips | Where-Object { $_ -like '10.66.*' })
    } | Select-Object -First 1
}
if (-not $nat) { $nat = $up[-1] }

Write-Host "Repairing NAT adapter $($nat.Name) (ifIndex=$($nat.ifIndex)) -> $NatIP/$NatPrefix"

Set-NetIPInterface -InterfaceIndex $nat.ifIndex -Dhcp Disabled -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceIndex $nat.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    ForEach-Object {
        Remove-NetIPAddress -InterfaceIndex $nat.ifIndex -IPAddress $_.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
Remove-NetRoute -InterfaceIndex $nat.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $nat.ifIndex -IPAddress $NatIP -PrefixLength $NatPrefix -ErrorAction SilentlyContinue | Out-Null
Set-NetIPInterface -InterfaceIndex $nat.ifIndex -InterfaceMetric 5000 -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceIndex $nat.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue

Get-NetFirewallRule -DisplayName 'Quarantine Allow DHCP' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Quarantine Allow DHCP' -Name 'Quarantine-Allow-DHCP' -Group 'Quarantine Lab Outbound' `
    -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68 | Out-Null

Restart-Service -Name QuarantineLabAgent -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
sc.exe query QuarantineLabAgent | Out-Host
Get-NetIPAddress -InterfaceIndex $nat.ifIndex -AddressFamily IPv4 |
    Select-Object IPAddress, PrefixLength | Format-Table | Out-Host
Write-Host 'Done. On host: .\quarantine-vm.ps1 agent health'
