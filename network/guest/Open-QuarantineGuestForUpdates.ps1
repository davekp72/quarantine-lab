#Requires -Version 5.1
<#
.SYNOPSIS
  Temporarily open the guest so Windows Update can run on raw NAT.
.DESCRIPTION
  Host must already be: .\quarantine-vm.ps1 network nat

  The quarantine guest firewall (default-block) and system proxy stay in
  place after the host NIC is switched to NAT. This script undoes those
  so Windows Update can go direct to Microsoft.

  After updates finish, re-lock the guest:
    Configure-QuarantineGuestNetwork.ps1
    Disable-QuarantineGuestUpdates.ps1
    Install-QuarantineProxyCA.ps1   (if HTTPS via proxy is still needed)
  Then on the host: .\quarantine-vm.ps1 network quarantine
#>
[CmdletBinding()]
param()

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

Write-Host 'Opening guest for Windows Update (raw NAT)...'

Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow
Write-Host '  Firewall default outbound: Allow'

$inetPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
)
foreach ($path in $inetPaths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    Set-ItemProperty -Path $path -Name ProxyEnable -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $path -Name ProxyServer -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $path -Name AutoConfigURL -ErrorAction SilentlyContinue
}

$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
if (Test-Path -LiteralPath $policyPath) {
    Remove-ItemProperty -Path $policyPath -Name ProxySettingsPerUser -ErrorAction SilentlyContinue
}
Write-Host '  System proxy cleared'

& netsh.exe winhttp reset proxy | Out-Null
Write-Host '  WinHTTP proxy reset'

$wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if (Test-Path -LiteralPath $wuPolicy) {
    Remove-Item -LiteralPath $wuPolicy -Recurse -Force
    Write-Host '  Windows Update policy removed'
}

foreach ($name in @('wuauserv', 'UsoSvc', 'DoSvc', 'WaaSMedicSvc', 'BITS')) {
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if (Test-Path -LiteralPath $svcKey) {
        $defaultStart = if ($name -eq 'WaaSMedicSvc') { 3 } else { 2 }
        Set-ItemProperty -Path $svcKey -Name Start -Value $defaultStart -Type DWord -ErrorAction SilentlyContinue
    }
    try {
        Set-Service -Name $name -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name $name -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not start ${name}: $_"
    }
}
Write-Host '  Update services re-enabled'

$taskPaths = @('\Microsoft\Windows\WindowsUpdate\', '\Microsoft\Windows\UpdateOrchestrator\')
foreach ($taskPath in $taskPaths) {
    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
        ForEach-Object {
            Enable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null
        }
}

Write-Host @'

Guest is open for updates. Settings > Windows Update > Check for updates.

When finished, re-lock the guest (Admin):
  Configure-QuarantineGuestNetwork.ps1
  Disable-QuarantineGuestUpdates.ps1

Then on the host:
  .\quarantine-vm.ps1 stop
  .\quarantine-vm.ps1 network quarantine
  .\quarantine-vm.ps1 baseline
'@
