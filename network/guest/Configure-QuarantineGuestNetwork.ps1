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
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyOverride -Value "${ProxyHost};<local>"

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

# Strict outbound firewall: allow proxy + PAC + DNS first, then default-block.
# New-NetFirewallRule takes -Group (not -DisplayGroup; that is Get-NetFirewallRule only).
$groupName = 'Quarantine Lab Outbound'
$ruleNames = @(
    'Quarantine Allow Proxy',
    'Quarantine Allow PAC',
    'Quarantine Allow DNS',
    'Quarantine Allow DNS TCP'
)
foreach ($ruleName in $ruleNames) {
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

New-NetFirewallRule -DisplayName 'Quarantine Allow Proxy' -Name 'Quarantine-Allow-Proxy' -Group $groupName `
    -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $ProxyHost -RemotePort $ProxyPort | Out-Null
New-NetFirewallRule -DisplayName 'Quarantine Allow PAC' -Name 'Quarantine-Allow-PAC' -Group $groupName `
    -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $ProxyHost -RemotePort $PacPort | Out-Null
New-NetFirewallRule -DisplayName 'Quarantine Allow DNS' -Name 'Quarantine-Allow-DNS' -Group $groupName `
    -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DnsServer -RemotePort 53 | Out-Null
New-NetFirewallRule -DisplayName 'Quarantine Allow DNS TCP' -Name 'Quarantine-Allow-DNS-TCP' -Group $groupName `
    -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DnsServer -RemotePort 53 | Out-Null

Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Block -ErrorAction SilentlyContinue

# Trust the host mitmproxy CA so HTTPS works (download over HTTP, no TLS needed).
$caUrl = "http://${ProxyHost}:${PacPort}/mitmproxy-ca-cert.cer"
$caPath = Join-Path $env:TEMP 'mitmproxy-ca-cert.cer'
$caInstalled = $false
try {
    & curl.exe --noproxy '*' -fsSL $caUrl -o $caPath
    if (-not (Test-Path -LiteralPath $caPath) -or ((Get-Item -LiteralPath $caPath).Length -lt 32)) {
        throw "empty download from $caUrl"
    }
    Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    $caInstalled = $true
    Write-Host '  mitmproxy CA installed (Trusted Root)'
} catch {
    Write-Warning "Could not install mitmproxy CA from $caUrl. After the host proxy is up, run Install-QuarantineProxyCA.ps1"
}

Write-Host @'

Guest quarantine network configured.

Next steps:
  1. In this guest (Admin): Disable-QuarantineGuestUpdates.ps1
  2. Shut down this VM
  3. On the host: .\quarantine-vm.ps1 baseline   (freeze firewall + proxy + CA + no-WU into Clean)

Test from guest (after host enables quarantine network):
  - Internet HTTP(S) should work via proxy
  - ping 192.168.x.x should fail
'@
if (-not $caInstalled) {
    Write-Host '  If browsers show SSL errors, run Install-QuarantineProxyCA.ps1 as Admin.'
}
