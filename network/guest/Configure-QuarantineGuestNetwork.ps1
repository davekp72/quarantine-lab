#Requires -Version 5.1
<#
.SYNOPSIS
  Configure guest Windows for quarantine networking: system proxy, PAC, strict outbound firewall.
.DESCRIPTION
  Run inside the quarantine VM as Administrator (once after Windows install).
  Then shut down and run .\quarantine-vm.ps1 baseline on the host to freeze into Clean.

  Modes:
    host-nat (default) — VirtualBox NAT + host mitmproxy at 10.0.2.2
    gateway            — Linux gateway on intnet (static 10.66.0.15, GW/DNS 10.66.0.1)

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Configure-QuarantineGuestNetwork.ps1
  powershell -ExecutionPolicy Bypass -File .\Configure-QuarantineGuestNetwork.ps1 -Mode gateway
#>
[CmdletBinding()]
param(
    [ValidateSet('host-nat', 'gateway')]
    [string]$Mode = 'host-nat',

    [string]$ProxyHost = '',
    [int]$ProxyPort = 8080,
    [int]$PacPort = 8080,
    [string]$DnsServer = '',
    [string]$GuestIP = '',
    [string]$GatewayIP = '',
    [string]$PrefixLength = '24'
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

if ($Mode -eq 'gateway') {
    if (-not $ProxyHost) { $ProxyHost = '10.66.0.1' }
    if (-not $DnsServer) { $DnsServer = '10.66.0.1' }
    if (-not $GatewayIP) { $GatewayIP = '10.66.0.1' }
    if (-not $GuestIP) { $GuestIP = '10.66.0.15' }
    # PAC is served by gateway mitm on the same listen port as explicit proxy.
    if ($PacPort -le 0) { $PacPort = $ProxyPort }
} else {
    if (-not $ProxyHost) { $ProxyHost = '10.0.2.2' }
    if (-not $DnsServer) { $DnsServer = '10.0.2.3' }
    if ($PSBoundParameters.ContainsKey('PacPort') -eq $false -and $PacPort -eq 8080) {
        $PacPort = 8081
    }
}

$PacUrl = "http://${ProxyHost}:${PacPort}/quarantine.pac"
Write-Host "Configuring quarantine guest network ($Mode)..."
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

$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if ($adapter) {
    if ($Mode -eq 'gateway' -and $GuestIP -and $GatewayIP) {
        Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -ne $GuestIP } |
            ForEach-Object {
                Remove-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $_.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }
        Remove-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $GuestIP -PrefixLength ([int]$PrefixLength) -DefaultGateway $GatewayIP -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  Static IP $GuestIP/$PrefixLength gateway $GatewayIP on $($adapter.Name)"
    }
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
    Write-Host "  DNS set on adapter: $($adapter.Name)"
} else {
    Write-Warning 'No active network adapter found; configure IP/DNS manually.'
}

# Strict outbound firewall
$groupName = 'Quarantine Lab Outbound'
$ruleNames = @(
    'Quarantine Allow Proxy',
    'Quarantine Allow PAC',
    'Quarantine Allow DNS',
    'Quarantine Allow DNS TCP',
    'Quarantine Allow Gateway Any',
    'Quarantine Allow HTTP',
    'Quarantine Allow HTTPS'
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

if ($Mode -eq 'gateway') {
    # Transparent MITM: allow HTTP/HTTPS to internet via gateway (nftables REDIRECT on gateway).
    New-NetFirewallRule -DisplayName 'Quarantine Allow HTTP' -Name 'Quarantine-Allow-HTTP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80 | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow HTTPS' -Name 'Quarantine-Allow-HTTPS' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow Gateway Any' -Name 'Quarantine-Allow-Gateway-Any' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol Any -RemoteAddress $GatewayIP | Out-Null
}

Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Block -ErrorAction SilentlyContinue

# Trust mitm CA (download over HTTP from PAC/proxy port)
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
    Write-Warning "Could not install mitmproxy CA from $caUrl. After the gateway/proxy is up, run Install-QuarantineProxyCA.ps1"
}

Write-Host @"

Guest quarantine network configured ($Mode).

Next steps:
  1. In this guest (Admin): Disable-QuarantineGuestUpdates.ps1
  2. Shut down this VM
  3. On the host: .\quarantine-vm.ps1 baseline

Test from guest:
  - Internet HTTP(S) should work (transparent MITM in gateway mode, or PAC in host-nat)
  - ping 192.168.x.x should fail (blocked on gateway/host policy)
"@
if (-not $caInstalled) {
    Write-Host '  If browsers show SSL errors, run Install-QuarantineProxyCA.ps1 as Admin.'
}
