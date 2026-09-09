#Requires -Version 5.1
<#
.SYNOPSIS
  Configure guest Windows for quarantine networking: system proxy, PAC, strict outbound firewall.
.DESCRIPTION
  Run inside the quarantine VM as Administrator (once after Windows install).
  Then shut down and run .\quarantine-vm.ps1 baseline on the host to freeze into Clean.

  Modes:
    gateway (default) — Linux gateway on intnet (static 10.66.0.15, GW/DNS 10.66.0.1).
                         Host reaches the guest agent via the gateway (no lab NAT NIC).
    host-nat          — legacy VirtualBox NAT + host mitmproxy at 10.0.2.2 (prefer gateway).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Configure-QuarantineGuestNetwork.ps1 -Mode gateway
#>
[CmdletBinding()]
param(
    [ValidateSet('host-nat', 'gateway')]
    [string]$Mode = 'gateway',

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
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyOverride -Value "${ProxyHost};<local>"

# WinHTTP (many services ignore WinINET)
& netsh.exe winhttp set proxy "proxy-server=${ProxyHost}:${ProxyPort}" "bypass-list=${ProxyHost};<local>" | Out-Null
Write-Host '  WinHTTP proxy set'

# Patch payload / other interactive user hives so standard users get PAC (not only Admin HKCU)
$payloadUser = 'jkcooper'
$configPayload = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\quarantine-vm.json'
if (Test-Path -LiteralPath $configPayload) {
    try {
        $cfgUser = (Get-Content -LiteralPath $configPayload -Raw | ConvertFrom-Json).payload.username
        if ($cfgUser) { $payloadUser = [string]$cfgUser }
    } catch { }
}
foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
    $sid = $hive.PSChildName
    if ($sid -notmatch '^S-1-5-21-' -or $sid -match '_Classes$') { continue }
    $profilePath = (Get-ItemProperty -LiteralPath "Registry::$($hive.Name)\Volatile Environment" -ErrorAction SilentlyContinue).USERPROFILE
    if (-not $profilePath) {
        $profilePath = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath
    }
    if (-not $profilePath) { continue }
    $leaf = Split-Path -Leaf $profilePath
    if ($leaf -notin @($payloadUser, $env:USERNAME)) { continue }
    $inet = "Registry::$($hive.Name)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (-not (Test-Path -LiteralPath $inet)) { New-Item -Path $inet -Force | Out-Null }
    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 1 -Type DWord
    Set-ItemProperty -Path $inet -Name ProxyServer -Value "${ProxyHost}:${ProxyPort}"
    Set-ItemProperty -Path $inet -Name AutoConfigURL -Value $PacUrl
    Set-ItemProperty -Path $inet -Name ProxyOverride -Value "${ProxyHost};<local>"
    Write-Host "  WinINET proxy set for loaded user $leaf"
}

$upAdapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object ifIndex)
if ($upAdapters.Count -eq 0) {
    Write-Warning 'No active network adapter found; configure IP/DNS manually.'
	} elseif ($Mode -eq 'gateway' -and $GuestIP -and $GatewayIP) {
    $lan = $upAdapters | Where-Object {
        $ips = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty IPAddress)
        ($ips | Where-Object { $_ -eq $GuestIP -or $_ -like '10.66.*' })
    } | Select-Object -First 1
    if (-not $lan) { $lan = $upAdapters[0] }

    Get-NetIPAddress -InterfaceIndex $lan.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $GuestIP } |
        ForEach-Object {
            Remove-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $_.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }
    Remove-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $GuestIP -PrefixLength ([int]$PrefixLength) -DefaultGateway $GatewayIP -ErrorAction SilentlyContinue | Out-Null
    Set-NetIPInterface -InterfaceIndex $lan.ifIndex -InterfaceMetric 10 -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex $lan.ifIndex -ServerAddresses $DnsServer
    Write-Host "  LAN (intnet): static $GuestIP/$PrefixLength gw $GatewayIP metric 10 on $($lan.Name)"

    foreach ($extra in $upAdapters) {
        if ($extra.ifIndex -eq $lan.ifIndex) { continue }
        Remove-NetRoute -InterfaceIndex $extra.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $extra.ifIndex -InterfaceMetric 5000 -ErrorAction SilentlyContinue
        Write-Host "  Extra adapter $($extra.Name): metric 5000, no default route (unused in gateway mode)"
    }
} else {
    $adapter = $upAdapters[0]
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
    Write-Host "  DNS set on adapter: $($adapter.Name)"
}

# Strict outbound firewall
$groupName = 'Quarantine Lab Outbound'
$ruleNames = @(
    'Quarantine Allow Proxy',
    'Quarantine Allow PAC',
    'Quarantine Allow DNS',
    'Quarantine Allow DNS TCP',
    'Quarantine Allow DHCP',
    'Quarantine Allow Gateway Any',
    'Quarantine Allow Agent In',
    'Quarantine Allow HTTP',
    'Quarantine Allow HTTPS',
    'Quarantine Block Gateway SSH'
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
# DHCP (needed if NAT ever falls back to DHCP instead of static 10.0.2.15)
New-NetFirewallRule -DisplayName 'Quarantine Allow DHCP' -Name 'Quarantine-Allow-DHCP' -Group $groupName `
    -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68 | Out-Null

if ($Mode -eq 'gateway') {
    # Transparent MITM: allow HTTP/HTTPS to internet via gateway (nftables REDIRECT on gateway).
    New-NetFirewallRule -DisplayName 'Quarantine Allow HTTP' -Name 'Quarantine-Allow-HTTP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80 | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow HTTPS' -Name 'Quarantine-Allow-HTTPS' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 | Out-Null
    # Do not allow unrestricted access to the gateway IP (that exposed sshd).
    New-NetFirewallRule -DisplayName 'Quarantine Block Gateway SSH' -Name 'Quarantine-Block-Gateway-SSH' -Group $groupName `
        -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $GatewayIP -RemotePort 22 | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow Agent In' -Name 'Quarantine-Allow-Agent-In' -Group $groupName `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9443 -RemoteAddress $GatewayIP | Out-Null
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
if ($Mode -eq 'gateway') {
    Restart-Service -Name QuarantineLabAgent -ErrorAction SilentlyContinue
    Write-Host '  Restarted QuarantineLabAgent (if installed).'
}
if (-not $caInstalled) {
    Write-Host '  If browsers show SSL errors, run Install-QuarantineProxyCA.ps1 as Admin.'
}
