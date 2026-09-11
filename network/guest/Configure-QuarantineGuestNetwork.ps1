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
    host-nat          — retired. Do not use; always configure gateway.

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
if ($Mode -eq 'host-nat') {
    throw 'host-nat mitm is retired. Use -Mode gateway.'
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegStringProp {
    param(
        [string]$Path,
        [string]$Name
    )
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $obj = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $obj) { return $null }
    $prop = $obj.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    $val = $prop.Value
    if ([string]::IsNullOrWhiteSpace([string]$val)) { return $null }
    return [string]$val
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
$payloadUser = 'analyst'
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
    $profilePath = Get-RegStringProp -Path "Registry::$($hive.Name)\Volatile Environment" -Name 'USERPROFILE'
    if (-not $profilePath) {
        $profilePath = Get-RegStringProp -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name 'ProfileImagePath'
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
    # Always re-assert default route. New-NetIPAddress -DefaultGateway is a no-op when the
    # address already exists — which left the guest with 10.66.0.15 and no 0.0.0.0/0
    # ("PING: transmit failed. General failure" to anything off-link).
    Remove-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
    $haveIp = Get-NetIPAddress -InterfaceIndex $lan.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $GuestIP }
    if (-not $haveIp) {
        New-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $GuestIP -PrefixLength ([int]$PrefixLength) -DefaultGateway $GatewayIP -ErrorAction Stop | Out-Null
    } else {
        New-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop $GatewayIP -RouteMetric 10 -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $GatewayIP })) {
            Remove-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $GuestIP -Confirm:$false -ErrorAction SilentlyContinue
            New-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $GuestIP -PrefixLength ([int]$PrefixLength) -DefaultGateway $GatewayIP -ErrorAction Stop | Out-Null
        }
    }
    if (-not (Get-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $GatewayIP })) {
        throw "Failed to set default gateway $GatewayIP on $($lan.Name)"
    }
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
# Gateway mode: look like a normal routed network to the guest. Public ICMP/TCP/UDP
# (ping, SMTP, SSH, etc.) are allowed and show up in LAN PCAP. Private/host-LAN
# destinations are blocked on the Linux gateway (nftables + mitm), not here.
# host-nat mode: keep default-deny and only allow proxy/DNS (legacy).
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
    'Quarantine Allow Internet',
    'Quarantine Allow Internet TCP',
    'Quarantine Allow Internet UDP',
    'Quarantine Allow ICMP',
    'Quarantine Block Gateway SSH'
)
foreach ($ruleName in $ruleNames) {
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
# Also remove by -Name for rules that may only exist under Name=
foreach ($ruleName in @(
    'Quarantine-Allow-Proxy', 'Quarantine-Allow-PAC', 'Quarantine-Allow-DNS',
    'Quarantine-Allow-DNS-TCP', 'Quarantine-Allow-DHCP', 'Quarantine-Allow-Gateway-Any',
    'Quarantine-Allow-Agent-In', 'Quarantine-Allow-HTTP', 'Quarantine-Allow-HTTPS',
    'Quarantine-Allow-Internet', 'Quarantine-Allow-Internet-TCP', 'Quarantine-Allow-Internet-UDP',
    'Quarantine-Allow-ICMP', 'Quarantine-Block-Gateway-SSH'
)) {
    Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue |
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
    # Normal internet from the guest's point of view (routed via gateway).
    # HTTP/HTTPS still hit transparent MITM on the gateway; other ports are passthrough + PCAP.
    # Avoid -Protocol Any (unreliable on some builds); allow TCP/UDP/ICMP explicitly.
    New-NetFirewallRule -DisplayName 'Quarantine Allow Internet TCP' -Name 'Quarantine-Allow-Internet-TCP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow Internet UDP' -Name 'Quarantine-Allow-Internet-UDP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol UDP -Profile Any | Out-Null
    # Echo Request (ping). -IcmpType 8 = echo-request.
    New-NetFirewallRule -DisplayName 'Quarantine Allow ICMP' -Name 'Quarantine-Allow-ICMP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
    # Do not allow SSH onto the gateway appliance itself (escape foothold).
    New-NetFirewallRule -DisplayName 'Quarantine Block Gateway SSH' -Name 'Quarantine-Block-Gateway-SSH' -Group $groupName `
        -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $GatewayIP -RemotePort 22 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'Quarantine Allow Agent In' -Name 'Quarantine-Allow-Agent-In' -Group $groupName `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9443 -RemoteAddress $GatewayIP -Profile Any | Out-Null

    # Ensure built-in Core Networking echo rules are on (helps some Win builds).
    Get-NetFirewallRule -DisplayGroup 'Core Networking' -Direction Outbound -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Echo Request' } |
        Enable-NetFirewallRule -ErrorAction SilentlyContinue

    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow -ErrorAction Stop
    $profiles = Get-NetFirewallProfile -Profile Domain, Public, Private |
        Select-Object -ExpandProperty DefaultOutboundAction
    Write-Host "  Firewall: outbound default Allow (profiles: $($profiles -join ', ')); ICMP/TCP/UDP allowed; gateway SSH blocked"
} else {
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Block -ErrorAction Stop
}
# Trust mitm CA (HTTP from FakeNet :80 or permissive MITM :8080)
$caUrls = @(
    "http://${ProxyHost}/mitmproxy-ca-cert.cer",
    "http://${ProxyHost}:${PacPort}/mitmproxy-ca-cert.cer",
    "http://${ProxyHost}:${ProxyPort}/mitmproxy-ca-cert.cer"
)
$caPath = Join-Path $env:TEMP 'mitmproxy-ca-cert.cer'
$caInstalled = $false
foreach ($caUrl in $caUrls) {
    try {
        & curl.exe --noproxy '*' --http1.1 -fsSL --max-time 15 $caUrl -o $caPath
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $caPath) -or ((Get-Item -LiteralPath $caPath).Length -lt 32)) {
            continue
        }
        $parsed = $null
        try {
            $parsed = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
        } catch {
            continue
        }
        if (-not $parsed) { continue }
        Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        $caInstalled = $true
        Write-Host "  mitmproxy CA installed (Trusted Root) from $caUrl"
        Write-Host ("    {0} thumbprint {1}" -f $parsed.Subject, $parsed.Thumbprint)
        break
    } catch {
        continue
    }
}
if (-not $caInstalled) {
    Write-Warning "Could not install mitmproxy CA from FakeNet/MITM HTTP. After the gateway is up, run Install-QuarantineProxyCA.ps1"
}

Write-Host @"

Guest quarantine network configured ($Mode).

Next steps:
  1. In this guest (Admin): Disable-QuarantineGuestUpdates.ps1
  2. Shut down this VM
  3. On the host: .\quarantine-vm.ps1 baseline

Test from guest (gateway mode):
  - ping 1.1.1.1 / SSH or SMTP to public hosts should work (PCAP on gateway)
  - HTTP(S) works via transparent MITM
  - ping/SSH to 192.168.x.x or other private nets should fail (gateway policy)
  - SSH to the gateway itself ($GatewayIP:22) should fail
"@
if ($Mode -eq 'gateway') {
    Restart-Service -Name QuarantineLabAgent -ErrorAction SilentlyContinue
    Write-Host '  Restarted QuarantineLabAgent (if installed).'
}
if (-not $caInstalled) {
    Write-Host '  If browsers show SSL errors, run Install-QuarantineProxyCA.ps1 as Admin.'
}
