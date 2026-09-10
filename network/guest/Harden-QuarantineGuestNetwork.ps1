#Requires -Version 5.1
<#
.SYNOPSIS
  Harden guest quarantine networking gaps: default gateway, jkcooper WinINET proxy, WinHTTP proxy.
.DESCRIPTION
  Run as Administrator inside the guest (UAC elevate in the VM GUI if needed).
  Does not rely on host-driven privilege escalation.

  Fixes:
    - Missing default gateway (10.66.0.1)
    - Payload user (jkcooper) HKCU ProxyEnable=0
    - WinHTTP left on "Direct access"
    - Over-broad "Quarantine Allow Gateway Any" (allows SSH to gateway)

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\Users\Public\Quarantine\Harden-QuarantineGuestNetwork.ps1 -Mode gateway
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
    [string]$PrefixLength = '24',

    # Also patch this user's loaded hive / NTUSER.DAT (payload account).
    [string]$PayloadUser = 'jkcooper'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-WinInetProxyAtPath {
    param(
        [Parameter(Mandatory)][string]$RootPath,
        [Parameter(Mandatory)][string]$ProxyServer,
        [Parameter(Mandatory)][string]$PacUrl,
        [Parameter(Mandatory)][string]$ProxyOverride
    )
    if (-not (Test-Path -LiteralPath $RootPath)) {
        New-Item -Path $RootPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RootPath -Name ProxyEnable -Value 1 -Type DWord
    Set-ItemProperty -Path $RootPath -Name ProxyServer -Value $ProxyServer
    Set-ItemProperty -Path $RootPath -Name AutoConfigURL -Value $PacUrl
    Set-ItemProperty -Path $RootPath -Name ProxyOverride -Value $ProxyOverride
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

function Set-PayloadUserWinInetProxy {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ProxyServer,
        [Parameter(Mandatory)][string]$PacUrl,
        [Parameter(Mandatory)][string]$ProxyOverride
    )
    $inetRel = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $patched = $false

    # Currently loaded profile (jkcooper logged in).
    foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $hive.PSChildName
        if ($sid -notmatch '^S-1-5-21-' -or $sid -match '_Classes$') { continue }

        $profilePath = Get-RegStringProp -Path "Registry::$($hive.Name)\Volatile Environment" -Name 'USERPROFILE'
        if (-not $profilePath) {
            $profilePath = Get-RegStringProp -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name 'ProfileImagePath'
        }
        if (-not $profilePath) { continue }
        $leaf = Split-Path -Leaf $profilePath
        if ($leaf -ne $UserName) { continue }

        $root = "Registry::$($hive.Name)\$inetRel"
        Set-WinInetProxyAtPath -RootPath $root -ProxyServer $ProxyServer -PacUrl $PacUrl -ProxyOverride $ProxyOverride
        Write-Host "  WinINET proxy set for loaded hive $UserName ($sid)"
        $patched = $true
    }

    if ($patched) { return }

    # Offline hive (user not logged in).
    $ntuser = Join-Path $env:SystemDrive "Users\$UserName\NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $ntuser)) {
        Write-Warning "Payload user hive not found for $UserName; skip per-user WinINET."
        return
    }
    $tempKey = 'HKU\QuarantineHardenTmp'
    & reg.exe unload $tempKey 2>$null | Out-Null
    $load = & reg.exe load $tempKey $ntuser 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not load $ntuser (user may be logged in): $load"
        Write-Warning "Sign out $UserName, re-run this script as Admin, or set proxy while logged in as $UserName."
        return
    }
    try {
        $root = "Registry::HKEY_USERS\QuarantineHardenTmp\$inetRel"
        Set-WinInetProxyAtPath -RootPath $root -ProxyServer $ProxyServer -PacUrl $PacUrl -ProxyOverride $ProxyOverride
        Write-Host "  WinINET proxy set in offline hive $ntuser"
    } finally {
        [gc]::Collect()
        Start-Sleep -Milliseconds 300
        & reg.exe unload $tempKey | Out-Null
    }
}

if (-not (Test-Administrator)) {
    throw 'Run this script as Administrator inside the guest VM (elevate via UAC in the GUI).'
}

if ($Mode -eq 'gateway') {
    if (-not $ProxyHost) { $ProxyHost = '10.66.0.1' }
    if (-not $DnsServer) { $DnsServer = '10.66.0.1' }
    if (-not $GatewayIP) { $GatewayIP = '10.66.0.1' }
    if (-not $GuestIP) { $GuestIP = '10.66.0.15' }
    if ($PacPort -le 0) { $PacPort = $ProxyPort }
} else {
    if (-not $ProxyHost) { $ProxyHost = '10.0.2.2' }
    if (-not $DnsServer) { $DnsServer = '10.0.2.3' }
    if ($PSBoundParameters.ContainsKey('PacPort') -eq $false -and $PacPort -eq 8080) {
        $PacPort = 8081
    }
}

$PacUrl = "http://${ProxyHost}:${PacPort}/quarantine.pac"
$ProxyServer = "${ProxyHost}:${ProxyPort}"
$ProxyOverride = "${ProxyHost};<local>"

Write-Host "Hardening quarantine guest network ($Mode)..."
Write-Host "  Gateway/DNS: $GatewayIP / $DnsServer"
Write-Host "  Proxy/PAC:   $ProxyServer / $PacUrl"
Write-Host "  Payload user: $PayloadUser"

# --- Static IP + default gateway ---
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
    $haveIp = Get-NetIPAddress -InterfaceIndex $lan.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $GuestIP }
    if (-not $haveIp) {
        New-NetIPAddress -InterfaceIndex $lan.ifIndex -IPAddress $GuestIP -PrefixLength ([int]$PrefixLength) -DefaultGateway $GatewayIP -ErrorAction Stop | Out-Null
    } else {
        New-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop $GatewayIP -RouteMetric 10 -ErrorAction SilentlyContinue | Out-Null
        if (-not (Get-NetRoute -InterfaceIndex $lan.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $GatewayIP })) {
            # Fallback: recreate address with gateway
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
    Write-Host "  LAN: $GuestIP/$PrefixLength gw $GatewayIP on $($lan.Name)"

    foreach ($extra in $upAdapters) {
        if ($extra.ifIndex -eq $lan.ifIndex) { continue }
        Remove-NetRoute -InterfaceIndex $extra.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $extra.ifIndex -InterfaceMetric 5000 -ErrorAction SilentlyContinue
    }
} else {
    $adapter = $upAdapters[0]
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
    Write-Host "  DNS set on adapter: $($adapter.Name)"
}

# --- Machine WinINET + policy ---
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
if (-not (Test-Path -LiteralPath $policyPath)) {
    New-Item -Path $policyPath -Force | Out-Null
}
Set-ItemProperty -Path $policyPath -Name ProxySettingsPerUser -Value 0 -Type DWord
Set-WinInetProxyAtPath -RootPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -ProxyServer $ProxyServer -PacUrl $PacUrl -ProxyOverride $ProxyOverride
Set-WinInetProxyAtPath -RootPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
    -ProxyServer $ProxyServer -PacUrl $PacUrl -ProxyOverride $ProxyOverride
Write-Host '  HKLM + current-user WinINET proxy set'

# --- Payload user (jkcooper) ---
Set-PayloadUserWinInetProxy -UserName $PayloadUser -ProxyServer $ProxyServer -PacUrl $PacUrl -ProxyOverride $ProxyOverride

# --- WinHTTP (services / some system components) ---
$winhttpArgs = @(
    'winhttp', 'set', 'proxy',
    "proxy-server=$ProxyServer",
    "bypass-list=$ProxyOverride"
)
$wh = & netsh.exe @winhttpArgs 2>&1
Write-Host "  WinHTTP: $($wh -join ' ')"
& netsh.exe winhttp show proxy | ForEach-Object { Write-Host "    $_" }

# --- Outbound policy ---
# Gateway mode: normal routed internet (ping/SMTP/SSH/etc. + PCAP). Private nets
# are blocked on the Linux gateway. Only keep an explicit block for gateway SSH.
# host-nat: keep default-deny with proxy/DNS allows.
$groupName = 'Quarantine Lab Outbound'
Get-NetFirewallRule -DisplayName 'Quarantine Allow Gateway Any' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'Quarantine-Allow-Gateway-Any' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Ensure essentials exist (idempotent recreate)
$essentials = @(
    @{ Name = 'Quarantine-Allow-Proxy'; Display = 'Quarantine Allow Proxy'; Proto = 'TCP'; Remote = $ProxyHost; Port = $ProxyPort; Dir = 'Outbound' },
    @{ Name = 'Quarantine-Allow-PAC'; Display = 'Quarantine Allow PAC'; Proto = 'TCP'; Remote = $ProxyHost; Port = $PacPort; Dir = 'Outbound' },
    @{ Name = 'Quarantine-Allow-DNS'; Display = 'Quarantine Allow DNS'; Proto = 'UDP'; Remote = $DnsServer; Port = 53; Dir = 'Outbound' },
    @{ Name = 'Quarantine-Allow-DNS-TCP'; Display = 'Quarantine Allow DNS TCP'; Proto = 'TCP'; Remote = $DnsServer; Port = 53; Dir = 'Outbound' }
)
foreach ($r in $essentials) {
    Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $r.Name -DisplayName $r.Display -Group $groupName `
        -Direction $r.Dir -Action Allow -Protocol $r.Proto -RemoteAddress $r.Remote -RemotePort $r.Port | Out-Null
}

if ($Mode -eq 'gateway') {
    foreach ($name in @(
        'Quarantine-Allow-HTTP', 'Quarantine-Allow-HTTPS', 'Quarantine-Allow-Internet',
        'Quarantine-Allow-Internet-TCP', 'Quarantine-Allow-Internet-UDP', 'Quarantine-Allow-ICMP'
    )) {
        Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    New-NetFirewallRule -Name 'Quarantine-Allow-Internet-TCP' -DisplayName 'Quarantine Allow Internet TCP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol TCP -Profile Any | Out-Null
    New-NetFirewallRule -Name 'Quarantine-Allow-Internet-UDP' -DisplayName 'Quarantine Allow Internet UDP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol UDP -Profile Any | Out-Null
    New-NetFirewallRule -Name 'Quarantine-Allow-ICMP' -DisplayName 'Quarantine Allow ICMP' -Group $groupName `
        -Direction Outbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
    Get-NetFirewallRule -DisplayGroup 'Core Networking' -Direction Outbound -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Echo Request' } |
        Enable-NetFirewallRule -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name 'Quarantine-Allow-Agent-In' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name 'Quarantine-Allow-Agent-In' -DisplayName 'Quarantine Allow Agent In' -Group $groupName `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9443 -RemoteAddress $GatewayIP -Profile Any | Out-Null
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Host '  Firewall: outbound allow (normal internet); private nets blocked on gateway'
} else {
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Block -ErrorAction Stop
    Write-Host '  Firewall: essentials restored (default-deny)'
}

# Explicitly block guest -> gateway SSH (defense in depth; nftables also drops LAN:22)
Get-NetFirewallRule -Name 'Quarantine-Block-Gateway-SSH' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'Quarantine-Block-Gateway-SSH' -DisplayName 'Quarantine Block Gateway SSH' -Group $groupName `
    -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $GatewayIP -RemotePort 22 -Profile Any | Out-Null
Write-Host '  Firewall: gateway SSH blocked'

# --- Verify ---
Write-Host ''
Write-Host 'Verification:'
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "  default via $($_.NextHop) if $($_.InterfaceAlias) metric $($_.RouteMetric)" }
if (-not (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
    Write-Warning 'Still no default route after harden.'
}

Write-Host @"

Done. Re-login as $PayloadUser (or sign out/in) if browser proxy settings look stale.
Optional: shut down and run .\quarantine-vm.ps1 snapshot on the host to freeze this state.
"@
