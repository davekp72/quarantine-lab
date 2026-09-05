#Requires -Version 5.1
<#
.SYNOPSIS
  Collect DNS lookups and HTTP/proxy requests from host proxy logs and PCAP for a time window.
#>
Set-StrictMode -Version Latest

function Find-QuarantineTsharkCommand {
    $candidates = @(
        (Get-Command tshark -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "${env:ProgramFiles}\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($path in $candidates) {
        if ($path) { return $path }
    }
    return $null
}

function ConvertTo-QuarantineNetworkInstant {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        return [datetimeoffset]::Parse($Text, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        try {
            return [datetimeoffset]::Parse($Text)
        } catch {
            return $null
        }
    }
}

function Test-QuarantineNetworkNoiseUrl {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $true }
    $lower = $Url.ToLowerInvariant()
    if ($lower -match 'quarantine\.pac') { return $true }
    if ($lower -match 'mitmproxy-ca-cert\.cer') { return $true }
    if ($lower -match '/cert\.cer(\?|$)') { return $true }
    if ($lower -match '^https?://127\.0\.0\.1') { return $true }
    if ($lower -match '^https?://localhost') { return $true }
    return $false
}

function Get-QuarantineDnsTypeName {
    param([string]$TypeCode)

    if ([string]::IsNullOrWhiteSpace($TypeCode)) { return '' }
    $map = @{
        '1'  = 'A'
        '2'  = 'NS'
        '5'  = 'CNAME'
        '6'  = 'SOA'
        '12' = 'PTR'
        '15' = 'MX'
        '16' = 'TXT'
        '28' = 'AAAA'
        '33' = 'SRV'
        '65' = 'HTTPS'
    }
    $key = [string]$TypeCode
    if ($map.ContainsKey($key)) { return $map[$key] }
    return $key
}

function Read-QuarantineSharedLogLines {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $lines = New-Object System.Collections.Generic.List[string]
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($stream)
        while ($null -ne ($line = $reader.ReadLine())) {
            [void]$lines.Add($line)
        }
        $reader.Dispose()
        $stream.Dispose()
    } catch {
        Write-Warning "Could not read log (file may be locked): $Path - $($_.Exception.Message)"
        return @()
    }
    return $lines.ToArray()
}

function Read-QuarantineProxyAccessLog {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [datetimeoffset]$From,

        [Parameter(Mandatory)]
        [datetimeoffset]$To
    )

    $results = @()
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    foreach ($line in Read-QuarantineSharedLogLines -Path $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(\S+)\s+(\S+)\s+(.+)$') { continue }

        $tsText = $Matches[1]
        $method = $Matches[2]
        $url = $Matches[3].Trim()
        if (Test-QuarantineNetworkNoiseUrl -Url $url) { continue }

        $ts = ConvertTo-QuarantineNetworkInstant -Text $tsText
        if (-not $ts) { continue }
        if ($ts -lt $From -or $ts -gt $To) { continue }

        $hostName = ''
        if ($url -match '^https?://([^/:]+)') {
            $hostName = $Matches[1]
        }

        $results += [pscustomobject]@{
            t      = $ts.ToUniversalTime().ToString('o')
            method = $method
            url    = $url
            host   = $hostName
            source = 'proxy'
        }
    }

    return @($results)
}

function Get-QuarantinePcapDnsQueries {
    param(
        [Parameter(Mandatory)]
        [string]$PcapPath,

        [Parameter(Mandatory)]
        [datetimeoffset]$From,

        [Parameter(Mandatory)]
        [datetimeoffset]$To,

        [Parameter(Mandatory)]
        [string]$TsharkPath
    )

    if (-not (Test-Path -LiteralPath $PcapPath)) { return @() }

    $item = Get-Item -LiteralPath $PcapPath
    $fileFrom = [datetimeoffset]$item.CreationTimeUtc
    $fileTo = [datetimeoffset]$item.LastWriteTimeUtc
    if ($fileTo -lt $fileFrom) { $fileTo = $fileFrom }
    # Fast reject: file entirely outside evidence window (with slack for clock skew).
    if ($fileTo -lt $From.AddMinutes(-5) -or $fileFrom -gt $To.AddMinutes(5)) {
        return @()
    }

    $probe = @(& $TsharkPath -r $PcapPath -c 5 -T fields -e frame.time_epoch 2>$null)
    $relative = $false
    foreach ($p in $probe) {
        $v = 0.0
        if ([double]::TryParse([string]$p, [ref]$v) -and $v -gt 0 -and $v -lt 1000000000) {
            $relative = $true
            break
        }
    }

    $nameFields = @(
        @('dns.qry.name', 'dns.qry.type'),
        @('dns.qname', 'dns.qtype')
    )
    $output = $null
    foreach ($fields in $nameFields) {
        if ($relative) {
            # VirtualBox NIC traces often use relative epochs (1970-based), not wall clock.
            $filter = 'dns.flags.response == 0'
        } else {
            $fromEpoch = $From.ToUnixTimeSeconds()
            $toEpoch = $To.ToUnixTimeSeconds()
            $filter = ('frame.time_epoch >= {0} and frame.time_epoch <= {1} and dns.flags.response == 0' -f $fromEpoch, $toEpoch)
        }
        $argList = @(
            '-r', $PcapPath,
            '-Y', $filter,
            '-T', 'fields',
            '-E', 'separator=	',
            '-e', 'frame.time_epoch',
            '-e', $fields[0],
            '-e', $fields[1]
        )
        $output = & $TsharkPath @argList 2>$null
        if ($output -match '\S') { break }
    }
    if (-not ($output -match '\S')) { return @() }

    $maxRel = 0.0
    $minRel = [double]::MaxValue
    if ($relative) {
        foreach ($line in @($output)) {
            $epochText = (($line -split "`t", 2)[0])
            $epoch = 0.0
            if ([double]::TryParse($epochText, [ref]$epoch)) {
                if ($epoch -gt $maxRel) { $maxRel = $epoch }
                if ($epoch -lt $minRel) { $minRel = $epoch }
            }
        }
        if ($minRel -eq [double]::MaxValue) { $minRel = 0.0 }

        # Prefer full-capture duration (VBox relative clock often spans more than wall-clock file age).
        $capinfos = Join-Path (Split-Path -Parent $TsharkPath) 'capinfos.exe'
        if (Test-Path -LiteralPath $capinfos) {
            $ciOut = & $capinfos -u $PcapPath 2>$null | Out-String
            if ($ciOut -match '(?i)Capture duration:\s*([\d.]+)\s*seconds') {
                $dur = 0.0
                if ([double]::TryParse($Matches[1], [ref]$dur) -and $dur -gt $maxRel) {
                    $maxRel = $dur
                    $minRel = 0.0
                }
            }
        }
    }

    $wallSecs = [math]::Max(($fileTo - $fileFrom).TotalSeconds, 0.001)
    $relSpan = [math]::Max($maxRel - $minRel, 0.001)
    # When relative duration disagrees with file age, end-anchoring skews late packets past the window.
    $useLinearScale = $relative -and ($relSpan -gt ($wallSecs * 1.25))

    # Small slack so packets at the capture/preserve boundary are not dropped.
    $fromBound = $From.AddSeconds(-2)
    $toBound = $To.AddSeconds(2)

    $results = @()
    foreach ($line in @($output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "`t", 3
        if ($parts.Count -lt 2) { continue }

        $epochText = $parts[0]
        $query = ($parts[1] -replace '\.$', '').Trim()
        $qtype = if ($parts.Count -ge 3) { Get-QuarantineDnsTypeName -TypeCode $parts[2] } else { '' }
        if ([string]::IsNullOrWhiteSpace($query)) { continue }

        $epoch = 0.0
        if (-not [double]::TryParse($epochText, [ref]$epoch)) { continue }

        if ($relative) {
            if ($useLinearScale) {
                $ts = $fileFrom.AddSeconds((($epoch - $minRel) / $relSpan) * $wallSecs)
            } else {
                # Relative clock roughly matches wall duration — anchor to last write.
                $ts = $fileTo.AddSeconds($epoch - $maxRel)
            }
        } else {
            $ts = [datetimeoffset]::FromUnixTimeSeconds([long][math]::Floor($epoch))
        }
        if ($ts -lt $fromBound -or $ts -gt $toBound) { continue }

        $results += [pscustomobject]@{
            t      = $ts.ToUniversalTime().ToString('o')
            query  = $query
            type   = $qtype
            source = 'pcap'
        }
    }

    return @($results)
}

function Get-QuarantineDnsFromProxyRequests {
    param([array]$Requests)

    $byHost = [ordered]@{}
    foreach ($req in @($Requests)) {
        $hostName = if ($req.host) { [string]$req.host.Trim().ToLowerInvariant() } else { '' }
        if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
        if (-not $byHost.Contains($hostName)) {
            $byHost[$hostName] = [pscustomobject]@{
                t      = [string]$req.t
                query  = $hostName
                type   = 'inferred'
                source = 'proxy'
            }
        }
    }
    return @($byHost.Values)
}

function Get-QuarantineNetworkEvidence {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [datetimeoffset]$From,

        [Parameter(Mandatory)]
        [datetimeoffset]$To,

        [int]$MaxDns = 0,

        [int]$MaxRequests = 0
    )

    if ($From -gt $To) {
        return [pscustomobject]@{
            available  = $false
            message    = 'Invalid network window: From is after To.'
            windowFrom = $From.ToUniversalTime().ToString('o')
            windowTo   = $To.ToUniversalTime().ToString('o')
            sources    = [ordered]@{ proxyLogs = @(); pcaps = @() }
            dns        = @()
            requests   = @()
            truncated  = $false
        }
    }

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\quarantine-vm.json'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        return [pscustomobject]@{
            available  = $false
            message    = "Config not found for network evidence: $ConfigPath"
            windowFrom = $From.ToUniversalTime().ToString('o')
            windowTo   = $To.ToUniversalTime().ToString('o')
            sources    = [ordered]@{ proxyLogs = @(); pcaps = @() }
            dns        = @()
            requests   = @()
            truncated  = $false
        }
    }

    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $proxyLogDir = if ($cfg.network -and $cfg.network.proxy -and $cfg.network.proxy.logDir) {
        [string]$cfg.network.proxy.logDir
    } else { '' }
    $pcapLogDir = if ($cfg.network -and $cfg.network.capture -and $cfg.network.capture.logDir) {
        [string]$cfg.network.capture.logDir
    } else { '' }

    $proxyLogs = @()
    $pcaps = @()
    $dns = @()
    $requests = @()
    $truncated = $false

    if ($proxyLogDir -and (Test-Path -LiteralPath $proxyLogDir)) {
        $accessFiles = Get-ChildItem -LiteralPath $proxyLogDir -Recurse -Filter 'access.log' -File -ErrorAction SilentlyContinue
        foreach ($file in $accessFiles) {
            $proxyLogs += $file.FullName
            $requests += Read-QuarantineProxyAccessLog -Path $file.FullName -From $From -To $To
        }
    }

    $manifestLogDir = if ($cfg.manifest -and $cfg.manifest.logDir) {
        [string]$cfg.manifest.logDir
    } else { '' }
    if ($manifestLogDir -and (Test-Path -LiteralPath $manifestLogDir)) {
        Get-ChildItem -LiteralPath $manifestLogDir -Directory -Filter '*-network' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $access = Join-Path $_.FullName 'access.log'
                if (Test-Path -LiteralPath $access) {
                    $proxyLogs += $access
                    $requests += Read-QuarantineProxyAccessLog -Path $access -From $From -To $To
                }
            }
    }

    $tshark = Find-QuarantineTsharkCommand
    if ($pcapLogDir -and (Test-Path -LiteralPath $pcapLogDir) -and $tshark) {
        $pcapFiles = @(Get-ChildItem -LiteralPath $pcapLogDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.pcap', '.pcapng') })
        foreach ($file in $pcapFiles) {
            $pcaps += $file.FullName
            $dns += Get-QuarantinePcapDnsQueries -PcapPath $file.FullName -From $From -To $To -TsharkPath $tshark
        }
    }
    if ($manifestLogDir -and (Test-Path -LiteralPath $manifestLogDir) -and $tshark) {
        Get-ChildItem -LiteralPath $manifestLogDir -Directory -Filter '*-network' -ErrorAction SilentlyContinue |
            ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in @('.pcap', '.pcapng') } |
                    ForEach-Object {
                        $pcaps += $_.FullName
                        $dns += Get-QuarantinePcapDnsQueries -PcapPath $_.FullName -From $From -To $To -TsharkPath $tshark
                    }
            }
    }

    $sortedDns = @($dns | Sort-Object { $_.t }, { $_.query })
    $sortedRequests = @($requests | Sort-Object { $_.t }, { $_.url })

    $proxyDns = Get-QuarantineDnsFromProxyRequests -Requests $sortedRequests
    $pcapDnsCount = @($dns).Count
    if (@($proxyDns).Count -gt 0) {
        $sortedDns = @($sortedDns + @($proxyDns) | Sort-Object { $_.t }, { $_.query })
    }

    if ($MaxDns -gt 0 -and $sortedDns.Count -gt $MaxDns) {
        $sortedDns = @($sortedDns | Select-Object -First $MaxDns)
        $truncated = $true
    }
    if ($MaxRequests -gt 0 -and $sortedRequests.Count -gt $MaxRequests) {
        $sortedRequests = @($sortedRequests | Select-Object -First $MaxRequests)
        $truncated = $true
    }

    $available = ($sortedDns.Count -gt 0) -or ($sortedRequests.Count -gt 0) -or ($proxyLogs.Count -gt 0) -or ($pcaps.Count -gt 0)
    $message = ''
    if (-not $available) {
        $message = 'No proxy access logs or PCAP files found for this window. Ensure quarantine network mode with proxy/capture enabled during the test.'
    } elseif ($sortedDns.Count -eq 0 -and $sortedRequests.Count -eq 0) {
        $message = 'Proxy/PCAP sources were scanned but no DNS or HTTP requests matched the snapshot time window.'
    } elseif (@($proxyDns).Count -gt 0 -and $pcapDnsCount -eq 0) {
        $message = 'DNS hosts inferred from proxy HTTP traffic (no UDP/53 in PCAP). Use capture mode guest-nic (VirtualBox NIC trace) and/or Sysmon DNS Event 22.'
    } elseif ($pcapDnsCount -gt 0) {
        $message = "DNS from PCAP ($pcapDnsCount queries). Sysmon DNS merged when present."
    }

    return [pscustomobject]@{
        available  = $available
        message    = $message
        windowFrom = $From.ToUniversalTime().ToString('o')
        windowTo   = $To.ToUniversalTime().ToString('o')
        sources    = [ordered]@{
            proxyLogs = @($proxyLogs)
            pcaps     = @($pcaps)
            tshark    = if ($tshark) { $tshark } else { $null }
        }
        dns        = $sortedDns
        requests   = $sortedRequests
        truncated  = $truncated
    }
}

function Merge-QuarantineSysmonDnsEvidence {
    param(
        [array]$DnsEntries = @(),

        [array]$SysmonEvents = @(),

        [datetimeoffset]$From,

        [datetimeoffset]$To
    )

    $merged = @()
    foreach ($entry in @($DnsEntries)) { $merged += $entry }

    # Unwrap PowerShell 5.1 ConvertFrom-Json nesting: @(bigJsonArray) can become Count=1.
    $events = @($SysmonEvents)
    if ($events.Count -eq 1 -and $events[0] -is [System.Array]) {
        $events = @($events[0])
    }

    foreach ($ev in $events) {
        if ($null -eq $ev -or $ev -is [System.Array]) { continue }
        $eid = if ($ev.PSObject.Properties['eid']) { [int]$ev.eid } else { 0 }
        $kind = if ($ev.PSObject.Properties['t']) { [string]$ev.t } elseif ($ev.PSObject.Properties['type']) { [string]$ev.type } else { '' }
        if ($eid -ne 22 -and $kind -ne 'DnsQuery') { continue }
        $query = if ($ev.PSObject.Properties['queryName']) { [string]$ev.queryName } else { '' }
        if ([string]::IsNullOrWhiteSpace($query)) { continue }

        # `t` is event type (DnsQuery); timestamp is `time`.
        $timeText = if ($ev.PSObject.Properties['time'] -and $ev.time) { [string]$ev.time } else { '' }
        $ts = ConvertTo-QuarantineNetworkInstant -Text $timeText
        if ($ts) {
            if ($From -and $ts -lt $From) { continue }
            if ($To -and $ts -gt $To) { continue }
        }

        $merged += [pscustomobject]@{
            t      = if ($ts) { $ts.ToUniversalTime().ToString('o') } else { $timeText }
            query  = $query.TrimEnd('.')
            type   = ''
            source = 'sysmon'
            image  = if ($ev.image) { [string]$ev.image } else { '' }
        }
    }

    return @($merged | Sort-Object { $_.t }, { $_.query })
}
