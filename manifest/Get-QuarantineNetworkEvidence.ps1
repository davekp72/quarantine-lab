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

        [datetimeoffset]$From,

        [datetimeoffset]$To,

        # Evidence packages are authoritative for a snapshot; gateway clocks may skew vs host.
        [switch]$IgnoreTimeWindow
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
        if (-not $IgnoreTimeWindow) {
            if (-not $From -or -not $To) { continue }
            if ($ts -lt $From -or $ts -gt $To) { continue }
        }

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

function Read-QuarantineFlowsJsonl {
    <#
      Decrypted HTTPS from mitmproxy (not PCAP). Bodies capped on the gateway.
      Diff embeds a short preview; full body stays in flows.jsonl on disk.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [datetimeoffset]$From,

        [datetimeoffset]$To,

        [switch]$IgnoreTimeWindow,

        [int]$BodyPreviewChars = 2048
    )

    $results = @()
    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $lineNo = 0
    foreach ($line in Read-QuarantineSharedLogLines -Path $Path) {
        $lineNo++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $obj = $line | ConvertFrom-Json
        } catch {
            continue
        }
        $url = [string]$obj.url
        $method = [string]$obj.method
        if (Test-QuarantineNetworkNoiseUrl -Url $url) { continue }

        $ts = ConvertTo-QuarantineNetworkInstant -Text ([string]$obj.t)
        if (-not $IgnoreTimeWindow) {
            if (-not $ts -or -not $From -or -not $To) { continue }
            if ($ts -lt $From -or $ts -gt $To) { continue }
        }

        $hostName = ''
        if ($url -match '^https?://([^/:]+)') {
            $hostName = $Matches[1]
        }
        $rawHost = [string]$obj.host
        # Transparent MITM often puts the peer IP in host; prefer URL hostname.
        if ($hostName -match '^\d{1,3}(\.\d{1,3}){3}$' -or ($hostName -and $hostName.Contains(':'))) {
            if ($rawHost -and $rawHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and -not $rawHost.Contains(':')) {
                $hostName = $rawHost
            }
        } elseif ([string]::IsNullOrWhiteSpace($hostName) -and $rawHost) {
            $hostName = $rawHost
        }

        $tText = if ($ts) { $ts.ToUniversalTime().ToString('o') } else { [string]$obj.t }
        $resolved = @()
        if ($obj.PSObject.Properties['resolvedIps'] -and $obj.resolvedIps) {
            $resolved = @($obj.resolvedIps | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }
        # Do not embed request/response bodies: ConvertTo-Json emits invalid `\a`/`\v`
        # escapes for control bytes, which drops the entire HTTP list in the UI.
        $results += [pscustomobject]@{
            t            = $tText
            method       = $method
            url          = $url
            host         = $hostName
            status       = $obj.status
            source       = 'mitm'
            hasBody      = $true
            flowFile     = $Path
            flowLine     = $lineNo
            resolvedIps  = $resolved
        }
    }

    return @($results)
}

function Compress-QuarantineFlowPart {
    param(
        $Part,
        [int]$MaxChars = 2048
    )
    if ($null -eq $Part) { return $null }
    $body = [string]$Part.body
    $truncated = [bool]$Part.bodyTruncated
    if ($body.Length -gt $MaxChars) {
        $body = $body.Substring(0, $MaxChars)
        $truncated = $true
    }
    return [pscustomobject]@{
        contentType   = [string]$Part.contentType
        bodyBytes     = $Part.bodyBytes
        bodyTruncated = $truncated
        encoding      = [string]$Part.encoding
        body          = $body
        headers       = $Part.headers
    }
}

function Get-QuarantineSafeSnapshotFileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $s = $Name.Trim()
    foreach ($ch in @('<', '>', ':', '"', '/', '\', '|', '?', '*')) {
        $s = $s.Replace($ch, '_')
    }
    return $s
}

function Get-QuarantinePcapDnsQueries {
    param(
        [Parameter(Mandatory)]
        [string]$PcapPath,

        [datetimeoffset]$From,

        [datetimeoffset]$To,

        [Parameter(Mandatory)]
        [string]$TsharkPath,

        [switch]$IgnoreTimeWindow
    )

    if (-not (Test-Path -LiteralPath $PcapPath)) { return @() }

    $item = Get-Item -LiteralPath $PcapPath
    $fileFrom = [datetimeoffset]$item.CreationTimeUtc
    $fileTo = [datetimeoffset]$item.LastWriteTimeUtc
    if ($fileTo -lt $fileFrom) { $fileTo = $fileFrom }
    # Fast reject: file entirely outside evidence window (with slack for clock skew).
    if (-not $IgnoreTimeWindow) {
        if (-not $From -or -not $To) { return @() }
        if ($fileTo -lt $From.AddMinutes(-5) -or $fileFrom -gt $To.AddMinutes(5)) {
            return @()
        }
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
        if ($relative -or $IgnoreTimeWindow) {
            # VirtualBox NIC traces often use relative epochs (1970-based), not wall clock.
            # Evidence packages: skip epoch filter (gateway clock may skew vs host snapshot times).
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
    $fromBound = $null
    $toBound = $null
    if (-not $IgnoreTimeWindow -and $From -and $To) {
        $fromBound = $From.AddSeconds(-2)
        $toBound = $To.AddSeconds(2)
    }

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
        if ($null -ne $fromBound -and $null -ne $toBound) {
            if ($ts -lt $fromBound -or $ts -gt $toBound) { continue }
        }

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
        # HTTP host is often the resolved IP after transparent MITM — not a DNS name.
        if ($hostName -match '^\d{1,3}(\.\d{1,3}){3}$' -or $hostName.Contains(':')) { continue }
        $ips = @()
        if ($req.PSObject.Properties['resolvedIps'] -and $req.resolvedIps) {
            $ips = @($req.resolvedIps | ForEach-Object { [string]$_.Trim() } | Where-Object { $_ })
        }
        if (-not $byHost.Contains($hostName)) {
            $src = if ($req.source -eq 'mitm') { 'mitm' } else { 'proxy' }
            $byHost[$hostName] = [pscustomobject]@{
                t       = [string]$req.t
                query   = $hostName
                type    = if ($ips.Count -gt 0) { 'A' } else { 'inferred' }
                source  = $src
                answers = [System.Collections.Generic.List[string]]::new()
            }
        }
        foreach ($ip in $ips) {
            if (-not $byHost[$hostName].answers.Contains($ip)) {
                [void]$byHost[$hostName].answers.Add($ip)
            }
        }
    }
    $out = @()
    foreach ($v in $byHost.Values) {
        $answers = @($v.answers)
        $out += [pscustomobject]@{
            t       = $v.t
            query   = $v.query
            type    = if ($answers.Count -gt 0) { 'A' } else { $v.type }
            source  = $v.source
            answers = $answers
        }
    }
    return @($out)
}

function Select-QuarantineNetworkBySnapshotWindow {
    <#
      Clip package rows to the CleanSession→Evidence gap.
      Prefer absolute From/To with clock skew; if empty or the kept span is much
      larger than the snapshot gap (leftover traffic admitted by skew), keep the
      duration-tail ending at the latest package timestamp.
    #>
    param(
        [array]$Rows,
        [datetimeoffset]$From,
        [datetimeoffset]$To,
        [int]$ClockSkewMinutes = 30
    )

    $list = @($Rows | Where-Object { $_ })
    if ($list.Count -eq 0 -or -not $From -or -not $To) { return $list }
    if ($To -lt $From) {
        $tmp = $From; $From = $To; $To = $tmp
    }
    $session = $To - $From
    if ($session.TotalMinutes -lt 2) {
        $session = [TimeSpan]::FromMinutes(2)
    }
    $looseFrom = $From.AddMinutes(-$ClockSkewMinutes)
    $looseTo = $To.AddMinutes($ClockSkewMinutes)

    $parsed = @()
    foreach ($r in $list) {
        $ts = ConvertTo-QuarantineNetworkInstant -Text ([string]$r.t)
        if (-not $ts) { continue }
        $parsed += [pscustomobject]@{ Row = $r; Ts = $ts }
    }
    if ($parsed.Count -eq 0) { return $list }

    $abs = @($parsed | Where-Object { $_.Ts -ge $looseFrom -and $_.Ts -le $looseTo })
    if ($abs.Count -gt 0) {
        $absMin = ($abs | Measure-Object -Property Ts -Minimum).Minimum
        $absMax = ($abs | Measure-Object -Property Ts -Maximum).Maximum
        $absSpan = $absMax - $absMin
        $maxSpan = $session + [TimeSpan]::FromMinutes(10)
        if ($absSpan -le $maxSpan) {
            return @($abs | ForEach-Object { $_.Row })
        }
    }

    $maxT = ($parsed | Measure-Object -Property Ts -Maximum).Maximum
    $pad = [TimeSpan]::FromMinutes(2)
    if (($session.TotalMinutes / 4) -gt $pad.TotalMinutes) {
        $pad = [TimeSpan]::FromMinutes($session.TotalMinutes / 4)
    }
    $cut = $maxT - ($session + $pad)
    $tail = @($parsed | Where-Object { $_.Ts -ge $cut } | ForEach-Object { $_.Row })
    if ($tail.Count -eq 0) { return $list }
    return $tail
}

function Get-QuarantinePcapDnsAnswers {
    <#
      DNS response A/AAAA records from PCAP (guest→gateway DNS when present).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PcapPath,

        [Parameter(Mandatory)]
        [string]$TsharkPath,

        [int]$MaxRows = 2000
    )

    if (-not (Test-Path -LiteralPath $PcapPath)) { return @() }

    $argList = @(
        '-n',
        '-r', $PcapPath,
        '-Y', 'dns.flags.response == 1 && (dns.a || dns.aaaa)',
        '-T', 'fields',
        '-E', 'separator=	',
        '-e', 'frame.time_epoch',
        '-e', 'dns.qry.name',
        '-e', 'dns.a',
        '-e', 'dns.aaaa'
    )
    $output = & $TsharkPath @argList 2>$null
    if (-not ($output -match '\S')) { return @() }

    $byHost = [ordered]@{}
    $count = 0
    foreach ($line in @($output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "`t", 4
        if ($parts.Count -lt 2) { continue }
        $epochText = $parts[0]
        $query = ($parts[1] -replace '\.$', '').Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($query)) { continue }

        $ips = @()
        if ($parts.Count -ge 3 -and $parts[2]) {
            $ips += @($parts[2] -split '[, ]+' | Where-Object { $_ })
        }
        if ($parts.Count -ge 4 -and $parts[3]) {
            $ips += @($parts[3] -split '[, ]+' | Where-Object { $_ })
        }
        $ips = @($ips | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
        if ($ips.Count -eq 0) { continue }

        $epoch = 0.0
        $tText = ''
        if ([double]::TryParse($epochText, [ref]$epoch) -and $epoch -gt 1000000000) {
            $tText = [datetimeoffset]::FromUnixTimeSeconds([long][math]::Floor($epoch)).ToUniversalTime().ToString('o')
        } else {
            $tText = (Get-Item -LiteralPath $PcapPath).LastWriteTimeUtc.ToString('o')
        }

        if (-not $byHost.Contains($query)) {
            $byHost[$query] = [pscustomobject]@{
                t       = $tText
                query   = $query
                type    = 'A'
                source  = 'pcap'
                answers = [System.Collections.Generic.List[string]]::new()
            }
        }
        foreach ($ip in $ips) {
            if (-not $byHost[$query].answers.Contains($ip)) {
                [void]$byHost[$query].answers.Add($ip)
            }
        }
        $count++
        if ($count -ge $MaxRows) { break }
    }

    $out = @()
    foreach ($v in $byHost.Values) {
        $out += [pscustomobject]@{
            t       = $v.t
            query   = $v.query
            type    = 'A'
            source  = 'pcap'
            answers = @($v.answers)
        }
    }
    return @($out)
}

function Merge-QuarantineDnsEntries {
    param([array]$Entries)

    $byKey = [ordered]@{}
    foreach ($e in @($Entries)) {
        if ($null -eq $e) { continue }
        $q = if ($e.query) { [string]$e.query.ToLowerInvariant() } else { '' }
        if (-not $q) { continue }
        $src = if ($e.source) { [string]$e.source } else { '' }
        $key = "$q|$src"
        $answers = @()
        if ($e.PSObject.Properties['answers'] -and $e.answers) {
            $answers = @($e.answers | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }

        if (-not $byKey.Contains($key)) {
            $byKey[$key] = [pscustomobject]@{
                t       = [string]$e.t
                query   = $q
                type    = if ($e.type) { [string]$e.type } else { '' }
                source  = $src
                answers = [System.Collections.Generic.List[string]]::new()
                image   = if ($e.PSObject.Properties['image']) { [string]$e.image } else { '' }
                dst     = if ($e.PSObject.Properties['dst']) { [string]$e.dst } else { '' }
                port    = if ($e.PSObject.Properties['port']) { [string]$e.port } else { '' }
            }
        }
        foreach ($ip in $answers) {
            if (-not $byKey[$key].answers.Contains($ip)) {
                [void]$byKey[$key].answers.Add($ip)
            }
        }
        # Prefer richer type when we have answers.
        if ($byKey[$key].answers.Count -gt 0 -and ($byKey[$key].type -eq 'inferred' -or $byKey[$key].type -eq 'sni' -or [string]::IsNullOrWhiteSpace($byKey[$key].type))) {
            $byKey[$key].type = 'A'
        }
    }

    # Attach mitm/proxy answers onto pcap/sni rows for the same query when those lack answers.
    $answerByQuery = @{}
    foreach ($v in $byKey.Values) {
        if ($v.answers.Count -eq 0) { continue }
        if ($v.source -notin @('mitm', 'proxy', 'pcap')) { continue }
        $q = $v.query
        if (-not $answerByQuery.ContainsKey($q)) {
            $answerByQuery[$q] = [System.Collections.Generic.List[string]]::new()
        }
        foreach ($ip in $v.answers) {
            if (-not $answerByQuery[$q].Contains($ip)) {
                [void]$answerByQuery[$q].Add($ip)
            }
        }
    }
    foreach ($v in $byKey.Values) {
        if ($v.answers.Count -gt 0) { continue }
        if (-not $answerByQuery.ContainsKey($v.query)) { continue }
        foreach ($ip in $answerByQuery[$v.query]) {
            [void]$v.answers.Add($ip)
        }
        if ($v.answers.Count -gt 0 -and ($v.type -eq 'inferred' -or $v.type -eq 'sni')) {
            # Keep original evidence type but show resolution.
            if ($v.type -eq 'inferred') { $v.type = 'A' }
        }
    }

    $out = @()
    foreach ($v in $byKey.Values) {
        $row = [ordered]@{
            t       = $v.t
            query   = $v.query
            type    = $v.type
            source  = $v.source
            answers = @($v.answers)
        }
        if ($v.image) { $row.image = $v.image }
        if ($v.dst) { $row.dst = $v.dst }
        if ($v.port) { $row.port = $v.port }
        $out += [pscustomobject]$row
    }
    return @($out | Sort-Object { $_.t }, { $_.query })
}

function Get-QuarantinePcapTlsSniHosts {
    <#
      Explicit MITM/proxy LAN captures rarely have UDP/53 for browsed sites.
      Client Hellos still carry SNI (e.g. purple.com → 10.66.0.1:8080).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PcapPath,

        [Parameter(Mandatory)]
        [string]$TsharkPath,

        [int]$MaxHosts = 500
    )

    if (-not (Test-Path -LiteralPath $PcapPath)) { return @() }

    $argList = @(
        '-n',
        '-r', $PcapPath,
        '-Y', 'tls.handshake.type == 1 && tls.handshake.extensions_server_name',
        '-T', 'fields',
        '-E', 'separator=	',
        '-e', 'frame.time_epoch',
        '-e', 'tls.handshake.extensions_server_name',
        '-e', 'ip.dst',
        '-e', 'tcp.dstport'
    )
    $output = & $TsharkPath @argList 2>$null
    if (-not ($output -match '\S')) { return @() }

    $byHost = [ordered]@{}
    foreach ($line in @($output)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "`t", 4
        if ($parts.Count -lt 2) { continue }

        $epochText = $parts[0]
        $sniRaw = ($parts[1] -replace '\.$', '').Trim()
        if ([string]::IsNullOrWhiteSpace($sniRaw)) { continue }

        # tshark can emit comma-separated SNIs
        foreach ($piece in ($sniRaw -split '[, ]+' | Where-Object { $_ })) {
            $hostName = $piece.Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
            if ($byHost.Contains($hostName)) { continue }

            $epoch = 0.0
            $tText = ''
            if ([double]::TryParse($epochText, [ref]$epoch) -and $epoch -gt 1000000000) {
                $tText = [datetimeoffset]::FromUnixTimeSeconds([long][math]::Floor($epoch)).ToUniversalTime().ToString('o')
            } else {
                $tText = (Get-Item -LiteralPath $PcapPath).LastWriteTimeUtc.ToString('o')
            }

            $dst = if ($parts.Count -ge 3) { [string]$parts[2] } else { '' }
            $port = if ($parts.Count -ge 4) { [string]$parts[3] } else { '' }
            $byHost[$hostName] = [pscustomobject]@{
                t      = $tText
                query  = $hostName
                type   = 'sni'
                source = 'pcap'
                dst    = $dst
                port   = $port
            }
            if ($MaxHosts -gt 0 -and $byHost.Count -ge $MaxHosts) { break }
        }
        if ($MaxHosts -gt 0 -and $byHost.Count -ge $MaxHosts) { break }
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

        # When set, prefer {snapshot}-network packages (ignore host/gateway clock skew).
        [string]$FromSnapshot = '',

        [string]$ToSnapshot = '',

        # Extra minutes around From/To for loose (non-package) logs — gateway clocks often drift.
        [int]$ClockSkewMinutes = 30,

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
    $packageHits = 0

    $skew = [Math]::Max(0, $ClockSkewMinutes)
    $looseFrom = $From.AddMinutes(-$skew)
    $looseTo = $To.AddMinutes($skew)

    $manifestLogDir = if ($cfg.manifest -and $cfg.manifest.logDir) {
        [string]$cfg.manifest.logDir
    } else { '' }

    $namedNetworkDirs = @()
    # Only the To (Evidence) package is authoritative. From (CleanSession) network
    # dirs are baselines from earlier sessions and must not be merged into the diff.
    foreach ($snap in @($ToSnapshot)) {
        $safe = Get-QuarantineSafeSnapshotFileName -Name $snap
        if (-not $safe -or -not $manifestLogDir) { continue }
        $dir = Join-Path $manifestLogDir ($safe + '-network')
        if (Test-Path -LiteralPath $dir) {
            $namedNetworkDirs += $dir
        }
    }
    $namedNetworkDirs = @($namedNetworkDirs | Select-Object -Unique)

    # Snapshot-scoped packages: load full contents then clip to the snapshot gap
    # (absolute window with clock skew, else duration-tail). Do not IgnoreTimeWindow
    # forever — that reintroduced hours of leftover flows when truncate failed.
    foreach ($dir in $namedNetworkDirs) {
        $flowsPath = Join-Path $dir 'flows.jsonl'
        $access = Join-Path $dir 'access.log'
        $usedFlows = $false
        if (Test-Path -LiteralPath $flowsPath) {
            $flowReqs = @(Read-QuarantineFlowsJsonl -Path $flowsPath -IgnoreTimeWindow)
            if ($flowReqs.Count -gt 0) {
                $proxyLogs += $flowsPath
                $packageHits++
                $requests += $flowReqs
                $usedFlows = $true
            }
        }
        if (-not $usedFlows -and (Test-Path -LiteralPath $access)) {
            $proxyLogs += $access
            $packageHits++
            $requests += Read-QuarantineProxyAccessLog -Path $access -IgnoreTimeWindow
        } elseif ($usedFlows -and (Test-Path -LiteralPath $access)) {
            $proxyLogs += $access
        }
    }
    if ($packageHits -gt 0 -and $requests.Count -gt 0) {
        $requests = @(Select-QuarantineNetworkBySnapshotWindow -Rows $requests -From $From -To $To -ClockSkewMinutes $skew)
    }

    # When a named evidence-network package supplied HTTP, do not mix ambient host proxy
    # logs from the long CleanSession→Evidence wall clock (prior-day sessions pollute the UI).
    if ($packageHits -eq 0 -and $proxyLogDir -and (Test-Path -LiteralPath $proxyLogDir)) {
        $accessFiles = Get-ChildItem -LiteralPath $proxyLogDir -Recurse -Filter 'access.log' -File -ErrorAction SilentlyContinue
        foreach ($file in $accessFiles) {
            $proxyLogs += $file.FullName
            $requests += Read-QuarantineProxyAccessLog -Path $file.FullName -From $looseFrom -To $looseTo
        }
    }

    # Legacy: scan all *-network folders only when no named snapshot packages were provided.
    if ($namedNetworkDirs.Count -eq 0 -and $manifestLogDir -and (Test-Path -LiteralPath $manifestLogDir)) {
        Get-ChildItem -LiteralPath $manifestLogDir -Directory -Filter '*-network' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $access = Join-Path $_.FullName 'access.log'
                if (Test-Path -LiteralPath $access) {
                    $proxyLogs += $access
                    # Prefer full package contents when meta says attached near the To window.
                    $useAll = $false
                    $metaPath = Join-Path $_.FullName 'meta.json'
                    if (Test-Path -LiteralPath $metaPath) {
                        try {
                            $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
                            $attached = ConvertTo-QuarantineNetworkInstant -Text ([string]$meta.attachedAt)
                            if ($attached -and $attached -ge $looseFrom -and $attached -le $looseTo) {
                                $useAll = $true
                            }
                        } catch { }
                    }
                    if ($useAll) {
                        $packageHits++
                        $requests += Read-QuarantineProxyAccessLog -Path $access -IgnoreTimeWindow
                    } else {
                        $requests += Read-QuarantineProxyAccessLog -Path $access -From $looseFrom -To $looseTo
                    }
                }
            }
    }

    $tshark = Find-QuarantineTsharkCommand
    # Same rule as proxy: ambient PCAP DNS only when no snapshot network package was used.
    if ($packageHits -eq 0 -and $pcapLogDir -and (Test-Path -LiteralPath $pcapLogDir) -and $tshark) {
        $pcapFiles = @(Get-ChildItem -LiteralPath $pcapLogDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.pcap', '.pcapng') })
        foreach ($file in $pcapFiles) {
            $pcaps += $file.FullName
            $dns += Get-QuarantinePcapDnsQueries -PcapPath $file.FullName -From $looseFrom -To $looseTo -TsharkPath $tshark
        }
    }
    $pcapDirs = @()
    if ($namedNetworkDirs.Count -gt 0) {
        $pcapDirs = $namedNetworkDirs
    } elseif ($manifestLogDir -and (Test-Path -LiteralPath $manifestLogDir)) {
        $pcapDirs = @(Get-ChildItem -LiteralPath $manifestLogDir -Directory -Filter '*-network' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
    }
    $sniCount = 0
    if ($tshark) {
        foreach ($dir in $pcapDirs) {
            $isNamed = $namedNetworkDirs -contains $dir
            $hasAccess = Test-Path -LiteralPath (Join-Path $dir 'access.log')
            $hasFlows = Test-Path -LiteralPath (Join-Path $dir 'flows.jsonl')
            Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @('.pcap', '.pcapng') } |
                ForEach-Object {
                    $pcaps += $_.FullName
                    # Prefer TLS SNI for gateway LAN captures (explicit proxy → :8080).
                    $sniHosts = @(Get-QuarantinePcapTlsSniHosts -PcapPath $_.FullName -TsharkPath $tshark)
                    if ($sniHosts.Count -gt 0) {
                        $dns += $sniHosts
                        $sniCount += $sniHosts.Count
                    }
                    # DNS answer records (A/AAAA) when guest used gateway DNS.
                    $dns += Get-QuarantinePcapDnsAnswers -PcapPath $_.FullName -TsharkPath $tshark
                    # Classic UDP/53 queries: skip on large named packages when proxy/flows already list hosts.
                    if ($isNamed -and ($hasAccess -or $hasFlows)) { return }
                    if ($isNamed) {
                        $dns += Get-QuarantinePcapDnsQueries -PcapPath $_.FullName -TsharkPath $tshark -IgnoreTimeWindow
                    } else {
                        $dns += Get-QuarantinePcapDnsQueries -PcapPath $_.FullName -From $looseFrom -To $looseTo -TsharkPath $tshark
                    }
                }
        }
    }

    $proxyDns = Get-QuarantineDnsFromProxyRequests -Requests $requests
    $pcapDnsCount = @($dns | Where-Object { $_.source -eq 'pcap' }).Count
    $sortedDns = Merge-QuarantineDnsEntries -Entries (@($dns) + @($proxyDns))
    if ($packageHits -gt 0 -and $sortedDns.Count -gt 0) {
        $sortedDns = @(Select-QuarantineNetworkBySnapshotWindow -Rows $sortedDns -From $From -To $To -ClockSkewMinutes $skew)
    }

    if ($MaxDns -gt 0 -and $sortedDns.Count -gt $MaxDns) {
        $sortedDns = @($sortedDns | Select-Object -First $MaxDns)
        $truncated = $true
    }
    $sortedRequests = @($requests | Sort-Object { $_.t }, { $_.url })
    if ($MaxRequests -gt 0 -and $sortedRequests.Count -gt $MaxRequests) {
        $sortedRequests = @($sortedRequests | Select-Object -First $MaxRequests)
        $truncated = $true
    }

    $windowFromOut = $From.ToUniversalTime().ToString('o')
    $windowToOut = $To.ToUniversalTime().ToString('o')
    # Prefer real traffic span from the evidence package over the CleanSession→Evidence wall clock.
    if ($packageHits -gt 0 -and $sortedRequests.Count -gt 0) {
        $trafficFrom = ConvertTo-QuarantineNetworkInstant -Text ([string]$sortedRequests[0].t)
        $trafficTo = ConvertTo-QuarantineNetworkInstant -Text ([string]$sortedRequests[-1].t)
        if ($trafficFrom -and $trafficTo) {
            $windowFromOut = $trafficFrom.ToUniversalTime().ToString('o')
            $windowToOut = $trafficTo.ToUniversalTime().ToString('o')
        }
    }

    $available = ($sortedDns.Count -gt 0) -or ($sortedRequests.Count -gt 0) -or ($proxyLogs.Count -gt 0) -or ($pcaps.Count -gt 0)
    $message = ''
    if (-not $available) {
        $message = 'No proxy access logs or PCAP files found for this window. Ensure quarantine network mode with proxy/capture enabled during the test.'
    } elseif ($sortedDns.Count -eq 0 -and $sortedRequests.Count -eq 0) {
        $message = 'Proxy/PCAP sources were scanned but no DNS or HTTP requests matched the snapshot time window.'
    } elseif ($packageHits -gt 0 -and ($sortedRequests | Where-Object { $_.source -eq 'mitm' } | Select-Object -First 1)) {
        $message = "Includes evidence-network package(s) ($packageHits); decrypted HTTPS from mitmproxy flows.jsonl (click a request for bodies)."
    } elseif ($packageHits -gt 0 -and $sniCount -gt 0) {
        $message = "Includes evidence-network package(s) ($packageHits); TLS SNI from PCAP ($sniCount hosts) plus proxy access.log."
    } elseif ($packageHits -gt 0) {
        $message = "Includes evidence-network package(s) ($packageHits); hosts from proxy access.log (gateway clock may differ from host)."
    } elseif (@($proxyDns).Count -gt 0 -and $pcapDnsCount -eq 0) {
        $message = 'DNS hosts inferred from proxy HTTP traffic (no UDP/53 or TLS SNI in PCAP). Use capture mode guest-nic (VirtualBox NIC trace) and/or Sysmon DNS Event 22.'
    } elseif ($pcapDnsCount -gt 0) {
        $message = "Hosts from PCAP ($pcapDnsCount entries: DNS and/or TLS SNI). Sysmon DNS merged when present."
    }

    return [pscustomobject]@{
        available  = $available
        message    = $message
        windowFrom = $windowFromOut
        windowTo   = $windowToOut
        sources    = [ordered]@{
            proxyLogs = @($proxyLogs)
            pcaps     = @($pcaps)
            tshark    = if ($tshark) { $tshark } else { $null }
            evidencePackages = @($namedNetworkDirs)
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
            t       = if ($ts) { $ts.ToUniversalTime().ToString('o') } else { $timeText }
            query   = $query.TrimEnd('.')
            type    = ''
            source  = 'sysmon'
            image   = if ($ev.image) { [string]$ev.image } else { '' }
            answers = @()
        }
        $qr = if ($ev.PSObject.Properties['queryResults'] -and $ev.queryResults) { [string]$ev.queryResults } else { '' }
        if ($qr) {
            $answers = @()
            foreach ($part in ($qr -split '[;,\r\n]+')) {
                $p = $part.Trim()
                if (-not $p -or $p -match '^(?i)type:') { continue }
                if ($p -match '^(?i)A{1,4}:\s*(.+)$') { $p = $Matches[1].Trim() }
                if ($p -match '^\d+\.\d+\.\d+\.\d+$' -or ($p -match ':' -and $p -notmatch '[ /]')) {
                    if ($answers -notcontains $p) { $answers += $p }
                }
            }
            if ($answers.Count -gt 0) {
                $merged[-1].answers = $answers
                $merged[-1].type = 'A'
            }
        }
    }

    return @($merged | Sort-Object { $_.t }, { $_.query })
}
