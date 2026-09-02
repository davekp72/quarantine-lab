#Requires -Version 5.1
<#
.SYNOPSIS
  Export System log service-install events (7045) for manifest capture / diff.
#>
[CmdletBinding()]
param(
    [string]$BaselineFile = 'C:\Users\Public\Quarantine\usn-baseline.json',
    [string]$LogName = 'System',
    [int]$MaxEvents = 500,
    [int[]]$IncludeEventIds = @(7045),
    [string]$OutFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$privModule = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'QuarantineGuestPriv.psm1'
if (Test-Path -LiteralPath $privModule) {
    try {
        Import-Module $privModule -Force -ErrorAction Stop
        Enable-QuarantineManifestReadPrivileges
    } catch { }
}

function Get-MapValue {
    param(
        [object]$Map,
        [Parameter(Mandatory)][string[]]$Keys
    )

    foreach ($key in $Keys) {
        if ($null -eq $Map) { continue }
        if ($Map -is [System.Collections.IDictionary] -and $Map.Contains($key)) {
            return [string]$Map[$key]
        }
    }
    return ''
}

function Get-ServiceInstallEventDataMap {
    param($EventRecord)

    $map = [ordered]@{}
    try {
        $xml = [xml]$EventRecord.ToXml()
        $index = 0
        foreach ($node in $xml.Event.EventData.Data) {
            $name = [string]$node.Name
            $value = [string]$node.'#text'
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "param$index"
                $index++
            }
            $map[$name] = $value
        }
    } catch { }

    return $map
}

function ConvertFrom-ServiceInstallEventRecord {
    param($EventRecord)

    $data = Get-ServiceInstallEventDataMap -EventRecord $EventRecord
    $values = @($data.Values)

    $serviceName = Get-MapValue -Map $data -Keys @('ServiceName', 'param1')
    if (-not $serviceName -and $values.Count -gt 0) { $serviceName = [string]$values[0] }

    $imagePath = Get-MapValue -Map $data -Keys @('ImagePath', 'param2')
    if (-not $imagePath -and $values.Count -gt 1) { $imagePath = [string]$values[1] }

    $serviceType = Get-MapValue -Map $data -Keys @('ServiceType', 'param3')
    if (-not $serviceType -and $values.Count -gt 2) { $serviceType = [string]$values[2] }

    $startType = Get-MapValue -Map $data -Keys @('StartType', 'param4')
    if (-not $startType -and $values.Count -gt 3) { $startType = [string]$values[3] }

    $accountName = Get-MapValue -Map $data -Keys @('AccountName', 'param5')
    if (-not $accountName -and $values.Count -gt 4) { $accountName = [string]$values[4] }

    $summary = if ($serviceName -and $imagePath) { "$serviceName -> $imagePath" }
        elseif ($serviceName) { $serviceName }
        elseif ($imagePath) { $imagePath }
        else { 'Service installed' }

    return [pscustomobject][ordered]@{
        id           = [string]$EventRecord.RecordId
        eid          = [int]$EventRecord.Id
        t            = $EventRecord.TimeCreated.ToUniversalTime().ToString('o')
        type         = 'ServiceInstall'
        serviceName  = $serviceName
        imagePath    = $imagePath
        serviceType  = $serviceType
        startType    = $startType
        accountName  = $accountName
        summary      = $summary
    }
}

function Get-ServiceInstallEventKey {
    param($Event)

    $parts = @(
        [string]$Event.eid,
        [string]$Event.t,
        [string]$Event.serviceName,
        [string]$Event.imagePath
    )
    return ($parts -join '|')
}

function Export-QuarantineGuestServiceInstallEvents {
    param(
        [string]$BaselineFilePath,
        [string]$SystemLogName,
        [int]$MaxEventCount,
        [int[]]$EventIds
    )

    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            available  = $false
            eventCount = 0
            message    = 'Get-WinEvent not available.'
            events     = @()
        }
    }

    $since = $null
    $baselineAt = $null
    if (Test-Path -LiteralPath $BaselineFilePath) {
        try {
            $baseline = Get-Content -LiteralPath $BaselineFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($baseline.recordedAt) {
                $baselineAt = [string]$baseline.recordedAt
                $since = [datetime]::Parse($baselineAt, $null, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            }
        } catch { }
    }

    $events = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    try {
        if ($since) {
            $filter = @{ Id = $EventIds; StartTime = $since; LogName = $SystemLogName }
            $records = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventCount -ErrorAction Stop
        } else {
            $records = Get-WinEvent -LogName $SystemLogName -MaxEvents ($MaxEventCount * 3) -ErrorAction Stop
        }

        foreach ($record in $records) {
            if ($record.Id -notin $EventIds) { continue }
            if ($since -and $record.TimeCreated.ToUniversalTime() -lt $since) { continue }

            try {
                $event = ConvertFrom-ServiceInstallEventRecord -EventRecord $record
            } catch {
                continue
            }

            $key = Get-ServiceInstallEventKey -Event $event
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            [void]$events.Add($event)
            if ($events.Count -ge $MaxEventCount) { break }
        }

        $ordered = @($events | Sort-Object { $_.t })
        return [pscustomobject]@{
            available  = $true
            eventCount = $ordered.Count
            logName    = $SystemLogName
            baselineAt = $baselineAt
            recordedAt = (Get-Date).ToUniversalTime().ToString('o')
            truncated  = ($events.Count -ge $MaxEventCount)
            events     = @($ordered)
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found that match the specified selection criteria') {
            return [pscustomobject]@{
                available  = $true
                eventCount = 0
                logName    = $SystemLogName
                baselineAt = $baselineAt
                recordedAt = (Get-Date).ToUniversalTime().ToString('o')
                truncated  = $false
                events     = @()
            }
        }
        return [pscustomobject]@{
            available  = $false
            eventCount = 0
            message    = $_.Exception.Message
            events     = @()
        }
    }
}

$result = $null
try {
    $result = Export-QuarantineGuestServiceInstallEvents `
        -BaselineFilePath $BaselineFile `
        -SystemLogName $LogName `
        -MaxEventCount $MaxEvents `
        -EventIds $IncludeEventIds
} catch {
    $result = [pscustomobject]@{
        available  = $false
        eventCount = 0
        message    = $_.Exception.Message
        events     = @()
    }
}

if ($OutFile) {
    try {
        if (Get-Command Write-QuarantineGuestJsonFile -ErrorAction SilentlyContinue) {
            Write-QuarantineGuestJsonFile -Object $result -Path $OutFile -Depth 12
        } else {
            $result | ConvertTo-Json -Depth 12 -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
        }
    } catch {
        [ordered]@{
            available  = $false
            eventCount = 0
            message    = $_.Exception.Message
            events     = @()
        } | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }
    Write-Output "SERVICE_INSTALL_EVENTS_WRITTEN $OutFile events=$($result.eventCount)"
}
