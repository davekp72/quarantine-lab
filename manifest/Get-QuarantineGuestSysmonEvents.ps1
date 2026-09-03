#Requires -Version 5.1

<#

.SYNOPSIS

  Export Sysmon operational log events for manifest capture / diff.

#>

[CmdletBinding()]

param(

    [string]$BaselineFile = 'C:\Users\Public\Quarantine\usn-baseline.json',

    [string]$LogName = 'Microsoft-Windows-Sysmon/Operational',

    [int]$MaxEvents = 50000,

    [int[]]$IncludeEventIds = @(1, 2, 11, 12, 13, 22, 23, 26),

    [string]$OutFile = ''

)



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'

$privModule = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'QuarantineGuestPriv.psm1'
if (Test-Path -LiteralPath $privModule) {
    Import-Module $privModule -Force
    Enable-QuarantineManifestReadPrivileges
}



function Get-SysmonEventTypeName {

    param([int]$EventId)

    switch ($EventId) {

        1 { return 'ProcessCreate' }

        2 { return 'FileCreateTime' }

        11 { return 'FileCreate' }

        12 { return 'FileCreateStream' }

        13 { return 'RegistryEvent' }

        22 { return 'DnsQuery' }

        23 { return 'FileDelete' }

        26 { return 'FileDeleteDetected' }

        default { return "Event$EventId" }

    }

}



function Get-SysmonEventField {
    param(
        [hashtable]$Map,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Map.ContainsKey($Name)) {
        return [string]$Map[$Name]
    }
    return ''
}

function Get-SysmonEventDataMap {

    param($EventRecord)



    $map = @{}

    try {

        $xml = [xml]$EventRecord.ToXml()

        foreach ($node in $xml.Event.EventData.Data) {

            if ($node.Name) {

                $map[$node.Name] = [string]$node.'#text'

            }

        }

    } catch { }

    return $map

}



function ConvertFrom-SysmonEventRecord {

    param($EventRecord)



    $data = Get-SysmonEventDataMap -EventRecord $EventRecord

    $type = Get-SysmonEventTypeName -EventId $EventRecord.Id

    $entry = [ordered]@{

        id    = [int64]$EventRecord.RecordId

        eid   = [int]$EventRecord.Id

        type  = $type

        t     = $EventRecord.TimeCreated.ToUniversalTime().ToString('o')

    }



    switch ($EventRecord.Id) {

        1 {

            $entry.image = Get-SysmonEventField -Map $data -Name 'Image'
            $entry.commandLine = Get-SysmonEventField -Map $data -Name 'CommandLine'
            $entry.user = Get-SysmonEventField -Map $data -Name 'User'
            $entry.parentImage = Get-SysmonEventField -Map $data -Name 'ParentImage'
            $entry.summary = "$(Get-SysmonEventField -Map $data -Name 'Image') :: $(Get-SysmonEventField -Map $data -Name 'CommandLine')"

        }

        11 {

            $entry.target = Get-SysmonEventField -Map $data -Name 'TargetFilename'
            $entry.summary = Get-SysmonEventField -Map $data -Name 'TargetFilename'

        }

        12 {

            $entry.target = Get-SysmonEventField -Map $data -Name 'TargetFilename'
            $entry.summary = "$(Get-SysmonEventField -Map $data -Name 'TargetFilename') (stream)"

        }

        13 {

            $entry.targetObject = Get-SysmonEventField -Map $data -Name 'TargetObject'
            $entry.details = Get-SysmonEventField -Map $data -Name 'Details'
            $entry.summary = "$(Get-SysmonEventField -Map $data -Name 'TargetObject') = $(Get-SysmonEventField -Map $data -Name 'Details')"

        }

        22 {

            $entry.queryName = Get-SysmonEventField -Map $data -Name 'QueryName'
            $entry.image = Get-SysmonEventField -Map $data -Name 'Image'
            $entry.summary = "$(Get-SysmonEventField -Map $data -Name 'QueryName') ($(Get-SysmonEventField -Map $data -Name 'Image'))"

        }

        23 {

            $entry.target = Get-SysmonEventField -Map $data -Name 'TargetFilename'
            $entry.image = Get-SysmonEventField -Map $data -Name 'Image'
            $entry.summary = Get-SysmonEventField -Map $data -Name 'TargetFilename'

        }

        26 {

            $entry.target = Get-SysmonEventField -Map $data -Name 'TargetFilename'
            $entry.summary = Get-SysmonEventField -Map $data -Name 'TargetFilename'

        }

        default {

            $entry.summary = ($data.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '

        }

    }



    if ([string]::IsNullOrWhiteSpace([string]$entry.summary)) {

        $entry.summary = $type

    }



    return [pscustomobject]$entry

}



function Get-SysmonEventKey {

    param($Event)

    $parts = foreach ($name in @('eid', 't', 'image', 'target', 'targetObject', 'commandLine', 'queryName', 'details')) {
        if ($Event.PSObject.Properties[$name]) { [string]$Event.$name } else { '' }
    }
    return ($parts -join '|')

}



function Export-QuarantineGuestSysmonEvents {

    param(

        [string]$BaselineFilePath,

        [string]$OperationalLogName,

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



    $svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $svc) {
        return [pscustomobject]@{
            available  = $false
            eventCount = 0
            message    = "Sysmon not installed ($OperationalLogName)."
            events     = @()
        }
    }
    if ($svc.Status -ne 'Running') {
        return [pscustomobject]@{
            available  = $false
            eventCount = 0
            message    = 'Sysmon64 service is not running.'
            events     = @()
        }
    }

    $useEvtxPath = $false
    $evtxPath = Join-Path $env:SystemRoot 'System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
    try {
        $null = Get-WinEvent -LogName $OperationalLogName -MaxEvents 1 -ErrorAction Stop
    } catch {
        if (-not (Test-Path -LiteralPath $evtxPath)) {
            return [pscustomobject]@{
                available  = $false
                eventCount = 0
                message    = "Sysmon log not readable: $($_.Exception.Message)"
                events     = @()
            }
        }
        $useEvtxPath = $true
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
            $filter = @{ Id = $EventIds; StartTime = $since }
            if ($useEvtxPath) { $filter.Path = $evtxPath } else { $filter.LogName = $OperationalLogName }
            $records = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventCount -ErrorAction Stop
        } elseif ($useEvtxPath) {
            $records = Get-WinEvent -Path $evtxPath -MaxEvents ($MaxEventCount * 3) -ErrorAction Stop
        } else {
            $records = Get-WinEvent -LogName $OperationalLogName -MaxEvents ($MaxEventCount * 3) -ErrorAction Stop
        }



        foreach ($record in $records) {

            if ($record.Id -notin $EventIds) { continue }

            if ($since -and $record.TimeCreated.ToUniversalTime() -lt $since) { continue }

            try {
                $event = ConvertFrom-SysmonEventRecord -EventRecord $record
            } catch {
                continue
            }

            $key = Get-SysmonEventKey -Event $event
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            [void]$events.Add($event)

            if ($events.Count -ge $MaxEventCount) { break }

        }



        $ordered = @($events | Sort-Object { $_.t })

        return [pscustomobject]@{

            available  = $true

            eventCount = $ordered.Count

            logName    = $OperationalLogName

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
                logName    = $OperationalLogName
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



$result = Export-QuarantineGuestSysmonEvents -BaselineFilePath $BaselineFile -OperationalLogName $LogName -MaxEventCount $MaxEvents -EventIds $IncludeEventIds

if ($OutFile) {
    Write-QuarantineGuestJsonFile -Object $result -Path $OutFile -Depth 12
    Write-Output "SYSMON_EVENTS_WRITTEN $OutFile events=$($result.eventCount)"
}

