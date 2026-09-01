#Requires -Version 5.1
<#
.SYNOPSIS
  Diff two quarantine guest manifest JSON files (filesystem + registry + tasks).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$From,

    [Parameter(Mandatory)]
    [string]$To,

    [string]$ReportPath,

    [string]$JsonPath,

    [string]$ConfigPath,

    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Get-QuarantineManifestDiff.ps1')

$diff = Get-QuarantineManifestDiff -From $From -To $To -ConfigPath $ConfigPath
$left = Get-Content -LiteralPath $From -Raw -Encoding UTF8 | ConvertFrom-Json
$right = Get-Content -LiteralPath $To -Raw -Encoding UTF8 | ConvertFrom-Json

$summary = $diff.summary

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('=== Quarantine manifest diff ===') | Out-Null
$lines.Add("From: $From ($($left.snapshot)) @ $($left.capturedAt)") | Out-Null
$lines.Add("To:   $To ($($right.snapshot)) @ $($right.capturedAt)") | Out-Null
$lines.Add('') | Out-Null
$lines.Add('--- Summary ---') | Out-Null
$summary.GetEnumerator() | ForEach-Object {
    $lines.Add("$($_.Key): $($_.Value)") | Out-Null
}

function Append-Section {
    param([string]$Title, [array]$Items, [scriptblock]$Formatter)
    if (@($Items).Count -eq 0) { return }
    [void]$lines.Add('')
    [void]$lines.Add("--- $Title ($(@($Items).Count)) ---")
    foreach ($item in $Items) {
        $formatted = & $Formatter $item
        [void]$lines.Add($formatted)
    }
}

Append-Section -Title 'Files added' -Items $diff.files.added -Formatter { param($x) "  + $($x.path)" }
Append-Section -Title 'Files removed' -Items $diff.files.removed -Formatter { param($x) "  - $($x.path)" }
Append-Section -Title 'Files modified' -Items $diff.files.modified -Formatter {
    param($x) "  ~ $($x.path) size $($x.fromSize)->$($x.toSize) hash $($x.fromHash)->$($x.toHash)"
}
Append-Section -Title 'Registry added' -Items $diff.registry.added -Formatter {
    param($x) "  + $($x.key)[$($x.name)] = $($x.value)"
}
Append-Section -Title 'Registry removed' -Items $diff.registry.removed -Formatter {
    param($x) "  - $($x.key)[$($x.name)] = $($x.value)"
}
Append-Section -Title 'Registry modified' -Items $diff.registry.modified -Formatter {
    param($x) "  ~ $($x.key)[$($x.name)] $($x.fromValue) -> $($x.toValue)"
}
Append-Section -Title 'Scheduled tasks added' -Items $diff.tasks.added -Formatter {
    param($x) "  + $($x.TaskName) | $($x.TaskToRun)"
}
Append-Section -Title 'Scheduled tasks removed' -Items $diff.tasks.removed -Formatter {
    param($x) "  - $($x.TaskName) | $($x.TaskToRun)"
}
Append-Section -Title 'Scheduled tasks modified' -Items $diff.tasks.modified -Formatter {
    param($x) "  ~ $($x.taskName) command $($x.fromTaskToRun) -> $($x.toTaskToRun)"
}
Append-Section -Title 'Scheduled tasks (schedule noise only)' -Items $diff.tasks.volatileOnly -Formatter {
    param($x) "  ~ $($x.taskName) lastRun $($x.fromLastRun) -> $($x.toLastRun)"
}
Append-Section -Title 'Sysmon events (new in To snapshot)' -Items $diff.sysmon.added -Formatter {
    param($x) "  + [$($x.type)] $($x.t) $($x.summary)"
}
if ($diff.network) {
    Append-Section -Title 'DNS lookups (proxy/PCAP/Sysmon)' -Items $diff.network.dns -Formatter {
        param($x) "  + [$($x.source)] $($x.t) $($x.query)$(if ($x.type) { " ($($x.type))" })"
    }
    Append-Section -Title 'HTTP/proxy requests' -Items $diff.network.requests -Formatter {
        param($x) "  + [$($x.source)] $($x.t) $($x.method) $($x.url)"
    }
}

$text = $lines -join [Environment]::NewLine
Write-Output $text

if ($ReportPath) {
    $reportDir = Split-Path -Parent $ReportPath
    if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $text | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "Report: $ReportPath"
}

if ($JsonPath) {
    $jsonDir = Split-Path -Parent $JsonPath
    if ($jsonDir -and -not (Test-Path -LiteralPath $jsonDir)) {
        New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null
    }
    $diff | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $JsonPath -Encoding UTF8
    Write-Host "Diff JSON: $JsonPath"
}

if ($PassThru) {
    return $diff
}
