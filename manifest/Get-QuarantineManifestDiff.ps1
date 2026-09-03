#Requires -Version 5.1
<#
.SYNOPSIS
  Build a structured diff object from two quarantine guest manifest JSON files.
#>
Set-StrictMode -Version Latest

if (-not (Get-Command ConvertFrom-RegshotCompareLog -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ConvertFrom-RegshotCompareLog.ps1')
}
if (-not (Get-Command Get-QuarantineNetworkEvidence -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'Get-QuarantineNetworkEvidence.ps1')
}

function Get-ManifestStringProperty {
    param(
        [object]$Manifest,
        [string]$Name
    )

    if ($null -eq $Manifest) { return '' }
    if ($Manifest.PSObject.Properties[$Name]) { return [string]$Manifest.$Name }
    return ''
}

function Read-QuarantineManifestFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Manifest not found: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    try {
        return $raw | ConvertFrom-Json
    } catch {
        # Guest copy occasionally appends trailing noise after the JSON line.
        $firstLine = Get-Content -LiteralPath $Path -TotalCount 1 -Encoding UTF8
        if ($firstLine) {
            return $firstLine | ConvertFrom-Json
        }
        throw
    }
}

function Get-RegistryEntryKey {
    param([object]$Entry)
    return "$($Entry.k)|$($Entry.n)"
}

function ConvertFrom-TaskCsvLine {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    if ($Line -match '^"HostName"') { return $null }

    $headers = @(
        'HostName', 'TaskName', 'NextRunTime', 'Status', 'LogonMode', 'LastRunTime',
        'LastResult', 'Author', 'TaskToRun', 'StartIn', 'Comment', 'ScheduledTaskState',
        'IdleTime', 'PowerManagement', 'RunAsUser', 'DeleteTaskIfNotRescheduled',
        'StopTaskIfRuns', 'Schedule', 'ScheduleType', 'StartTime', 'StartDate', 'EndDate',
        'Days', 'Months', 'RepeatEvery', 'RepeatUntilTime', 'RepeatUntilDuration',
        'RepeatStopIfStillRunning'
    )

    try {
        $row = $Line | ConvertFrom-Csv -Header $headers
        if (-not $row.TaskName) { return $null }
        return [pscustomobject]@{
            TaskName            = $row.TaskName
            Status              = $row.Status
            TaskToRun           = $row.TaskToRun
            RunAsUser           = $row.RunAsUser
            Comment             = $row.Comment
            ScheduledTaskState  = $row.ScheduledTaskState
            LastRunTime         = $row.LastRunTime
            NextRunTime         = $row.NextRunTime
            Line                = $Line
        }
    } catch {
        return $null
    }
}

function Get-TaskStableFingerprint {
    param([object]$Task)
    $parts = @($Task.TaskToRun, $Task.Status, $Task.RunAsUser, $Task.Comment, $Task.ScheduledTaskState)
    return ($parts -join '|')
}

function Get-FileDiffDetail {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$Entry
    )

    $detail = [ordered]@{
        path  = $Path
        size  = [int64]$Entry.s
        hash  = [string]$Entry.h
        mtime = [string]$Entry.m
    }

    if ($Entry.PSObject.Properties['c']) {
        $detail.contentEncoding = [string]$Entry.c
    }
    if ($Entry.PSObject.Properties['d']) {
        $detail.content = [string]$Entry.d
    }

    return [pscustomobject]$detail
}

function Get-SysmonEventFieldValue {
    param(
        $Event,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Event) { return '' }
    if ($Event.PSObject.Properties[$Name]) {
        return [string]$Event.$Name
    }
    return ''
}

function Get-SysmonEventKey {
    param($Event)

    $explicit = Get-SysmonEventFieldValue -Event $Event -Name 'key'
    if (-not [string]::IsNullOrWhiteSpace($explicit)) {
        return $explicit
    }

    $parts = foreach ($name in @('eid', 't', 'image', 'target', 'targetObject', 'commandLine', 'queryName', 'details', 'summary', 'id')) {
        Get-SysmonEventFieldValue -Event $Event -Name $name
    }
    $key = ($parts -join '|')
    if ([string]::IsNullOrWhiteSpace($key)) {
        return ('sysmon|{0}' -f [guid]::NewGuid().ToString('n'))
    }
    return $key
}

function Get-SysmonEventsFromManifest {
    param($Manifest)
    if (-not $Manifest) { return @() }
    if (-not $Manifest.PSObject.Properties['sysmon']) { return @() }
    $sysmon = $Manifest.sysmon
    if (-not $sysmon) { return @() }
    if ($sysmon.PSObject.Properties['available'] -and $sysmon.available -eq $false) { return @() }
    if (-not $sysmon.PSObject.Properties['events']) { return @() }
    return @($sysmon.events)
}

function Get-SysmonSectionFromManifest {
    param($Manifest)
    if (-not $Manifest -or -not $Manifest.PSObject.Properties['sysmon']) {
        return [pscustomobject]@{ available = $false; message = 'Sysmon not captured in manifest.'; events = @() }
    }
    return $Manifest.sysmon
}

function Get-ServiceInstallEventsFromManifest {
    param($Manifest)
    if (-not $Manifest) { return @() }
    if (-not $Manifest.PSObject.Properties['serviceInstalls']) { return @() }
    $section = $Manifest.serviceInstalls
    if (-not $section) { return @() }
    if ($section.PSObject.Properties['available'] -and $section.available -eq $false) { return @() }
    if (-not $section.PSObject.Properties['events']) { return @() }
    return @($section.events)
}

function Get-ServiceInstallEventKey {
    param($Event)
    $parts = foreach ($name in @('eid', 't', 'serviceName', 'imagePath', 'summary', 'id')) {
        Get-SysmonEventFieldValue -Event $Event -Name $name
    }
    $key = ($parts -join '|')
    if ([string]::IsNullOrWhiteSpace($key)) {
        return ('service-install|{0}' -f [guid]::NewGuid().ToString('n'))
    }
    return $key
}

function Get-ServiceInstallSectionFromManifest {
    param($Manifest)
    if (-not $Manifest -or -not $Manifest.PSObject.Properties['serviceInstalls']) {
        return [pscustomobject]@{ available = $false; message = 'Service install events not captured in manifest.'; events = @() }
    }
    return $Manifest.serviceInstalls
}

function Get-ManifestScanMode {
    param($Manifest)
    if (-not $Manifest) { return 'full' }
    if ($Manifest.PSObject.Properties['scanMode'] -and -not [string]::IsNullOrWhiteSpace([string]$Manifest.scanMode)) {
        return [string]$Manifest.scanMode
    }
    $fc = if ($Manifest.PSObject.Properties['fileCount']) { [int]$Manifest.fileCount } else { @($Manifest.files).Count }
    if ($fc -eq 0) { return 'events' }
    return 'full'
}

function Resolve-UsnEventPath {
    param($Event)
    $name = Get-SysmonEventFieldValue -Event $Event -Name 'fileName'
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    if ($name -match '^[A-Za-z]:\\') { return $name }
    if ($name.StartsWith('\')) { return "C:$name" }
    if ($name -match '(^|\\)hosts$') { return 'C:\Windows\System32\drivers\etc\hosts' }
    return "C:\$name"
}

function Get-UsnChangeKind {
    param([string[]]$Reasons)
    $r = @($Reasons)
    if ($r -contains 'file_delete') { return 'removed' }
    if ($r -contains 'file_create' -or $r -contains 'rename_new_name') { return 'added' }
    if ($r -contains 'rename_old_name') { return 'removed' }
    return 'modified'
}

function Get-UsnEventKey {
    param($Event)
    $parts = @(
        (Get-SysmonEventFieldValue -Event $Event -Name 'usn'),
        (Get-SysmonEventFieldValue -Event $Event -Name 'timestamp'),
        (Get-SysmonEventFieldValue -Event $Event -Name 'fileName'),
        (($Event.reasons | ForEach-Object { [string]$_ }) -join ',')
    )
    return ($parts -join '|')
}

function Test-QuarantineVolatileRegistryEntry {
    param($Entry)

    $key = if ($Entry.key) { [string]$Entry.key } elseif ($Entry.k) { [string]$Entry.k } else { '' }
    if ([string]::IsNullOrWhiteSpace($key)) { return $false }

    $volatilePatterns = @(
        '\\IrisService\\Cache\\',
        '\\TaskCache\\Tasks\\\{',
        '\\Explorer\\SessionInfo\\',
        '\\ContentDeliveryManager\\',
        '\\InstallService\\State',
        '\\Volatile Environment\\',
        '\\BackgroundActivityModerator\\',
        '\\BAM\\State\\',
        '\\DAM\\State\\'
    )
    foreach ($pattern in $volatilePatterns) {
        if ($key -match $pattern) { return $true }
    }
    return $false
}

function Get-EventDerivedFileChanges {
    <#
    .SYNOPSIS
      Build file added/removed/modified lists from USN + Sysmon on the To manifest.
      When Left is supplied, only events present in To but not in From are used (incremental diff).
    #>
    param(
        [object]$Left,
        [Parameter(Mandatory)]
        [object]$Right,
        [hashtable]$ScannedFiles = @{},
        [hashtable]$LeftScannedFiles = @{}
    )

    $kinds = @{}
    $sources = @{}

    $leftUsnKeys = @{}
    if ($Left -and $Left.PSObject.Properties['usn'] -and $Left.usn -and $Left.usn.events) {
        foreach ($ev in @($Left.usn.events)) {
            $leftUsnKeys[(Get-UsnEventKey -Event $ev)] = $true
        }
    }

    if ($Right.PSObject.Properties['usn'] -and $Right.usn -and $Right.usn.available -eq $true -and $Right.usn.events) {
        foreach ($ev in @($Right.usn.events)) {
            if ($Left -and $leftUsnKeys.ContainsKey((Get-UsnEventKey -Event $ev))) { continue }
            $path = Resolve-UsnEventPath -Event $ev
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $kind = Get-UsnChangeKind -Reasons @($ev.reasons)
            $kinds[$path] = $kind
            $sources[$path] = 'usn'
        }
    }

    $leftSysmonKeys = @{}
    if ($Left) {
        foreach ($ev in (Get-SysmonEventsFromManifest -Manifest $Left)) {
            $leftSysmonKeys[(Get-SysmonEventKey -Event $ev)] = $true
        }
    }

    foreach ($ev in (Get-SysmonEventsFromManifest -Manifest $Right)) {
        if ($Left -and $leftSysmonKeys.ContainsKey((Get-SysmonEventKey -Event $ev))) { continue }
        $eid = 0
        if ($ev.PSObject.Properties['eid']) { $eid = [int]$ev.eid }
        if ($eid -notin @(2, 11, 12, 23, 26)) { continue }
        $path = Get-SysmonEventFieldValue -Event $ev -Name 'target'
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $kind = if ($eid -in @(23, 26)) { 'removed' } elseif ($eid -eq 2) { 'modified' } else { 'added' }
        if (-not $kinds.ContainsKey($path) -or $kind -eq 'removed' -or ($kind -eq 'modified' -and $kinds[$path] -ne 'removed')) {
            $kinds[$path] = $kind
            $sources[$path] = 'sysmon'
        }
    }

    $added = New-Object System.Collections.Generic.List[object]
    $removed = New-Object System.Collections.Generic.List[object]
    $modified = New-Object System.Collections.Generic.List[object]

    foreach ($path in ($kinds.Keys | Sort-Object)) {
        $kind = $kinds[$path]
        $src = $sources[$path]
        $scan = if ($ScannedFiles.ContainsKey($path)) { $ScannedFiles[$path] } else { $null }

        if ($kind -eq 'added') {
            if ($scan) {
                $detail = Get-FileDiffDetail -Path $path -Entry $scan
                $detail | Add-Member -NotePropertyName source -NotePropertyValue $src -Force
                $added.Add($detail) | Out-Null
            } else {
                $added.Add([pscustomobject]@{
                    path   = $path
                    size   = $null
                    hash   = $null
                    mtime  = $null
                    source = $src
                }) | Out-Null
            }
        } elseif ($kind -eq 'removed') {
            if ($scan) {
                $detail = Get-FileDiffDetail -Path $path -Entry $scan
                $detail | Add-Member -NotePropertyName source -NotePropertyValue $src -Force
                $removed.Add($detail) | Out-Null
            } else {
                $removed.Add([pscustomobject]@{
                    path   = $path
                    size   = $null
                    hash   = $null
                    mtime  = $null
                    source = $src
                }) | Out-Null
            }
        } else {
            $leftScan = if ($LeftScannedFiles.ContainsKey($path)) { $LeftScannedFiles[$path] } else { $null }
            $rightScan = if ($ScannedFiles.ContainsKey($path)) { $ScannedFiles[$path] } else { $null }
            if ($leftScan -or $rightScan) {
                $item = [ordered]@{
                    path      = $path
                    fromSize  = if ($leftScan) { [int64]$leftScan.s } else { $null }
                    toSize    = if ($rightScan) { [int64]$rightScan.s } else { $null }
                    fromHash  = if ($leftScan) { [string]$leftScan.h } else { $null }
                    toHash    = if ($rightScan) { [string]$rightScan.h } else { $null }
                    fromMtime = if ($leftScan) { [string]$leftScan.m } else { $null }
                    toMtime   = if ($rightScan) { [string]$rightScan.m } else { $null }
                    source    = $src
                }
                if ($leftScan -and $leftScan.PSObject.Properties['c']) { $item.fromContentEncoding = [string]$leftScan.c }
                if ($leftScan -and $leftScan.PSObject.Properties['d']) { $item.fromContent = [string]$leftScan.d }
                if ($rightScan -and $rightScan.PSObject.Properties['c']) { $item.toContentEncoding = [string]$rightScan.c }
                if ($rightScan -and $rightScan.PSObject.Properties['d']) { $item.toContent = [string]$rightScan.d }
                $modified.Add([pscustomobject]$item) | Out-Null
            } else {
                $modified.Add([pscustomobject]@{
                    path   = $path
                    source = $src
                }) | Out-Null
            }
        }
    }

    return [pscustomobject]@{
        added    = $added.ToArray()
        removed  = $removed.ToArray()
        modified = $modified.ToArray()
    }
}

function Get-EnrichableFilePathsFromManifest {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,
        [switch]$ExistingOnly
    )

    $derived = Get-EventDerivedFileChanges -Right $Manifest
    $paths = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    foreach ($bucket in @($derived.added, $derived.modified)) {
        foreach ($item in @($bucket)) {
            $p = [string]$item.path
            if ([string]::IsNullOrWhiteSpace($p) -or $seen.ContainsKey($p)) { continue }
            if ($ExistingOnly -and -not ($p -match '^[A-Za-z]:\\')) { continue }
            $seen[$p] = $true
            $paths.Add($p) | Out-Null
        }
    }

    return @($paths)
}

function Get-QuarantineManifestCompareWarnings {
    param(
        [object]$Left,
        [object]$Right
    )

    $warnings = New-Object System.Collections.Generic.List[string]
    if (-not $Left -or -not $Right) { return @() }

    $fromSnapName = Get-ManifestStringProperty -Manifest $Left -Name 'snapshot'
    $toSnapName = Get-ManifestStringProperty -Manifest $Right -Name 'snapshot'
    if ($fromSnapName -match '^Evidence-' -and $toSnapName -match '^Evidence-') {
        [void]$warnings.Add(
            'Snapshot-pair compare: files, registry, Sysmon, and USN show changes in To that were not in From. Background OS activity between preserves may still appear.'
        )
    }

    $fromCount = if ($Left.PSObject.Properties['fileCount'] -and $null -ne $Left.fileCount) {
        [int]$Left.fileCount
    } else {
        @($Left.files).Count
    }
    $toCount = if ($Right.PSObject.Properties['fileCount'] -and $null -ne $Right.fileCount) {
        [int]$Right.fileCount
    } else {
        @($Right.files).Count
    }

    try {
        $fromAt = [datetimeoffset]::Parse([string]$Left.capturedAt)
        $toAt = [datetimeoffset]::Parse([string]$Right.capturedAt)
        if ($toAt -lt $fromAt) {
            [void]$warnings.Add(
                "To manifest ($($Right.snapshot), $($Right.capturedAt)) is older than From ($($Left.snapshot), $($Left.capturedAt)). Re-capture To before trusting file changes."
            )
        }
    } catch { }

    if ($fromCount -gt 0) {
        $delta = [math]::Abs($fromCount - $toCount) / [double]$fromCount
        if ($delta -gt 0.15) {
            [void]$warnings.Add(
                "Scan coverage differs (From: $fromCount files, To: $toCount files). Large removed/added lists may be scanner scope noise, not malware activity."
            )
        }
    } elseif ((Get-ManifestScanMode -Manifest $Left) -eq 'events' -or (Get-ManifestScanMode -Manifest $Right) -eq 'events') {
        # Expected for event-first manifests — file changes come from USN/Sysmon.
    }

    $leftVer = if ($Left.PSObject.Properties['version']) { [int]$Left.version } else { 1 }
    $rightVer = if ($Right.PSObject.Properties['version']) { [int]$Right.version } else { 1 }
    if ($leftVer -ne $rightVer) {
        [void]$warnings.Add("Manifest version mismatch (From v$leftVer, To v$rightVer). Re-capture both snapshots.")
    }

    $fromHku = if ($Left.PSObject.Properties['userRegistryCount']) { [int]$Left.userRegistryCount } else { @($Left.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }
    $toHku = if ($Right.PSObject.Properties['userRegistryCount']) { [int]$Right.userRegistryCount } else { @($Right.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }
    $regshotEngine = ($Right.PSObject.Properties['registryEngine'] -and [string]$Right.registryEngine -eq 'regshot') -or
        ($Right.PSObject.Properties['regshot'] -and $Right.regshot)
    $cliEngine = ($Left.PSObject.Properties['registryEngine'] -and [string]$Left.registryEngine -eq 'cli') -or
        ($Right.PSObject.Properties['registryEngine'] -and [string]$Right.registryEngine -eq 'cli')
    if (-not $regshotEngine -and -not $cliEngine -and ($fromHku -eq 0 -or $toHku -eq 0)) {
        [void]$warnings.Add("HKU (local user) registry missing from one or both manifests (From: $fromHku entries, To: $toHku entries). User registry changes will not appear until live snapshot mark or NTUSER.DAT offline load succeeds.")
    }
    if ($cliEngine -and ($fromHku -eq 0 -or $toHku -eq 0)) {
        [void]$warnings.Add('Payload registry sidecar missing for one or both snapshots. Live snapshot/preserve marks reg.exe export automatically; re-run manifest mark if needed.')
    }
    if ($regshotEngine -and (-not $Right.regshot -or -not $Right.regshot.compareLog)) {
        [void]$warnings.Add('Regshot registry compare missing on To manifest. Run reset -Clean, regshot copy, then manifest view -Refresh.')
    }

    foreach ($side in @(@{ Label = 'From'; Manifest = $Left }, @{ Label = 'To'; Manifest = $Right })) {
        $wlist = if ($side.Manifest.PSObject.Properties['userRegistryWarnings']) { @($side.Manifest.userRegistryWarnings) } else { @() }
        foreach ($w in $wlist) {
            if ($w) { [void]$warnings.Add("$($side.Label) manifest: $w") }
        }
    }

    $toUsn = if ($Right.PSObject.Properties['usn']) { $Right.usn } else { $null }
    if (-not $toUsn -or $toUsn.available -eq $false) {
        $msg = if ($toUsn -and $toUsn.message) { [string]$toUsn.message } else { 'USN journal not captured in To manifest.' }
        if ($msg -match 'endusn=') {
            $msg = "$msg (stale guest USN script - re-capture with -Refresh after updating repo)."
        }
        [void]$warnings.Add("To USN: $msg Run reset -Clean (auto-mark) before the test, then re-capture To.")
    }

    $expectedGuestScriptVersion = 4
    foreach ($side in @(@{ Label = 'From'; Manifest = $Left }, @{ Label = 'To'; Manifest = $Right })) {
        $gsv = if ($side.Manifest.PSObject.Properties['guestScriptVersion']) { [int]$side.Manifest.guestScriptVersion } else { 0 }
        if ($gsv -lt $expectedGuestScriptVersion) {
            [void]$warnings.Add("$($side.Label) manifest guestScriptVersion=$gsv (expected $expectedGuestScriptVersion). Re-capture with -Refresh to pick up HKU/USN fixes.")
        }
    }

    $toSysmon = if ($Right.PSObject.Properties['sysmon']) { $Right.sysmon } else { $null }
    if (-not $toSysmon -or $toSysmon.available -eq $false) {
        $msg = if ($toSysmon -and $toSysmon.message) { [string]$toSysmon.message } else { 'Sysmon not captured in To manifest.' }
        [void]$warnings.Add("To Sysmon: $msg Place Sysmon64.exe in tools\ and re-capture, or run .\quarantine-vm.ps1 sysmon install.")
    }

    return @($warnings)
}

function Get-QuarantineManifestDiff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$From,

        [Parameter(Mandatory)]
        [string]$To,

        [string]$ConfigPath
    )

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\quarantine-vm.json'
    }

    $left = Read-QuarantineManifestFile -Path $From
    $right = Read-QuarantineManifestFile -Path $To

    $leftFiles = @{}
    foreach ($f in @($left.files)) { if ($f.p) { $leftFiles[$f.p] = $f } }
    $rightFiles = @{}
    foreach ($f in @($right.files)) { if ($f.p) { $rightFiles[$f.p] = $f } }

    $addedFiles = @(
        $rightFiles.Keys |
            Where-Object { -not $leftFiles.ContainsKey($_) } |
            Sort-Object |
            ForEach-Object { Get-FileDiffDetail -Path $_ -Entry $rightFiles[$_] }
    )
    $removedFiles = @(
        $leftFiles.Keys |
            Where-Object { -not $rightFiles.ContainsKey($_) } |
            Sort-Object |
            ForEach-Object { Get-FileDiffDetail -Path $_ -Entry $leftFiles[$_] }
    )
    $modifiedFiles = @()
    foreach ($p in $leftFiles.Keys) {
        if (-not $rightFiles.ContainsKey($p)) { continue }
        $a = $leftFiles[$p]; $b = $rightFiles[$p]
        if ($a.h -ne $b.h -or [int64]$a.s -ne [int64]$b.s) {
            $item = [ordered]@{
                path      = $p
                fromSize  = [int64]$a.s
                toSize    = [int64]$b.s
                fromHash  = [string]$a.h
                toHash    = [string]$b.h
                fromMtime = [string]$a.m
                toMtime   = [string]$b.m
            }
            if ($a.PSObject.Properties['c']) { $item.fromContentEncoding = [string]$a.c }
            if ($a.PSObject.Properties['d']) { $item.fromContent = [string]$a.d }
            if ($b.PSObject.Properties['c']) { $item.toContentEncoding = [string]$b.c }
            if ($b.PSObject.Properties['d']) { $item.toContent = [string]$b.d }
            $modifiedFiles += [pscustomobject]$item
        }
    }

    $leftReg = @{}
    foreach ($r in @($left.registry)) { $leftReg[(Get-RegistryEntryKey $r)] = $r }
    $rightReg = @{}
    foreach ($r in @($right.registry)) { $rightReg[(Get-RegistryEntryKey $r)] = $r }

    $addedReg = @()
    $removedReg = @()
    $modifiedReg = @()
    $registryDiffSource = 'legacy'

    $useRegshot = $false
    if ($right.PSObject.Properties['registryEngine'] -and [string]$right.registryEngine -eq 'regshot') {
        $useRegshot = $true
    } elseif ($right.PSObject.Properties['regshot'] -and $right.regshot) {
        $useRegshot = $true
    }

    if ($useRegshot -and $right.regshot) {
        $registryDiffSource = 'regshot'
        $addedReg = @($right.regshot.added)
        $removedReg = @($right.regshot.removed)
        $modifiedReg = @($right.regshot.modified)
        if (@($addedReg).Count -eq 0 -and @($removedReg).Count -eq 0 -and @($modifiedReg).Count -eq 0) {
            $logPath = if ($right.regshot.PSObject.Properties['compareLog']) { [string]$right.regshot.compareLog } else { '' }
            if ($logPath -and (Test-Path -LiteralPath $logPath)) {
                $parsed = ConvertFrom-RegshotCompareLog -Path $logPath
                $addedReg = @($parsed.added)
                $removedReg = @($parsed.removed)
                $modifiedReg = @($parsed.modified)
            }
        }
    } else {
        foreach ($k in ($rightReg.Keys | Where-Object { -not $leftReg.ContainsKey($_) } | Sort-Object)) {
            $r = $rightReg[$k]
            $addedReg += [pscustomobject]@{
                key   = [string]$r.k
                name  = [string]$r.n
                type  = [string]$r.t
                value = [string]$r.v
            }
        }
        foreach ($k in ($leftReg.Keys | Where-Object { -not $rightReg.ContainsKey($_) } | Sort-Object)) {
            $r = $leftReg[$k]
            $removedReg += [pscustomobject]@{
                key   = [string]$r.k
                name  = [string]$r.n
                type  = [string]$r.t
                value = [string]$r.v
            }
        }
        foreach ($k in $leftReg.Keys) {
            if (-not $rightReg.ContainsKey($k)) { continue }
            if ($leftReg[$k].h -ne $rightReg[$k].h) {
                $modifiedReg += [pscustomobject]@{
                    key      = [string]$leftReg[$k].k
                    name     = [string]$leftReg[$k].n
                    fromValue = [string]$leftReg[$k].v
                    toValue   = [string]$rightReg[$k].v
                }
            }
        }
    }

    $registryVolatileFiltered = 0
    if (-not $useRegshot) {
        $filteredAdded = New-Object System.Collections.Generic.List[object]
        foreach ($item in @($addedReg)) {
            if (Test-QuarantineVolatileRegistryEntry -Entry $item) { $registryVolatileFiltered++ } else { $filteredAdded.Add($item) | Out-Null }
        }
        $addedReg = $filteredAdded.ToArray()

        $filteredRemoved = New-Object System.Collections.Generic.List[object]
        foreach ($item in @($removedReg)) {
            if (Test-QuarantineVolatileRegistryEntry -Entry $item) { $registryVolatileFiltered++ } else { $filteredRemoved.Add($item) | Out-Null }
        }
        $removedReg = $filteredRemoved.ToArray()

        $filteredModified = New-Object System.Collections.Generic.List[object]
        foreach ($item in @($modifiedReg)) {
            if (Test-QuarantineVolatileRegistryEntry -Entry $item) { $registryVolatileFiltered++ } else { $filteredModified.Add($item) | Out-Null }
        }
        $modifiedReg = $filteredModified.ToArray()
    }

    $leftTasks = @{}
    foreach ($t in @($left.tasks)) {
        $parsed = ConvertFrom-TaskCsvLine -Line $t.line
        if ($parsed -and -not $leftTasks.ContainsKey($parsed.TaskName)) {
            $leftTasks[$parsed.TaskName] = $parsed
        }
    }
    $rightTasks = @{}
    foreach ($t in @($right.tasks)) {
        $parsed = ConvertFrom-TaskCsvLine -Line $t.line
        if ($parsed -and -not $rightTasks.ContainsKey($parsed.TaskName)) {
            $rightTasks[$parsed.TaskName] = $parsed
        }
    }

    $addedTasks = @()
    $removedTasks = @()
    $modifiedTasks = @()
    $volatileTasks = @()

    foreach ($name in ($rightTasks.Keys | Where-Object { -not $leftTasks.ContainsKey($_) } | Sort-Object)) {
        $addedTasks += $rightTasks[$name]
    }
    foreach ($name in ($leftTasks.Keys | Where-Object { -not $rightTasks.ContainsKey($_) } | Sort-Object)) {
        $removedTasks += $leftTasks[$name]
    }
    foreach ($name in ($leftTasks.Keys | Where-Object { $rightTasks.ContainsKey($_) } | Sort-Object)) {
        $a = $leftTasks[$name]; $b = $rightTasks[$name]
        $stableA = Get-TaskStableFingerprint -Task $a
        $stableB = Get-TaskStableFingerprint -Task $b
        if ($stableA -ne $stableB) {
            $modifiedTasks += [pscustomobject]@{
                taskName    = $name
                fromTaskToRun = $a.TaskToRun
                toTaskToRun   = $b.TaskToRun
                fromStatus    = $a.Status
                toStatus      = $b.Status
                fromRunAsUser = $a.RunAsUser
                toRunAsUser   = $b.RunAsUser
            }
        } elseif ($a.LastRunTime -ne $b.LastRunTime -or $a.NextRunTime -ne $b.NextRunTime) {
            $volatileTasks += [pscustomobject]@{
                taskName      = $name
                fromLastRun   = $a.LastRunTime
                toLastRun     = $b.LastRunTime
                fromNextRun   = $a.NextRunTime
                toNextRun     = $b.NextRunTime
            }
        }
    }

    $leftScanMode = Get-ManifestScanMode -Manifest $left
    $rightScanMode = Get-ManifestScanMode -Manifest $right
    $useEventFiles = ($leftScanMode -eq 'events' -or $rightScanMode -eq 'events') -or
        ((@($addedFiles).Count + @($removedFiles).Count + @($modifiedFiles).Count) -eq 0 -and
            ($right.PSObject.Properties['usn'] -and $right.usn -and $right.usn.available -eq $true -and @($right.usn.events).Count -gt 0))

    $fileDiffSource = 'scan'
    if ($useEventFiles) {
        $eventFiles = $null
        try {
            $eventFiles = Get-EventDerivedFileChanges -Left $left -Right $right -ScannedFiles $rightFiles -LeftScannedFiles $leftFiles
        } catch {
            Write-Warning "Event-derived file diff failed: $($_.Exception.Message)"
            $eventFiles = [pscustomobject]@{ added = @(); removed = @(); modified = @() }
        }
        if (@($addedFiles).Count + @($removedFiles).Count + @($modifiedFiles).Count -eq 0) {
            $addedFiles = @($eventFiles.added)
            $removedFiles = @($eventFiles.removed)
            $modifiedFiles = @($eventFiles.modified)
            $fileDiffSource = 'events'
        } else {
            # Merge: event paths not already in scan diff
            $scanPaths = @{}
            foreach ($f in @($addedFiles) + @($removedFiles) + @($modifiedFiles)) {
                $p = if ($f.path) { [string]$f.path } else { '' }
                if ($p) { $scanPaths[$p] = $true }
            }
            foreach ($f in @($eventFiles.added)) {
                if (-not $scanPaths.ContainsKey([string]$f.path)) { $addedFiles += $f }
            }
            foreach ($f in @($eventFiles.removed)) {
                if (-not $scanPaths.ContainsKey([string]$f.path)) { $removedFiles += $f }
            }
            foreach ($f in @($eventFiles.modified)) {
                if (-not $scanPaths.ContainsKey([string]$f.path)) { $modifiedFiles += $f }
            }
            $fileDiffSource = 'mixed'
        }
    }

    $summary = [ordered]@{
        filesAdded        = @($addedFiles).Count
        filesRemoved      = @($removedFiles).Count
        filesModified     = @($modifiedFiles).Count
        registryAdded     = @($addedReg).Count
        registryRemoved   = @($removedReg).Count
        registryModified  = @($modifiedReg).Count
        registryVolatileFiltered = $registryVolatileFiltered
        registryDiffSource = $registryDiffSource
        tasksAdded        = @($addedTasks).Count
        tasksRemoved      = @($removedTasks).Count
        tasksModified     = @($modifiedTasks).Count
        tasksVolatileOnly = @($volatileTasks).Count
        sysmonAdded       = 0
        serviceInstallsAdded = 0
        dnsQueries        = 0
        networkRequests   = 0
        fileDiffSource    = $fileDiffSource
    }

    $leftSysmonKeys = @{}
    foreach ($event in (Get-SysmonEventsFromManifest -Manifest $left)) {
        $leftSysmonKeys[(Get-SysmonEventKey -Event $event)] = $true
    }
    $addedSysmon = @(
        Get-SysmonEventsFromManifest -Manifest $right |
            Where-Object { -not $leftSysmonKeys.ContainsKey((Get-SysmonEventKey -Event $_)) }
    )
    $summary.sysmonAdded = @($addedSysmon).Count

    $leftServiceInstallKeys = @{}
    foreach ($event in (Get-ServiceInstallEventsFromManifest -Manifest $left)) {
        $leftServiceInstallKeys[(Get-ServiceInstallEventKey -Event $event)] = $true
    }
    $addedServiceInstalls = @(
        Get-ServiceInstallEventsFromManifest -Manifest $right |
            Where-Object { -not $leftServiceInstallKeys.ContainsKey((Get-ServiceInstallEventKey -Event $_)) }
    )
    $summary.serviceInstallsAdded = @($addedServiceInstalls).Count

    $fromSnapName = Get-ManifestStringProperty -Manifest $left -Name 'snapshot'
    $toSnapName = Get-ManifestStringProperty -Manifest $right -Name 'snapshot'
    $isSnapshotPair = -not [string]::IsNullOrWhiteSpace($fromSnapName) -and -not [string]::IsNullOrWhiteSpace($toSnapName)
    $compareMode = if ($isSnapshotPair) { 'snapshot-pair' } else { 'baseline-to-evidence' }

    $leftUsnKeys = @{}
    if ($left.PSObject.Properties['usn'] -and $left.usn -and $left.usn.events) {
        foreach ($ev in @($left.usn.events)) {
            $leftUsnKeys[(Get-UsnEventKey -Event $ev)] = $true
        }
    }
    $rightUsn = if ($right.PSObject.Properties['usn']) { $right.usn } else { $null }
    $addedUsn = @()
    if ($rightUsn -and $rightUsn.available -eq $true -and $rightUsn.events) {
        $addedUsn = @($rightUsn.events | Where-Object { -not $leftUsnKeys.ContainsKey((Get-UsnEventKey -Event $_)) })
    }

    $networkSection = $null
    $fromCapturedText = Get-ManifestStringProperty -Manifest $left -Name 'capturedAt'
    $toCapturedText = Get-ManifestStringProperty -Manifest $right -Name 'capturedAt'
    $networkFrom = ConvertTo-QuarantineNetworkInstant -Text $fromCapturedText
    $networkTo = ConvertTo-QuarantineNetworkInstant -Text $toCapturedText
    if ($networkFrom -and $networkTo) {
        try {
            $networkEvidence = Get-QuarantineNetworkEvidence -ConfigPath $ConfigPath -From $networkFrom -To $networkTo
            $dnsMerged = Merge-QuarantineSysmonDnsEvidence `
                -DnsEntries @($networkEvidence.dns) `
                -SysmonEvents @($addedSysmon) `
                -From $networkFrom -To $networkTo
            $dnsTruncated = [bool]$networkEvidence.truncated
            $networkSection = [ordered]@{
                available  = [bool]$networkEvidence.available -or (@($dnsMerged).Count -gt 0) -or (@($networkEvidence.requests).Count -gt 0)
                message    = [string]$networkEvidence.message
                windowFrom = [string]$networkEvidence.windowFrom
                windowTo   = [string]$networkEvidence.windowTo
                sources    = $networkEvidence.sources
                dns        = @($dnsMerged)
                requests   = @($networkEvidence.requests)
                truncated  = [bool]($networkEvidence.truncated -or $dnsTruncated)
            }
            $summary.dnsQueries = @($dnsMerged).Count
            $summary.networkRequests = @($networkEvidence.requests).Count
        } catch {
            $networkSection = [ordered]@{
                available  = $false
                message    = "Network evidence failed: $($_.Exception.Message)"
                windowFrom = if ($networkFrom) { $networkFrom.ToUniversalTime().ToString('o') } else { '' }
                windowTo   = if ($networkTo) { $networkTo.ToUniversalTime().ToString('o') } else { '' }
                sources    = [ordered]@{ proxyLogs = @(); pcaps = @() }
                dns        = @()
                requests   = @()
                truncated  = $false
            }
            $summary.dnsQueries = 0
            $summary.networkRequests = 0
        }
    } else {
        $networkSection = [ordered]@{
            available  = $false
            message    = 'Snapshot capture times missing; cannot correlate proxy/PCAP logs.'
            windowFrom = ''
            windowTo   = ''
            sources    = [ordered]@{ proxyLogs = @(); pcaps = @() }
            dns        = @()
            requests   = @()
            truncated  = $false
        }
        $summary.dnsQueries = 0
        $summary.networkRequests = 0
    }

    $rightSysmon = Get-SysmonSectionFromManifest -Manifest $right
    $rightServiceInstalls = Get-ServiceInstallSectionFromManifest -Manifest $right
    $compareWarnings = Get-QuarantineManifestCompareWarnings -Left $left -Right $right
    $fromFileCount = if ($left.PSObject.Properties['fileCount']) { [int]$left.fileCount } else { @($left.files).Count }
    $toFileCount = if ($right.PSObject.Properties['fileCount']) { [int]$right.fileCount } else { @($right.files).Count }
    $fromHku = if ($left.PSObject.Properties['userRegistryCount']) { [int]$left.userRegistryCount } else { @($left.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }
    $toHku = if ($right.PSObject.Properties['userRegistryCount']) { [int]$right.userRegistryCount } else { @($right.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }

    return [pscustomobject]@{
        meta = [ordered]@{
            fromManifest = $From
            toManifest   = $To
            fromSnapshot = Get-ManifestStringProperty -Manifest $left -Name 'snapshot'
            toSnapshot   = Get-ManifestStringProperty -Manifest $right -Name 'snapshot'
            fromCaptured = Get-ManifestStringProperty -Manifest $left -Name 'capturedAt'
            toCaptured   = Get-ManifestStringProperty -Manifest $right -Name 'capturedAt'
            fromComputer = Get-ManifestStringProperty -Manifest $left -Name 'computerName'
            toComputer   = Get-ManifestStringProperty -Manifest $right -Name 'computerName'
            fromFileCount = $fromFileCount
            toFileCount   = $toFileCount
            fromScanMode  = $leftScanMode
            toScanMode    = $rightScanMode
            fileDiffSource = $fileDiffSource
            registryDiffSource = $registryDiffSource
            fromUserRegistryCount = $fromHku
            toUserRegistryCount   = $toHku
            compareMode   = $compareMode
            warnings      = @($compareWarnings)
        }
        summary = $summary
        files = [ordered]@{
            added    = @($addedFiles)
            removed  = @($removedFiles)
            modified = @($modifiedFiles)
        }
        registry = [ordered]@{
            added    = @($addedReg)
            removed  = @($removedReg)
            modified = @($modifiedReg)
        }
        tasks = [ordered]@{
            added         = @($addedTasks)
            removed       = @($removedTasks)
            modified      = @($modifiedTasks)
            volatileOnly  = @($volatileTasks)
        }
        sysmon = [ordered]@{
            available  = if ($rightSysmon.PSObject.Properties['available']) { [bool]$rightSysmon.available } else { $false }
            message    = if ($rightSysmon.PSObject.Properties['message']) { [string]$rightSysmon.message } else { '' }
            baselineAt = if ($isSnapshotPair) {
                Get-ManifestStringProperty -Manifest $left -Name 'capturedAt'
            } elseif ($rightSysmon.PSObject.Properties['baselineAt']) {
                [string]$rightSysmon.baselineAt
            } else { '' }
            recordedAt = if ($rightSysmon.PSObject.Properties['recordedAt']) { [string]$rightSysmon.recordedAt } else { '' }
            added      = @($addedSysmon)
        }
        serviceInstalls = [ordered]@{
            available  = if ($rightServiceInstalls.PSObject.Properties['available']) { [bool]$rightServiceInstalls.available } else { $false }
            message    = if ($rightServiceInstalls.PSObject.Properties['message']) { [string]$rightServiceInstalls.message } else { '' }
            baselineAt = if ($isSnapshotPair) {
                Get-ManifestStringProperty -Manifest $left -Name 'capturedAt'
            } elseif ($rightServiceInstalls.PSObject.Properties['baselineAt']) {
                [string]$rightServiceInstalls.baselineAt
            } else { '' }
            recordedAt = if ($rightServiceInstalls.PSObject.Properties['recordedAt']) { [string]$rightServiceInstalls.recordedAt } else { '' }
            added      = @($addedServiceInstalls)
        }
        usn = if ($rightUsn) {
            [ordered]@{
                available  = if ($rightUsn.PSObject.Properties['available']) { [bool]$rightUsn.available } else { $false }
                message    = if ($isSnapshotPair) {
                    "USN events in To not in From ($fromSnapName → $toSnapName)."
                } elseif ($rightUsn.PSObject.Properties['message']) {
                    [string]$rightUsn.message
                } else { '' }
                volume     = if ($rightUsn.PSObject.Properties['volume']) { [string]$rightUsn.volume } else { 'C:' }
                baselineAt = if ($isSnapshotPair) {
                    Get-ManifestStringProperty -Manifest $left -Name 'capturedAt'
                } elseif ($rightUsn.PSObject.Properties['baselineAt']) {
                    [string]$rightUsn.baselineAt
                } else { '' }
                recordedAt = if ($rightUsn.PSObject.Properties['recordedAt']) { [string]$rightUsn.recordedAt } else { '' }
                truncated  = if ($rightUsn.PSObject.Properties['truncated']) { [bool]$rightUsn.truncated } else { $false }
                eventCount = @($addedUsn).Count
                events     = @($addedUsn)
            }
        } else { $null }
        network = $networkSection
    }
}
