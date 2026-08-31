#Requires -Version 5.1
<#
.SYNOPSIS
  Build a structured diff object from two quarantine guest manifest JSON files.
#>
Set-StrictMode -Version Latest

if (-not (Get-Command ConvertFrom-RegshotCompareLog -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'ConvertFrom-RegshotCompareLog.ps1')
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

function Get-EventDerivedFileChanges {
    <#
    .SYNOPSIS
      Build file added/removed/modified lists from USN + Sysmon on the To manifest (Option G).
    #>
    param(
        [Parameter(Mandatory)]
        [object]$Right,
        [hashtable]$ScannedFiles = @{}
    )

    $kinds = @{}
    $sources = @{}

    if ($Right.PSObject.Properties['usn'] -and $Right.usn -and $Right.usn.available -eq $true -and $Right.usn.events) {
        foreach ($ev in @($Right.usn.events)) {
            $path = Resolve-UsnEventPath -Event $ev
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $kind = Get-UsnChangeKind -Reasons @($ev.reasons)
            $kinds[$path] = $kind
            $sources[$path] = 'usn'
        }
    }

    foreach ($ev in (Get-SysmonEventsFromManifest -Manifest $Right)) {
        $eid = 0
        if ($ev.PSObject.Properties['eid']) { $eid = [int]$ev.eid }
        if ($eid -notin @(11, 23, 26)) { continue }
        $path = Get-SysmonEventFieldValue -Event $ev -Name 'target'
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $kind = if ($eid -in @(23, 26)) { 'removed' } else { 'added' }
        if (-not $kinds.ContainsKey($path) -or $kind -eq 'removed') {
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
            if ($scan) {
                $item = [ordered]@{
                    path      = $path
                    fromSize  = $null
                    toSize    = [int64]$scan.s
                    fromHash  = $null
                    toHash    = [string]$scan.h
                    toMtime   = [string]$scan.m
                    source    = $src
                }
                if ($scan.PSObject.Properties['c']) { $item.toContentEncoding = [string]$scan.c }
                if ($scan.PSObject.Properties['d']) { $item.toContent = [string]$scan.d }
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
        [string]$To
    )

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
            $eventFiles = Get-EventDerivedFileChanges -Right $right -ScannedFiles $rightFiles
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
        registryDiffSource = $registryDiffSource
        tasksAdded        = @($addedTasks).Count
        tasksRemoved      = @($removedTasks).Count
        tasksModified     = @($modifiedTasks).Count
        tasksVolatileOnly = @($volatileTasks).Count
        sysmonAdded       = 0
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

    $rightSysmon = Get-SysmonSectionFromManifest -Manifest $right
    $compareWarnings = Get-QuarantineManifestCompareWarnings -Left $left -Right $right
    $fromFileCount = if ($left.PSObject.Properties['fileCount']) { [int]$left.fileCount } else { @($left.files).Count }
    $toFileCount = if ($right.PSObject.Properties['fileCount']) { [int]$right.fileCount } else { @($right.files).Count }
    $fromHku = if ($left.PSObject.Properties['userRegistryCount']) { [int]$left.userRegistryCount } else { @($left.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }
    $toHku = if ($right.PSObject.Properties['userRegistryCount']) { [int]$right.userRegistryCount } else { @($right.registry | Where-Object { $_.k -match '^HKU:\\' }).Count }

    return [pscustomobject]@{
        meta = [ordered]@{
            fromManifest = $From
            toManifest   = $To
            fromSnapshot = [string]$left.snapshot
            toSnapshot   = [string]$right.snapshot
            fromCaptured = [string]$left.capturedAt
            toCaptured   = [string]$right.capturedAt
            fromComputer = [string]$left.computerName
            toComputer   = [string]$right.computerName
            fromFileCount = $fromFileCount
            toFileCount   = $toFileCount
            fromScanMode  = $leftScanMode
            toScanMode    = $rightScanMode
            fileDiffSource = $fileDiffSource
            registryDiffSource = $registryDiffSource
            fromUserRegistryCount = $fromHku
            toUserRegistryCount   = $toHku
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
            baselineAt = if ($rightSysmon.PSObject.Properties['baselineAt']) { [string]$rightSysmon.baselineAt } else { '' }
            recordedAt = if ($rightSysmon.PSObject.Properties['recordedAt']) { [string]$rightSysmon.recordedAt } else { '' }
            added      = @($addedSysmon)
        }
        usn = if ($right.PSObject.Properties['usn']) { $right.usn } else { $null }
    }
}
