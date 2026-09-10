#Requires -Version 5.1
<#
.SYNOPSIS
  Derive changed file paths from USN + Sysmon sidecar objects (host or guest).
#>
Set-StrictMode -Version Latest

function Get-QuarantineJsonProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if (-not $Object.PSObject.Properties[$Name]) { return $null }
    $value = $Object.$Name
    # PowerShell unwraps empty arrays on return; preserve array identity for sidecar lists.
    if ($value -is [System.Array]) { return ,$value }
    return $value
}

function Get-QuarantineJsonArray {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return @() }
    if (-not $Object.PSObject.Properties[$Name]) { return @() }
    $value = $Object.$Name
    if ($null -eq $value) { return @() }
    if ($value -is [System.Array]) { return $value }
    return @($value)
}

function Test-QuarantineSidecarHasEvents {
    param($Sidecar)

    if (-not $Sidecar) { return $false }
    if ($Sidecar.PSObject.Properties['available'] -and $Sidecar.available -eq $false) { return $false }
    if ($Sidecar.PSObject.Properties['eventCount']) {
        return ([int]$Sidecar.eventCount -gt 0)
    }
    return ((Get-QuarantineJsonArray -Object $Sidecar -Name 'events').Length -gt 0)
}

function Resolve-QuarantineUsnEventPath {
    param($Event)

    $fromPath = [string](Get-QuarantineJsonProperty -Object $Event -Name 'path')
    if (-not [string]::IsNullOrWhiteSpace($fromPath)) { return $fromPath }
    $name = [string](Get-QuarantineJsonProperty -Object $Event -Name 'fileName')
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    if ($name -match '^[A-Za-z]:\\') { return $name }
    if ($name.StartsWith('\')) { return "C:$name" }
    if ($name -match '(^|\\)hosts$') { return 'C:\Windows\System32\drivers\etc\hosts' }
    return $null
}

function Get-QuarantineUsnChangeKind {
    param([string[]]$Reasons)
    $r = @($Reasons)
    if ($r -contains 'file_delete') { return 'removed' }
    if ($r -contains 'file_create' -or $r -contains 'rename_new_name') { return 'added' }
    if ($r -contains 'rename_old_name') { return 'removed' }
    return 'modified'
}

function Add-QuarantineChangedPathEntry {
    param(
        [hashtable]$PathKinds,
        [string]$Path,
        [string]$Kind,
        [string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not $PathKinds.ContainsKey($Path)) {
        $PathKinds[$Path] = [pscustomobject]@{ kind = $Kind; source = $Source }
        return
    }
    if ($Kind -eq 'removed') {
        $PathKinds[$Path] = [pscustomobject]@{ kind = 'removed'; source = $Source }
    }
}

function Get-QuarantineChangedPathMapFromEventSidecars {
    param(
        $Usn,
        $Sysmon
    )

    $pathKinds = @{}

    $usnEvents = Get-QuarantineJsonArray -Object $Usn -Name 'events'
    if ($Usn -and (Get-QuarantineJsonProperty -Object $Usn -Name 'available') -ne $false -and $usnEvents.Length -gt 0) {
        foreach ($ev in $usnEvents) {
            $path = Resolve-QuarantineUsnEventPath -Event $ev
            $reasons = Get-QuarantineJsonProperty -Object $ev -Name 'reasons'
            $kind = Get-QuarantineUsnChangeKind -Reasons @($reasons)
            Add-QuarantineChangedPathEntry -PathKinds $pathKinds -Path $path -Kind $kind -Source 'usn'
        }
    }

    $sysmonEvents = Get-QuarantineJsonArray -Object $Sysmon -Name 'events'
    if ($Sysmon -and (Get-QuarantineJsonProperty -Object $Sysmon -Name 'available') -ne $false -and $sysmonEvents.Length -gt 0) {
        foreach ($ev in $sysmonEvents) {
            $eid = [int](Get-QuarantineJsonProperty -Object $ev -Name 'eid')
            if ($eid -notin @(2, 11, 12, 23, 26)) { continue }
            $path = [string](Get-QuarantineJsonProperty -Object $ev -Name 'target')
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $kind = if ($eid -in @(23, 26)) { 'removed' } elseif ($eid -eq 2) { 'modified' } else { 'added' }
            Add-QuarantineChangedPathEntry -PathKinds $pathKinds -Path $path -Kind $kind -Source 'sysmon'
        }
    }

    return $pathKinds
}

function New-QuarantineChangedFilesExportFromEventSidecars {
    param(
        $Usn,
        $Sysmon,
        [string]$RecordedAt = ''
    )

    $pathKinds = Get-QuarantineChangedPathMapFromEventSidecars -Usn $Usn -Sysmon $Sysmon
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($path in ($pathKinds.Keys | Sort-Object)) {
        $meta = $pathKinds[$path]
        $files.Add([pscustomobject][ordered]@{
            p      = $path
            s      = $null
            h      = $null
            m      = $null
            src    = $meta.source
            change = $meta.kind
            c      = 'sidecar'
        }) | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($RecordedAt)) {
        $RecordedAt = (Get-Date).ToUniversalTime().ToString('o')
    }

    return [pscustomobject][ordered]@{
        available  = $true
        recordedAt = $RecordedAt
        pathCount  = $pathKinds.Count
        fileCount  = $files.Count
        files      = $files.ToArray()
        rebuilt    = $true
    }
}
