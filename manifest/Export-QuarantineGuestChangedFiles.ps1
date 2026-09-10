#Requires -Version 5.1
<#
.SYNOPSIS
  Hash and embed content for every file path reported by USN/Sysmon sidecars (events scan mode).
#>
[CmdletBinding()]
param(
    [string]$UsnFile = 'C:\Users\Public\Quarantine\usn-delta-export.json',
    [string]$SysmonFile = 'C:\Users\Public\Quarantine\sysmon-events-export.json',
    [string]$OutFile = '',
    [int]$HashMaxMb = 50,
    [int]$ContentMaxKb = 51200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$hashMaxBytes = [int64]$HashMaxMb * 1MB
$contentMaxBytes = [int64]$ContentMaxKb * 1KB
$files = New-Object System.Collections.Generic.List[object]
$pathKinds = @{}
$guestManifestRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

function Resolve-UsnEventPath {
    param($Event)

    if ($Event.path) {
        $fromPath = [string]$Event.path
        if (-not [string]::IsNullOrWhiteSpace($fromPath)) { return $fromPath }
    }
    $name = if ($Event.fileName) { [string]$Event.fileName } else { '' }
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    if ($name -match '^[A-Za-z]:\\') { return $name }
    if ($name.StartsWith('\')) { return "C:$name" }
    if ($name -match '(^|\\)hosts$') { return 'C:\Windows\System32\drivers\etc\hosts' }
    return $null
}

function Get-UsnChangeKind {
    param([string[]]$Reasons)
    $r = @($Reasons)
    if ($r -contains 'file_delete') { return 'removed' }
    if ($r -contains 'file_create' -or $r -contains 'rename_new_name') { return 'added' }
    if ($r -contains 'rename_old_name') { return 'removed' }
    return 'modified'
}

function Get-FileContentPayload {
    param(
        [System.IO.FileInfo]$Item,
        [int64]$MaxBytes
    )

    if ($Item.Length -gt $MaxBytes) {
        return @{ c = 'too_large' }
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Item.FullName)
        $hasNull = $false
        foreach ($b in $bytes) {
            if ($b -eq 0) { $hasNull = $true; break }
        }

        if (-not $hasNull) {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            $bad = 0
            foreach ($ch in $text.ToCharArray()) {
                $code = [int][char]$ch
                if ($code -lt 9 -or ($code -gt 13 -and $code -lt 32)) { $bad++ }
            }
            if ($text.Length -eq 0 -or ($bad / [Math]::Max($text.Length, 1)) -lt 0.05) {
                return @{ c = 'text'; d = $text }
            }
        }

        return @{ c = 'base64'; d = [Convert]::ToBase64String($bytes) }
    } catch {
        return @{ c = 'access_denied' }
    }
}

function Add-ChangedPath {
    param(
        [string]$Path,
        [string]$Kind,
        [string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not $pathKinds.ContainsKey($Path)) {
        $pathKinds[$Path] = [pscustomobject]@{ kind = $Kind; source = $Source }
        return
    }
    $existing = $pathKinds[$Path]
    if ($Kind -eq 'removed') {
        $pathKinds[$Path] = [pscustomobject]@{ kind = 'removed'; source = $Source }
    }
}

function Read-JsonSidecar {
    param([string]$SidecarPath)
    if ([string]::IsNullOrWhiteSpace($SidecarPath)) { return $null }
    if (-not (Test-Path -LiteralPath $SidecarPath)) { return $null }
    $privModule = Join-Path $guestManifestRoot 'QuarantineGuestPriv.psm1'
    if (Test-Path -LiteralPath $privModule) {
        Import-Module $privModule -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (Get-Command Read-QuarantineGuestJsonFile -ErrorAction SilentlyContinue) {
        return Read-QuarantineGuestJsonFile -Path $SidecarPath
    }
    return Get-Content -LiteralPath $SidecarPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Add-PathsFromUsn {
    param($Usn)

    if (-not $Usn -or ($Usn.PSObject.Properties['available'] -and $Usn.available -eq $false)) { return }
    if (-not $Usn.PSObject.Properties['events'] -or -not $Usn.events) { return }
    foreach ($ev in @($Usn.events)) {
        $path = Resolve-UsnEventPath -Event $ev
        $kind = Get-UsnChangeKind -Reasons @($ev.reasons)
        Add-ChangedPath -Path $path -Kind $kind -Source 'usn'
    }
}

function Add-PathsFromSysmon {
    param($Sysmon)

    if (-not $Sysmon -or ($Sysmon.PSObject.Properties['available'] -and $Sysmon.available -eq $false)) { return }
    if (-not $Sysmon.PSObject.Properties['events'] -or -not $Sysmon.events) { return }
    foreach ($ev in @($Sysmon.events)) {
        $eid = 0
        if ($ev.PSObject.Properties['eid']) { $eid = [int]$ev.eid }
        if ($eid -notin @(2, 11, 12, 23, 26)) { continue }
        $path = if ($ev.target) { [string]$ev.target } elseif ($ev.PSObject.Properties['TargetFilename']) { [string]$ev.TargetFilename } else { '' }
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $kind = if ($eid -in @(23, 26)) { 'removed' } elseif ($eid -eq 2) { 'modified' } else { 'added' }
        Add-ChangedPath -Path $path -Kind $kind -Source 'sysmon'
    }
}

function Add-FileEntry {
    param(
        [string]$Path,
        [string]$Source,
        [string]$Kind
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $files.Add([pscustomobject][ordered]@{
                p      = $Path
                s      = $null
                h      = $null
                m      = $null
                src    = $Source
                change = $Kind
                c      = 'missing'
            }) | Out-Null
            return
        }

        $item = Get-Item -LiteralPath $Path -Force
        $entry = [ordered]@{
            p      = $item.FullName
            s      = $item.Length
            m      = $item.LastWriteTimeUtc.ToString('o')
            src    = $Source
            change = $Kind
        }
        if ($item.Length -le $hashMaxBytes) {
            try {
                $entry.h = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch {
                $entry.h = 'ACCESS_DENIED'
            }
        } else {
            $entry.h = 'SKIPPED_LARGE'
        }
        if ($item.Length -le $contentMaxBytes) {
            $payload = Get-FileContentPayload -Item $item -MaxBytes $contentMaxBytes
            $entry.c = $payload.c
            if ($payload.d) { $entry.d = $payload.d }
        } else {
            $entry.c = 'too_large'
        }
        $files.Add([pscustomobject]$entry) | Out-Null
    } catch { }
}

$usn = Read-JsonSidecar -SidecarPath $UsnFile
$sysmon = Read-JsonSidecar -SidecarPath $SysmonFile
Add-PathsFromUsn -Usn $usn
Add-PathsFromSysmon -Sysmon $sysmon

foreach ($path in ($pathKinds.Keys | Sort-Object)) {
    $meta = $pathKinds[$path]
    if ($meta.kind -eq 'removed') {
        Add-FileEntry -Path $path -Source $meta.source -Kind 'removed'
        continue
    }
    Add-FileEntry -Path $path -Source $meta.source -Kind $meta.kind
}

$result = [ordered]@{
    available  = $true
    recordedAt = (Get-Date).ToUniversalTime().ToString('o')
    pathCount  = $pathKinds.Count
    fileCount  = $files.Count
    files      = $files.ToArray()
}

if ($OutFile) {
    $privModule = Join-Path $guestManifestRoot 'QuarantineGuestPriv.psm1'
    if (Test-Path -LiteralPath $privModule) {
        Import-Module $privModule -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (Get-Command Write-QuarantineGuestJsonFile -ErrorAction SilentlyContinue) {
        Write-QuarantineGuestJsonFile -Object $result -Path $OutFile -Depth 8
    } else {
        $result | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }
    Write-Output "CHANGED_FILES_WRITTEN $OutFile paths=$($pathKinds.Count) files=$($files.Count)"
}

return $result
