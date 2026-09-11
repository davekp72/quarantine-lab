#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:ManifestRoot = $PSScriptRoot
$script:ProjectRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:ManifestRoot 'Get-QuarantineManifestDiff.ps1')
. (Join-Path $script:ManifestRoot 'Get-QuarantineChangedPathsFromEventSidecars.ps1')

function Initialize-QuarantineManifestConfig {
    param([string]$ConfigPath)
    $vmModule = Join-Path $script:ProjectRoot 'QuarantineVM.psm1'
    if (-not (Get-Command Initialize-QuarantineVMContext -ErrorAction SilentlyContinue)) {
        Import-Module $vmModule -Force
    } else {
        Import-Module $vmModule -Scope Local -WarningAction SilentlyContinue
    }
    if ($ConfigPath) {
        Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
    }
}

function Get-QuarantineVMManifestSettings {
    param([string]$ConfigPath)
    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $dataDir = Get-QuarantineVMDataDir -Config $cfg
    $logDir = if ($cfg.manifest -and $cfg.manifest.logDir) {
        $cfg.manifest.logDir
    } else {
        Join-Path $dataDir 'logs\manifests'
    }
    [pscustomobject]@{
        Config     = $cfg
        LogDir     = $logDir
        HashMaxMb  = if ($cfg.manifest -and $cfg.manifest.hashMaxMb) { [int]$cfg.manifest.hashMaxMb } else { 50 }
        ContentMaxKb = if ($cfg.manifest -and $cfg.manifest.contentMaxKb) { [int]$cfg.manifest.contentMaxKb } else { 51200 }
        ScanMode = if ($cfg.manifest -and $cfg.manifest.scanMode) { [string]$cfg.manifest.scanMode } else { 'events' }
        RegistryEngine = 'hive'
        CompareScript = Join-Path $script:ManifestRoot 'Compare-QuarantineManifest.ps1'
        GuestScript = Join-Path $script:ManifestRoot 'Get-QuarantineGuestManifest.ps1'
        TargetedFilesScript = Join-Path $script:ManifestRoot 'Get-QuarantineGuestTargetedFiles.ps1'
        UsnBaselineScript = Join-Path $script:ManifestRoot 'Set-QuarantineGuestUsnBaseline.ps1'
        UsnDeltaScript = Join-Path $script:ManifestRoot 'Get-QuarantineGuestUsnDelta.ps1'
        SysmonScript = Join-Path $script:ManifestRoot 'Get-QuarantineGuestSysmonEvents.ps1'
        ServiceInstallScript = Join-Path $script:ManifestRoot 'Get-QuarantineGuestServiceInstallEvents.ps1'
        ChangedFilesScript = Join-Path $script:ManifestRoot 'Export-QuarantineGuestChangedFiles.ps1'
        PrivModule = Join-Path $script:ManifestRoot 'QuarantineGuestPriv.psm1'
        ElevatedRunnerScript = Join-Path $script:ProjectRoot 'guest\Invoke-QuarantineGuestElevated.ps1'
    }
}

function Get-SafeSnapshotFileName {
    param([string]$Name)
    ($Name -replace '[^\w\-]', '-')
}

function Get-QuarantineVMManifestHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe.json"
}

function Resolve-QuarantineManifestHostPathLatest {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName
    )

    $canonical = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    if (Test-Path -LiteralPath $canonical) {
        return $canonical
    }

    $dir = Split-Path -Parent $canonical
    $leaf = Split-Path -Leaf $canonical
    if (-not (Test-Path -LiteralPath $dir)) {
        return $canonical
    }

    $staging = Get-ChildItem -LiteralPath $dir -Filter "$leaf.staging-*.json" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($staging) {
        Write-Warning "Using staging manifest (canonical locked/missing): $($staging.FullName)"
        return $staging.FullName
    }

    return $canonical
}

function Get-QuarantineVMManifestBaselineHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-baseline.json"
}

function Get-QuarantineGuestUsnBaselineGuestPath {
    param([string]$ConfigPath)
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }
    Join-Path $guestDir 'usn-baseline.json'
}

function Get-QuarantineRegistryEngine {
    param([string]$ConfigPath)
    # Hive-index engine only (agent reg save dumps). Config cli/legacy/payload values are ignored.
    return 'hive'
}

function Test-QuarantineCliRegistryEngine {
    param([string]$ConfigPath)
    return $false
}

function Get-QuarantineVMPayloadRegistryHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-payload-registry.json"
}

function Get-QuarantineVMPayloadRegistryRegHostDir {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-payload-registry"
}

function Get-QuarantineVMHklmRegistryHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-hklm-registry.json"
}

function Get-QuarantineVMHklmRegistryRegHostDir {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-hklm-registry"
}

function Get-QuarantineVMUsnDeltaHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-usn-delta.json"
}

function Get-QuarantineVMSysmonHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-sysmon.json"
}

function Get-QuarantineVMServiceInstallHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-service-installs.json"
}

function Get-QuarantineVMChangedFilesHostPath {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    Join-Path $settings.LogDir "$safe-changed-files.json"
}

function Remove-QuarantineSnapshotManifestArtifacts {
    <#
    .SYNOPSIS
      Remove host-side manifest JSON and sidecars for a snapshot name.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $safe = Get-SafeSnapshotFileName -Name $SnapshotName
    $logDir = $settings.LogDir
    if (-not (Test-Path -LiteralPath $logDir)) { return @() }

    $removed = New-Object System.Collections.Generic.List[string]

    $paths = @(
        (Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMPayloadRegistryHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMHklmRegistryHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMUsnDeltaHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMSysmonHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMServiceInstallHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMChangedFilesHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName)
    )
    foreach ($path in $paths) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            $removed.Add($path) | Out-Null
        }
    }

    $dirs = @(
        (Get-QuarantineVMPayloadRegistryRegHostDir -ConfigPath $ConfigPath -SnapshotName $SnapshotName),
        (Get-QuarantineVMHklmRegistryRegHostDir -ConfigPath $ConfigPath -SnapshotName $SnapshotName)
    )
    # Hive dump + network (PCAP/proxy) sidecars live beside manifests.
    $dirs += @(
        (Join-Path $logDir "$safe-hives"),
        (Join-Path $logDir "$safe-network")
    )
    foreach ($dir in $dirs) {
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            $removed.Add($dir) | Out-Null
        }
    }

    $leaf = "$safe.json"
    Get-ChildItem -LiteralPath $logDir -Filter "$leaf.staging-*.json" -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            $removed.Add($_.FullName) | Out-Null
        }

    $diffPatterns = @(
        "diff-*-vs-$safe.diff.json",
        "diff-$safe-vs-*.diff.json"
    )
    foreach ($pattern in $diffPatterns) {
        Get-ChildItem -LiteralPath $logDir -Filter $pattern -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                $removed.Add($_.FullName) | Out-Null
            }
    }

    return @($removed)
}

function Get-QuarantineVMSessionBaselineSnapshotName {
    param([string]$ConfigPath)

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $candidate = if ($cfg.manifest -and $cfg.manifest.sessionBaselineSnapshot) {
        [string]$cfg.manifest.sessionBaselineSnapshot
    } elseif ($cfg.cleanSnapshotName) {
        [string]$cfg.cleanSnapshotName
    } else {
        'Clean'
    }

    try {
        return (Resolve-QuarantineVMSnapshotName -Name $candidate -ConfigPath $ConfigPath)
    } catch {
        return $candidate
    }
}

function Test-QuarantineSnapshotLiveSidecars {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [switch]$RequireEvents
    )

    $registryPath = Get-QuarantineVMPayloadRegistryHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    if (-not (Test-Path -LiteralPath $registryPath)) {
        return $false
    }

    if (-not $RequireEvents) {
        return $true
    }

    $usnPath = Get-QuarantineVMUsnDeltaHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $sysmonPath = Get-QuarantineVMSysmonHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    return (Test-Path -LiteralPath $usnPath) -or (Test-Path -LiteralPath $sysmonPath)
}

function Save-QuarantineBaselineEventMarkerSidecars {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [Parameter(Mandatory)][string]$BaselineHostPath
    )

    if (-not (Test-Path -LiteralPath $BaselineHostPath)) { return }

    $baseline = Get-Content -LiteralPath $BaselineHostPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $recordedAt = if ($baseline.recordedAt) { [string]$baseline.recordedAt } else { (Get-Date).ToUniversalTime().ToString('o') }

    $usnPath = Get-QuarantineVMUsnDeltaHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $usnMarker = [ordered]@{
        available   = $true
        eventCount  = 0
        message     = 'Baseline snapshot â€” USN delta starts after this point.'
        baselineAt  = $recordedAt
        recordedAt  = $recordedAt
        startUsn    = if ($baseline.startUsn) { [string]$baseline.startUsn } else { '' }
        events      = @()
    }
    $usnMarker | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $usnPath -Encoding UTF8

    $sysmonPath = Get-QuarantineVMSysmonHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $sysmonMarker = [ordered]@{
        available   = $true
        eventCount  = 0
        message     = 'Baseline snapshot â€” Sysmon events start after this point.'
        baselineAt  = $recordedAt
        recordedAt  = $recordedAt
        events      = @()
    }
    $sysmonMarker | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $sysmonPath -Encoding UTF8

    $serviceInstallPath = Get-QuarantineVMServiceInstallHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $serviceInstallMarker = [ordered]@{
        available   = $true
        eventCount  = 0
        message     = 'Baseline snapshot â€” service install events start after this point.'
        baselineAt  = $recordedAt
        recordedAt  = $recordedAt
        events      = @()
    }
    $serviceInstallMarker | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $serviceInstallPath -Encoding UTF8
}

function Invoke-QuarantineGuestChangedFilesCapture {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [int]$TimeoutMs = 900000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    $guestOut = Join-Path $guestDir 'changed-files-export.json'
    $hostOut = Get-QuarantineVMChangedFilesHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName

    Copy-QuarantineGuestPrivilegedExportDependencies -ConfigPath $ConfigPath -Settings $settings -GuestDir $guestDir

    try {
        Invoke-QuarantineGuestPrivilegedExportBatchFromHost -ConfigPath $ConfigPath -Steps @(
            [pscustomobject]@{
                GuestScriptLeaf = (Split-Path -Leaf $settings.ChangedFilesScript)
                GuestOutFile    = $guestOut
            }
        ) -TimeoutMs $TimeoutMs
    } catch {
        Write-Warning "Changed files privileged export failed: $($_.Exception.Message)"
        return $false
    }

    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $guestOut -HostPath $hostOut -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $hostOut) {
            $changed = Read-QuarantineGuestJsonHostFile -HostPath $hostOut
            Write-Host "Changed files saved for '$SnapshotName': $hostOut ($($changed.fileCount) files, $($changed.pathCount) paths)"
            return $true
        }
    } catch {
        Write-Warning "Changed files capture failed: $($_.Exception.Message)"
    }

    return $false
}

function Merge-QuarantineChangedFilesSidecarIntoManifest {
    param(
        [Parameter(Mandatory)][string]$HostManifestPath,
        [Parameter(Mandatory)]$ChangedExport
    )

    if (-not (Test-Path -LiteralPath $HostManifestPath)) { return $false }
    if (-not $ChangedExport) { return $false }
    if ($ChangedExport.PSObject.Properties['available'] -and $ChangedExport.available -eq $false) {
        $msg = if ($ChangedExport.PSObject.Properties['message']) { [string]$ChangedExport.message } else { 'changed-files export unavailable' }
        Write-Warning "Changed files sidecar skipped: $msg"
        return $false
    }
    if (-not $ChangedExport.PSObject.Properties['files']) { return $false }

    $changedFiles = @($ChangedExport.files | Where-Object { $_ })
    if ($changedFiles.Count -eq 0) { return $false }

    $changedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $changedFiles) {
        if ($entry.p) { [void]$changedPaths.Add([string]$entry.p) }
    }

    $manifest = Get-Content -LiteralPath $HostManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $merged = New-Object System.Collections.Generic.List[object]
    $existingFiles = if ($manifest.PSObject.Properties['files'] -and $manifest.files) { @($manifest.files) } else { @() }
    foreach ($entry in $existingFiles) {
        $key = if ($entry.p) { [string]$entry.p } elseif ($entry.path) { [string]$entry.path } else { '' }
        if ($key -and $changedPaths.Contains($key)) { continue }
        $merged.Add($entry) | Out-Null
    }
    foreach ($entry in $changedFiles) {
        $merged.Add($entry) | Out-Null
    }

    $manifest | Add-Member -NotePropertyName files -NotePropertyValue ($merged.ToArray()) -Force
    $manifest | Add-Member -NotePropertyName fileCount -NotePropertyValue $merged.Count -Force
    Save-QuarantineManifestHostFile -Manifest $manifest -HostPath $HostManifestPath
    Write-Host "Merged changed files into manifest: $($changedFiles.Count) entries"
    return $true
}

function Merge-QuarantineChangedFilesSidecarFromHost {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [Parameter(Mandatory)][string]$HostManifestPath
    )

    $changed = $null
    $sidecar = Get-QuarantineVMChangedFilesHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    if (Test-Path -LiteralPath $sidecar) {
        $changed = Read-QuarantineGuestJsonHostFile -HostPath $sidecar
    }

    $fileCount = 0
    if ($changed -and $changed.PSObject.Properties['files'] -and $changed.files) {
        $fileCount = @($changed.files | Where-Object { $_ }).Count
    }

    $needsRebuild = $false
    if (-not $changed) {
        $needsRebuild = $true
    } elseif ($changed.PSObject.Properties['available'] -and $changed.available -eq $false) {
        $needsRebuild = $true
    } elseif ($fileCount -eq 0) {
        $needsRebuild = $true
    }

    if ($needsRebuild) {
        $usnPath = Get-QuarantineVMUsnDeltaHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
        $sysmonPath = Get-QuarantineVMSysmonHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
        $usn = if (Test-Path -LiteralPath $usnPath) { Read-QuarantineGuestJsonHostFile -HostPath $usnPath } else { $null }
        $sysmon = if (Test-Path -LiteralPath $sysmonPath) { Read-QuarantineGuestJsonHostFile -HostPath $sysmonPath } else { $null }
        if ((Test-QuarantineSidecarHasEvents -Sidecar $usn) -or (Test-QuarantineSidecarHasEvents -Sidecar $sysmon)) {
            $changed = New-QuarantineChangedFilesExportFromEventSidecars -Usn $usn -Sysmon $sysmon
            Write-Host "Rebuilt changed-file paths from event sidecars for '$SnapshotName': $($changed.fileCount) paths"
        } elseif ($changed -and $changed.PSObject.Properties['available'] -and $changed.available -eq $false -and $changed.message) {
            Write-Warning "Changed files sidecar skipped: $($changed.message)"
            return $false
        } else {
            return $false
        }
    }

    if (-not $changed) { return $false }
    return (Merge-QuarantineChangedFilesSidecarIntoManifest -HostManifestPath $HostManifestPath -ChangedExport $changed)
}

function Invoke-QuarantineLiveSnapshotEventCapture {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [Parameter(Mandatory)][string]$FromBaselineSnapshotName,
        [int]$TimeoutMs = 900000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    $hostBaseline = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $FromBaselineSnapshotName
    if (-not (Test-Path -LiteralPath $hostBaseline)) {
        Write-Warning "USN/Sysmon live capture skipped: baseline missing for '$FromBaselineSnapshotName' ($hostBaseline)."
        return $false
    }

    Publish-QuarantineGuestUsnBaselineFromHost -ConfigPath $ConfigPath -HostBaselinePath $hostBaseline -TimeoutMs $TimeoutMs | Out-Null

    $guestUsnOut = Join-Path $guestDir 'usn-delta-export.json'
    $guestSysmonOut = Join-Path $guestDir 'sysmon-events-export.json'
    $guestServiceInstallOut = Join-Path $guestDir 'service-install-events-export.json'
    $hostUsn = Get-QuarantineVMUsnDeltaHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $hostSysmon = Get-QuarantineVMSysmonHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $hostServiceInstall = Get-QuarantineVMServiceInstallHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName

    $batchSteps = @(
        [pscustomobject]@{
            GuestScriptLeaf = (Split-Path -Leaf $settings.UsnDeltaScript)
            GuestOutFile    = $guestUsnOut
        },
        [pscustomobject]@{
            GuestScriptLeaf = (Split-Path -Leaf $settings.SysmonScript)
            GuestOutFile    = $guestSysmonOut
        },
        [pscustomobject]@{
            GuestScriptLeaf = (Split-Path -Leaf $settings.ServiceInstallScript)
            GuestOutFile    = $guestServiceInstallOut
        },
        [pscustomobject]@{
            GuestScriptLeaf = (Split-Path -Leaf $settings.ChangedFilesScript)
            GuestOutFile    = (Join-Path $guestDir 'changed-files-export.json')
        }
    )

    try {
        Invoke-QuarantineGuestPrivilegedExportBatchFromHost -ConfigPath $ConfigPath -Steps $batchSteps -TimeoutMs $TimeoutMs
    } catch {
        Write-Warning "Privileged batch export failed: $($_.Exception.Message)"
    }

    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $guestUsnOut -HostPath $hostUsn -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $hostUsn) {
            $usn = Read-QuarantineGuestJsonHostFile -HostPath $hostUsn
            Write-Host "USN delta saved for '$SnapshotName': $hostUsn ($($usn.eventCount) events)"
        }
    } catch {
        Write-Warning "USN delta live capture failed: $($_.Exception.Message)"
    }

    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $guestSysmonOut -HostPath $hostSysmon -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $hostSysmon) {
            $sysmon = Read-QuarantineGuestJsonHostFile -HostPath $hostSysmon
            Write-Host "Sysmon events saved for '$SnapshotName': $hostSysmon ($($sysmon.eventCount) events)"
        }
    } catch {
        Write-Warning "Sysmon live capture failed: $($_.Exception.Message)"
    }

    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $guestServiceInstallOut -HostPath $hostServiceInstall -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $hostServiceInstall) {
            $svcInstall = Read-QuarantineGuestJsonHostFile -HostPath $hostServiceInstall
            if ($svcInstall.available -eq $false -and $svcInstall.message) {
                Write-Warning "Service install capture: $($svcInstall.message)"
            }
            Write-Host "Service install events saved for '$SnapshotName': $hostServiceInstall ($($svcInstall.eventCount) events)"
        }
    } catch {
        Write-Warning "Service install event capture failed: $($_.Exception.Message)"
    }

    $hostChanged = Get-QuarantineVMChangedFilesHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $guestChangedOut = Join-Path $guestDir 'changed-files-export.json'
    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $guestChangedOut -HostPath $hostChanged -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $hostChanged) {
            $changed = Read-QuarantineGuestJsonHostFile -HostPath $hostChanged
            Write-Host "Changed files saved for '$SnapshotName': $hostChanged ($($changed.fileCount) files, $($changed.pathCount) paths)"
        }
    } catch {
        Write-Warning "Changed files capture failed: $($_.Exception.Message)"
    }

    return (Test-Path -LiteralPath $hostUsn) -or (Test-Path -LiteralPath $hostSysmon) `
        -or (Test-Path -LiteralPath $hostServiceInstall) -or (Test-Path -LiteralPath $hostChanged)
}

function Invoke-QuarantineManifestBaselineMark {
    <#
    .SYNOPSIS
      Record USN baselines on the running guest for manifest compare (registry via agent hive dumps).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [switch]$SkipGuestReadyWait,
        [int]$TimeoutMs = 900000
    )

    Invoke-QuarantineLiveSnapshotManifestMark -ConfigPath $ConfigPath -SnapshotName $SnapshotName `
        -SkipGuestReadyWait:$SkipGuestReadyWait -TimeoutMs $TimeoutMs
}

function Invoke-QuarantineLiveSnapshotManifestMark {
    <#
    .SYNOPSIS
      Capture live-session artifacts on a RAM snapshot: USN baseline or delta, Sysmon.
      Registry hive dumps come from the Go agent at preserve/compare time.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [string]$FromBaselineSnapshotName,
        [switch]$SkipGuestReadyWait,
        [int]$TimeoutMs = 900000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    if (-not $SkipGuestReadyWait) {
        Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath
    }

    $isEvidence = $SnapshotName -match '^Evidence-'
    if (-not $FromBaselineSnapshotName -and $isEvidence) {
        $FromBaselineSnapshotName = Get-QuarantineVMSessionBaselineSnapshotName -ConfigPath $ConfigPath
    }

    if ($isEvidence -and $FromBaselineSnapshotName) {
        Write-Host "Evidence capture vs baseline '$FromBaselineSnapshotName' (USN delta + Sysmon + service installs; registry via agent hive dumps)..."
        Invoke-QuarantineLiveSnapshotEventCapture -ConfigPath $ConfigPath -SnapshotName $SnapshotName `
            -FromBaselineSnapshotName $FromBaselineSnapshotName -TimeoutMs $TimeoutMs | Out-Null
        Write-Host "Live evidence marked for '$SnapshotName' (USN delta + Sysmon; registry via agent hive dumps)."
    } else {
        Set-QuarantineGuestUsnBaseline -ConfigPath $ConfigPath -SaveToHostForSnapshot $SnapshotName `
            -SkipGuestReadyWait -TimeoutMs $TimeoutMs | Out-Null
        $hostBaseline = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
        Save-QuarantineBaselineEventMarkerSidecars -ConfigPath $ConfigPath -SnapshotName $SnapshotName `
            -BaselineHostPath $hostBaseline
        Write-Host "Live baseline marked for '$SnapshotName' (USN; registry via agent hive dumps)."
    }

    Initialize-QuarantineGuestSysmonReady -ConfigPath $ConfigPath | Out-Null
}

function Save-QuarantineGuestUsnBaselineToHost {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName,
        [int]$TimeoutMs = 120000
    )

    $hostPath = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    $guestPath = Get-QuarantineGuestUsnBaselineGuestPath -ConfigPath $ConfigPath
    Copy-QuarantineVMGuestFileFrom -GuestPath $guestPath -HostPath $hostPath -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
    Write-Host "USN baseline saved for snapshot '$SnapshotName': $hostPath"
    return $hostPath
}

function Test-QuarantineGuestUsnBaselinePresent {
    param([string]$ConfigPath)

    $guestPath = Get-QuarantineGuestUsnBaselineGuestPath -ConfigPath $ConfigPath
    $escaped = $guestPath.Replace("'", "''")
    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 60000 `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @('-NoProfile', '-Command', "if (Test-Path -LiteralPath '$escaped') { 'YES' } else { 'NO' }")
    return ($output -join "`n") -match '\bYES\b'
}

function Publish-QuarantineGuestUsnBaselineFromHost {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$HostBaselinePath,
        [switch]$OnlyIfGuestMissing,
        [int]$TimeoutMs = 120000
    )

    if (-not (Test-Path -LiteralPath $HostBaselinePath)) {
        return $false
    }

    if ($OnlyIfGuestMissing -and (Test-QuarantineGuestUsnBaselinePresent -ConfigPath $ConfigPath)) {
        Write-Host 'Guest already has USN baseline - keeping on-disk baseline.'
        return $false
    }

    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    $stageDir = Join-Path $env:TEMP ("qv-baseline-{0}" -f [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    $stageFile = Join-Path $stageDir 'usn-baseline.json'
    try {
        Copy-Item -LiteralPath $HostBaselinePath -Destination $stageFile -Force
        Copy-QuarantineVMGuestFile -Path $stageFile -ConfigPath $ConfigPath -TargetDirectory $guestDir
        Write-Host "Injected USN baseline from host: $HostBaselinePath"
        return $true
    } finally {
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-QuarantineManifestHostText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$HostPath,
        [int]$MaxAttempts = 10
    )

    $tmp = "$HostPath.$PID.tmp"
    [System.IO.File]::WriteAllText($tmp, $Text, [System.Text.UTF8Encoding]::new($false))

    $lastError = $null
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            if (Test-Path -LiteralPath $HostPath) {
                Copy-Item -LiteralPath $tmp -Destination $HostPath -Force
            } else {
                $destDir = Split-Path -Parent $HostPath
                if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Move-Item -LiteralPath $tmp -Destination $HostPath -Force
            }
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            return
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds (500 * $i)
        }
    }

    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    throw $lastError
}

function Publish-QuarantineManifestHostFile {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestPath,
        [int]$MaxAttempts = 10
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) {
        throw "Staging manifest missing: $SourcePath"
    }

    $lastError = $null
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force
            return $DestPath
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds (500 * $i)
        }
    }

    Write-Warning @"
Could not replace locked manifest: $DestPath
Fresh capture kept at: $SourcePath
Close the manifest viewer (or any app using the JSON file) and re-run, or copy the staging file over manually.
"@
    return $SourcePath
}

function Repair-QuarantineGuestJsonHostFile {
    param([Parameter(Mandatory)][string]$HostPath)

    if (-not (Test-Path -LiteralPath $HostPath)) { return }

    $raw = [System.IO.File]::ReadAllText($HostPath)
    $privModule = Join-Path $script:ManifestRoot 'QuarantineGuestPriv.psm1'
    if (-not (Test-Path -LiteralPath $privModule)) { return }

    Import-Module $privModule -Force -ErrorAction SilentlyContinue | Out-Null
    try {
        $json = Get-QuarantineGuestJsonText -Text $raw
    } catch {
        return
    }

    if ($json -ne $raw.Trim()) {
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($HostPath, $json, $utf8)
        Write-Warning "Repaired trailing JSON in: $HostPath"
    }
}

function Read-QuarantineGuestJsonHostFile {
    param([Parameter(Mandatory)][string]$HostPath)

    Repair-QuarantineGuestJsonHostFile -HostPath $HostPath
    return (Get-Content -LiteralPath $HostPath -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Repair-QuarantineManifestHostFile {
    param([Parameter(Mandatory)][string]$HostPath)

    if (-not (Test-Path -LiteralPath $HostPath)) { return }

    $lineCount = 0
    $firstLine = $null
    foreach ($line in [System.IO.File]::ReadLines($HostPath)) {
        $lineCount++
        if ($lineCount -eq 1) { $firstLine = $line }
        if ($lineCount -gt 1) { break }
    }

    if ($lineCount -le 1 -or -not $firstLine) { return }

    try {
        $null = $firstLine | ConvertFrom-Json
    } catch {
        return
    }

    try {
        Write-QuarantineManifestHostText -Text $firstLine -HostPath $HostPath
        Write-Warning "Trimmed trailing data from manifest host file: $HostPath"
    } catch {
        Write-Warning "Could not trim trailing manifest data ($HostPath): $($_.Exception.Message)"
    }
}

function Save-QuarantineManifestHostFile {
    param(
        [Parameter(Mandatory)][object]$Manifest,
        [Parameter(Mandatory)][string]$HostPath,
        [int]$MaxAttempts = 10
    )

    $json = $Manifest | ConvertTo-Json -Depth 8 -Compress
    Write-QuarantineManifestHostText -Text $json -HostPath $HostPath -MaxAttempts $MaxAttempts
}

function Restart-QuarantineManifestCaptureSession {
    param([string]$ConfigPath)

    $vmModule = Join-Path $script:ProjectRoot 'QuarantineVM.psm1'
    Import-Module $vmModule -Force
    Restart-QuarantineVMGuestSession -ConfigPath $ConfigPath
}



function Copy-QuarantineVMGuestFileFrom {
    <#
    .SYNOPSIS
      Copy file(s) from the guest to the host via VirtualBox Guest Control.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GuestPath,

        [Parameter(Mandatory)]
        [string]$HostPath,

        [string]$Username,
        [string]$Password,
        [string]$Domain,
        [string]$ConfigPath,
        [int]$TimeoutMs = 120000
    )

    if (-not (Get-Command Invoke-QuarantineVMGuestControl -ErrorAction SilentlyContinue)) {
        Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    }

    $cred = Resolve-QuarantineVMGuestCredential -Username $Username -Password $Password -Domain $Domain -ConfigPath $ConfigPath
    $hostDir = Split-Path -Parent $HostPath
    if ($hostDir -and -not (Test-Path -LiteralPath $hostDir)) {
        New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
    }

    # copyfrom: --target-directory = full host destination file path (mirrors copyto)
    $copyArgs = @('copyfrom', "--target-directory=$HostPath", $GuestPath)
    Invoke-QuarantineVMGuestControl -Arguments $copyArgs -Username $cred.Username -Password $cred.Password -Domain $cred.Domain -TimeoutMs $TimeoutMs | Out-Null

    if (-not (Test-Path -LiteralPath $HostPath)) {
        throw "Guest copyfrom did not create host file: $HostPath"
    }
    Write-Host "Copied guest:$GuestPath -> $HostPath"
}

function Wait-QuarantineVMGuestReady {
    param(
        [string]$ConfigPath,
        [int]$TimeoutSeconds = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if (Test-QuarantineVMGuestControl -ConfigPath $ConfigPath) { return }
        } catch {
            if ($_.Exception.Message -match 'not ready|poweroff|not running|E_ACCESSDENIED') {
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }
    throw 'Guest control did not become ready within timeout.'
}

function Test-QuarantineGuestPrivilegedExportTaskReady {
    <#
    .SYNOPSIS
      Legacy probe — always false. The SYSTEM QuarantineLabPrivilegedExport task was removed.
    #>
    param([string]$ConfigPath)
    return $false
}

function Copy-QuarantineGuestPrivilegedExportDependencies {
    param(
        [string]$ConfigPath,
        [object]$Settings,
        [string]$GuestDir
    )

    if (-not $Settings) {
        $Settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    }
    if (-not $GuestDir) {
        $GuestDir = $Settings.Config.guest.copyTargetDir
        if (-not $GuestDir) { $GuestDir = 'C:\Users\Public\Quarantine' }
    }

    Copy-QuarantineVMGuestFile -Path $Settings.UsnDeltaScript -ConfigPath $ConfigPath -TargetDirectory $GuestDir -ErrorAction SilentlyContinue | Out-Null
    Copy-QuarantineVMGuestFile -Path $Settings.SysmonScript -ConfigPath $ConfigPath -TargetDirectory $GuestDir -ErrorAction SilentlyContinue | Out-Null
    Copy-QuarantineVMGuestFile -Path $Settings.ServiceInstallScript -ConfigPath $ConfigPath -TargetDirectory $GuestDir -ErrorAction SilentlyContinue | Out-Null
    Copy-QuarantineVMGuestFile -Path $Settings.ChangedFilesScript -ConfigPath $ConfigPath -TargetDirectory $GuestDir -ErrorAction SilentlyContinue | Out-Null
    if ($Settings.PrivModule -and (Test-Path -LiteralPath $Settings.PrivModule)) {
        Copy-QuarantineVMGuestFile -Path $Settings.PrivModule -ConfigPath $ConfigPath -TargetDirectory $GuestDir
    }
}

function Deploy-QuarantineGuestManifestScripts {
    [CmdletBinding()]
    param([string]$ConfigPath)

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }
    Copy-QuarantineGuestPrivilegedExportDependencies -ConfigPath $ConfigPath -Settings $settings -GuestDir $guestDir
    Write-Host "Manifest guest scripts deployed to $guestDir"
}

function Invoke-QuarantineGuestPrivilegedExportBatchFromHost {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [object[]]$Steps,
        [int]$TimeoutMs = 300000
    )

    if (-not $Steps -or $Steps.Count -eq 0) {
        throw 'Privileged export batch requires at least one step.'
    }

    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    Copy-QuarantineGuestPrivilegedExportDependencies -ConfigPath $ConfigPath -Settings $settings -GuestDir $guestDir

    # Known export scripts via guestcontrol as lab admin (after grant).
    # Legacy SYSTEM task that executed arbitrary scriptPath values was removed.
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($step in $Steps) {
        $leaf = [string]$step.GuestScriptLeaf
        $outFile = [string]$step.GuestOutFile
        if ([string]::IsNullOrWhiteSpace($leaf) -or [string]::IsNullOrWhiteSpace($outFile)) {
            throw 'Each privileged batch step requires GuestScriptLeaf and GuestOutFile.'
        }
        if ($leaf -match '[\\/]' -or $leaf -match '\.\.') {
            throw "Refusing non-allowlisted script leaf: $leaf"
        }
        $labels.Add($leaf) | Out-Null
        $scriptGuest = Join-Path $guestDir $leaf
        $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
            -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Command @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptGuest,
                '-OutFile', $outFile
            )
        if ($output) { $output | ForEach-Object { Write-Host $_ } }
    }
    Start-Sleep -Milliseconds 750
    Write-Host "Privileged export finished (guestcontrol, $($Steps.Count) step(s)): $($labels -join ', ')"
}

function Invoke-QuarantineGuestPrivilegedExportFromHost {
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$GuestScriptLeaf,
        [Parameter(Mandatory)][string]$GuestOutFile,
        [int]$TimeoutMs = 300000
    )

    Invoke-QuarantineGuestPrivilegedExportBatchFromHost -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs -Steps @(
        [pscustomobject]@{ GuestScriptLeaf = $GuestScriptLeaf; GuestOutFile = $GuestOutFile }
    )
}
function Invoke-QuarantineVMGuestManifestCapture {
    <#
    .SYNOPSIS
      Capture manifest from the currently running guest.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName,
        [string]$HostManifestPath,
        [int]$TimeoutMs = 600000
    )

    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    if (-not $HostManifestPath) {
        $HostManifestPath = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
    }

    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }
    $guestOut = Join-Path $guestDir 'manifest-capture.json'
    $guestScriptPath = Join-Path $guestDir (Split-Path -Leaf $settings.GuestScript)

    $maxAttempts = 2
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Copy-QuarantineVMGuestFile -Path $settings.GuestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
            Copy-QuarantineVMGuestFile -Path $settings.UsnDeltaScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
            Copy-QuarantineVMGuestFile -Path $settings.SysmonScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
            if ($settings.PrivModule -and (Test-Path -LiteralPath $settings.PrivModule)) {
                Copy-QuarantineVMGuestFile -Path $settings.PrivModule -ConfigPath $ConfigPath -TargetDirectory $guestDir
            }

            $usnOut = Join-Path $guestDir 'usn-delta-export.json'
            $sysmonOut = Join-Path $guestDir 'sysmon-events-export.json'
            $serviceInstallOut = Join-Path $guestDir 'service-install-events-export.json'
            try {
                Invoke-QuarantineGuestPrivilegedExportBatchFromHost -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs -Steps @(
                    [pscustomobject]@{
                        GuestScriptLeaf = (Split-Path -Leaf $settings.UsnDeltaScript)
                        GuestOutFile    = $usnOut
                    },
                    [pscustomobject]@{
                        GuestScriptLeaf = (Split-Path -Leaf $settings.SysmonScript)
                        GuestOutFile    = $sysmonOut
                    },
                    [pscustomobject]@{
                        GuestScriptLeaf = (Split-Path -Leaf $settings.ServiceInstallScript)
                        GuestOutFile    = $serviceInstallOut
                    }
                )
            } catch {
                Write-Warning "Privileged export batch skipped: $($_.Exception.Message)"
            }

            $scanMode = if ($settings.ScanMode) { [string]$settings.ScanMode } else { 'events' }
            $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
                -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
                -Command @(
                    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestScriptPath,
                    '-OutFile', $guestOut,
                    '-SnapshotLabel', $SnapshotName,
                    '-ScanMode', $scanMode,
                    '-RegistryEngine', 'hive',
                    '-HashMaxMb', "$($settings.HashMaxMb)",
                    '-ContentMaxKb', "$($settings.ContentMaxKb)"
                )

            if ($output) { $output | ForEach-Object { Write-Host $_ } }

            $stagePath = "$HostManifestPath.staging-$PID.json"
            Copy-QuarantineVMGuestFileFrom -GuestPath $guestOut -HostPath $stagePath -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
            # VBox guestcontrol copyfrom can briefly retain the destination handle on Windows.
            Start-Sleep -Milliseconds 750
            Repair-QuarantineManifestHostFile -HostPath $stagePath

            $savedPath = Publish-QuarantineManifestHostFile -SourcePath $stagePath -DestPath $HostManifestPath
            if ($savedPath -eq $HostManifestPath -and (Test-Path -LiteralPath $stagePath)) {
                Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Manifest saved: $savedPath"
            return $savedPath
        } catch {
            if ($attempt -ge $maxAttempts) { throw }
            Write-Warning "Manifest capture attempt $attempt/$maxAttempts failed: $($_.Exception.Message)"
            Restart-QuarantineManifestCaptureSession -ConfigPath $ConfigPath
        }
    }
}

function Set-QuarantineGuestUsnBaseline {
    <#
    .SYNOPSIS
      Mark the start of a malware test â€” records NTFS USN journal position in the guest.
      Run after snapshot restore, before executing the sample.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [string]$SaveToHostForSnapshot,
        [switch]$SkipGuestReadyWait,
        [int]$TimeoutMs = 120000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    if (-not $SkipGuestReadyWait) {
        Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath
    }
    Copy-QuarantineVMGuestFile -Path $settings.UsnBaselineScript -ConfigPath $ConfigPath -TargetDirectory $guestDir

    $guestScriptPath = Join-Path $guestDir (Split-Path -Leaf $settings.UsnBaselineScript)
    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestScriptPath)

    if ($output) { $output | ForEach-Object { Write-Host $_ } }
    Write-Host 'USN baseline set in guest. All C: file changes after this point will be recorded at manifest capture.'

    if ($SaveToHostForSnapshot) {
        Save-QuarantineGuestUsnBaselineToHost -ConfigPath $ConfigPath -SnapshotName $SaveToHostForSnapshot -TimeoutMs $TimeoutMs
    }
}

function Test-QuarantineGuestSysmonOperational {
    param([string]$ConfigPath)

    $psCmd = @'
try {
  $null = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
  'SYSMON_OK'
} catch {
  $svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -eq 'Running') { 'SYSMON_ELEVATION_REQUIRED' }
  else { 'SYSMON_NO' }
}
'@

    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 90000 `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @('-NoProfile', '-Command', $psCmd)
    $text = ($output | Out-String)
    if ($text -match 'SYSMON_OK') { return $true }
    if ($text -match 'SYSMON_ELEVATION_REQUIRED') {
        Write-Host 'Sysmon64 running; operational log requires elevated export (manifest capture uses SYSTEM task).'
        return $true
    }
    return $false
}

function Initialize-QuarantineGuestSysmonReady {
    <#
    .SYNOPSIS
      Ensure Sysmon is installed in the guest before manifest capture.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [switch]$SkipInstall
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath

    if (Test-QuarantineGuestSysmonOperational -ConfigPath $ConfigPath) {
        Write-Host 'Sysmon operational log present in guest.'
        return $true
    }

    if ($SkipInstall) {
        Write-Warning 'Sysmon not installed in guest (manifest sysmon section will be empty).'
        return $false
    }

    Write-Host 'Sysmon not detected in guest - deploying...'
    $hostExeCandidates = @()
    $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $hostSysmonExeRel = if ($cfg.sysmon -and $cfg.sysmon.PSObject.Properties['hostSysmonExe']) {
        [string]$cfg.sysmon.hostSysmonExe
    } else { '' }
    if ($hostSysmonExeRel) {
        $configured = if ([IO.Path]::IsPathRooted($hostSysmonExeRel)) {
            $hostSysmonExeRel
        } else {
            Join-Path $script:ProjectRoot ($hostSysmonExeRel -replace '\\', [IO.Path]::DirectorySeparatorChar)
        }
        $hostExeCandidates += $configured
    }
    $hostExeCandidates += @(
        (Join-Path $script:ProjectRoot 'tools\Sysmon64.exe'),
        (Join-Path $script:ProjectRoot 'sysmon\Sysmon64.exe')
    )
    $hasHostBinary = $false
    foreach ($candidate in $hostExeCandidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $hasHostBinary = $true
            break
        }
    }
    if (-not $hasHostBinary) {
        Write-Warning @"
Sysmon64.exe not found on host. Download from https://learn.microsoft.com/sysinternals/downloads/sysmon
and place at: $($script:ProjectRoot)\tools\Sysmon64.exe
(or set sysmon.hostSysmonExe in config). Manifest sysmon section will be empty until installed.
"@
    }

    $deploy = Join-Path $script:ProjectRoot 'guest\Deploy-QuarantineSysmon.ps1'
    if (-not (Test-Path -LiteralPath $deploy)) {
        Write-Warning "Deploy script missing: $deploy"
        return $false
    }

    try {
        & $deploy -ConfigPath $ConfigPath
    } catch {
        Write-Warning "Sysmon deploy failed: $($_.Exception.Message)"
        return $false
    }

    if (Test-QuarantineGuestSysmonOperational -ConfigPath $ConfigPath) {
        Write-Host 'Sysmon ready in guest.'
        return $true
    }

    Write-Warning 'Sysmon deploy finished but operational log still missing.'
    return $false
}

function Set-QuarantineVMManifestOfflineNetwork {
    param(
        [string]$ConfigPath
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    Set-QuarantineVMNetworkMode -ConfigPath $ConfigPath -Mode none -SkipProxy -SkipCapture
    Write-Host 'Manifest capture: network disabled (NIC none â€” no internet).'
}

function Restore-QuarantineVMManifestNetwork {
    param(
        [string]$ConfigPath,
        [string]$SavedMode
    )

    if ([string]::IsNullOrWhiteSpace($SavedMode)) {
        $SavedMode = 'quarantine'
    }

    Write-Host "Restoring network mode: $SavedMode"
    if ($SavedMode -eq 'quarantine') {
        Set-QuarantineVMNetworkMode -ConfigPath $ConfigPath -Mode quarantine -SkipProxy -SkipCapture
    } elseif ($SavedMode -eq 'offline') {
        Set-QuarantineVMNetworkMode -ConfigPath $ConfigPath -Mode intnet -SkipProxy -SkipCapture
    } else {
        Set-QuarantineVMNetworkMode -ConfigPath $ConfigPath -Mode $SavedMode -SkipProxy -SkipCapture
    }
}

function Export-QuarantineVMManifestFromSnapshot {
    <#
    .SYNOPSIS
      Restore a snapshot, boot guest, capture manifest, optionally stop VM.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName,
        [switch]$SkipRestore,
        [switch]$StopAfter,
        [switch]$MarkBeforeCapture,
        [switch]$SaveGuestBaselineOnly,
        [string]$InjectBaselineHostPath,
        [switch]$PreferGuestBaseline,
        [int]$TimeoutMs = 600000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $vmName = $settings.Config.vmName
    $savedNetworkMode = if ($settings.Config.network.mode) { $settings.Config.network.mode } else { 'quarantine' }
    $networkRestored = $false

    try {
        if (-not $SkipRestore) {
            $SnapshotName = Resolve-QuarantineVMSnapshotName -Name $SnapshotName -ConfigPath $ConfigPath
            Reset-QuarantineVM -ConfigPath $ConfigPath -SnapshotName $SnapshotName
        }

        $hostPath = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName

        Initialize-QuarantineVMMutable -ConfigPath $ConfigPath -VmName $vmName -Reason 'capture manifest offline'

        Set-QuarantineVMManifestOfflineNetwork -ConfigPath $ConfigPath

        if ((Get-QuarantineVMState -VmName $vmName) -notin @('running', 'paused', 'starting')) {
            Start-QuarantineVM -ConfigPath $ConfigPath -Type headless -SkipProxy
            Start-Sleep -Seconds 15
        }

        Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath

        Initialize-QuarantineGuestSysmonReady -ConfigPath $ConfigPath | Out-Null

        if ($InjectBaselineHostPath) {
            $onlyIfGuestMissing = $true
            if ($PSBoundParameters.ContainsKey('PreferGuestBaseline')) {
                $onlyIfGuestMissing = [bool]$PreferGuestBaseline
            }
            Publish-QuarantineGuestUsnBaselineFromHost -ConfigPath $ConfigPath `
                -HostBaselinePath $InjectBaselineHostPath `
                -OnlyIfGuestMissing:$onlyIfGuestMissing `
                -TimeoutMs $TimeoutMs | Out-Null
        }

        if ($SaveGuestBaselineOnly) {
            $hostBaseline = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $SnapshotName
            if (Test-QuarantineGuestUsnBaselinePresent -ConfigPath $ConfigPath) {
                Save-QuarantineGuestUsnBaselineToHost -ConfigPath $ConfigPath -SnapshotName $SnapshotName `
                    -TimeoutMs $TimeoutMs | Out-Null
            } elseif (Test-Path -LiteralPath $hostBaseline) {
                Write-Host "Clean snapshot has no frozen guest baseline; using host file from reset -Clean: $hostBaseline"
                Publish-QuarantineGuestUsnBaselineFromHost -ConfigPath $ConfigPath -HostBaselinePath $hostBaseline `
                    -TimeoutMs $TimeoutMs | Out-Null
            } else {
                Write-Warning "No USN baseline on guest or host for '$SnapshotName'. Run: .\quarantine-vm.ps1 reset -Clean"
                Set-QuarantineGuestUsnBaseline -ConfigPath $ConfigPath -SaveToHostForSnapshot $SnapshotName `
                    -SkipGuestReadyWait -TimeoutMs $TimeoutMs
            }
        } elseif ($MarkBeforeCapture) {
            Set-QuarantineGuestUsnBaseline -ConfigPath $ConfigPath -SaveToHostForSnapshot $SnapshotName `
                -SkipGuestReadyWait -TimeoutMs $TimeoutMs
        }

        $savedPath = Invoke-QuarantineVMGuestManifestCapture -ConfigPath $ConfigPath -SnapshotName $SnapshotName -HostManifestPath $hostPath -TimeoutMs $TimeoutMs

        if ($StopAfter) {
            Stop-QuarantineVM -ConfigPath $ConfigPath -Force
            Start-Sleep -Seconds 3
        }

        Restore-QuarantineVMManifestNetwork -ConfigPath $ConfigPath -SavedMode $savedNetworkMode
        $networkRestored = $true

        return $savedPath
    } finally {
        if (-not $networkRestored) {
            try {
                # Let an in-flight guestcontrol session finish closing before we poweroff for network restore.
                Start-Sleep -Seconds 8
                $state = Get-QuarantineVMState -VmName $vmName
                if ($state -in @('running', 'paused', 'starting')) {
                    Stop-QuarantineVM -ConfigPath $ConfigPath -Force
                    Start-Sleep -Seconds 5
                }
                Restore-QuarantineVMManifestNetwork -ConfigPath $ConfigPath -SavedMode $savedNetworkMode
            } catch {
                Write-Warning "Could not restore network mode '$savedNetworkMode': $($_.Exception.Message)"
            }
        }
    }
}



function Invoke-QuarantineManifestSnapshotPairCapture {
    <#
    .SYNOPSIS
      Prepare From/To manifests for compare. Default: host sidecars only (no VM restore).
      Use -ForceGuestCapture for legacy offline snapshot restore + guest boot.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$From,
        [Parameter(Mandatory)]
        [string]$To,
        [switch]$Refresh,
        [switch]$UseCache,
        [switch]$SkipMark,
        [switch]$StopAfter,
        [switch]$ForceGuestCapture
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath

    $doRefresh = $Refresh -or -not $UseCache
    $fromSnap = Resolve-QuarantineVMSnapshotName -Name $From -ConfigPath $ConfigPath
    $toSnap = Resolve-QuarantineVMSnapshotName -Name $To -ConfigPath $ConfigPath
    $fromPath = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $fromSnap
    $toPath = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $toSnap
    $baselineHost = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $fromSnap

    if ($ForceGuestCapture) {
        Write-Warning 'ForceGuestCapture: restoring snapshots and booting guest (legacy offline capture).'
    }

    if ($doRefresh -or -not (Test-Path -LiteralPath $fromPath)) {
        Write-Host "Capturing manifest for snapshot: $fromSnap"
        $markFrom = (-not $SkipMark) -and -not $doRefresh -and -not (Test-Path -LiteralPath $baselineHost)
        $saveGuestBaseline = (-not $SkipMark) -and $doRefresh
        if ($saveGuestBaseline) {
            Write-Host "Syncing USN baseline for From snapshot '$fromSnap' (guest file or host Clean-baseline.json)."
        } elseif ($markFrom) {
            Write-Host "No host baseline for '$fromSnap' - marking before From capture."
        }
        $fromExportParams = @{
            ConfigPath   = $ConfigPath
            SnapshotName = $fromSnap
            StopAfter    = $StopAfter
        }
        if ($saveGuestBaseline) { $fromExportParams.SaveGuestBaselineOnly = $true }
        elseif ($markFrom) { $fromExportParams.MarkBeforeCapture = $true }
        $fromPath = Export-QuarantineVMManifestFromSnapshot @fromExportParams
    }

    if (-not $SkipMark -and -not (Test-Path -LiteralPath $baselineHost)) {
        $baselineHost = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $fromSnap
    }

    $refreshTo = $doRefresh -or -not (Test-Path -LiteralPath $toPath)
    if (-not $refreshTo -and (Test-Path -LiteralPath $fromPath) -and (Test-Path -LiteralPath $toPath)) {
        try {
            $leftM = Get-Content -LiteralPath $fromPath -Raw -Encoding UTF8
            try { $leftObj = $leftM | ConvertFrom-Json } catch { $leftObj = (Get-Content -LiteralPath $fromPath -TotalCount 1) | ConvertFrom-Json }
            $rightM = Get-Content -LiteralPath $toPath -Raw -Encoding UTF8
            try { $rightObj = $rightM | ConvertFrom-Json } catch { $rightObj = (Get-Content -LiteralPath $toPath -TotalCount 1) | ConvertFrom-Json }
            $warn = Get-QuarantineManifestCompareWarnings -Left $leftObj -Right $rightObj
            if ($warn.Count -gt 0) {
                Write-Warning "Cached To manifest '$toSnap' looks stale vs From - re-capturing To."
                $refreshTo = $true
            }
        } catch {
            Write-Verbose "Could not compare manifest freshness: $($_.Exception.Message)"
        }
    }

    if ($refreshTo) {
        Write-Host "Capturing manifest for snapshot: $toSnap"
        $exportParams = @{
            ConfigPath   = $ConfigPath
            SnapshotName = $toSnap
            StopAfter    = $StopAfter
        }
        if (-not $SkipMark -and (Test-Path -LiteralPath $baselineHost)) {
            $exportParams.InjectBaselineHostPath = $baselineHost
            $exportParams.PreferGuestBaseline = $true
        }
        $toPath = Export-QuarantineVMManifestFromSnapshot @exportParams
    }

    $fromPath = Resolve-QuarantineManifestHostPathLatest -ConfigPath $ConfigPath -SnapshotName $fromSnap
    $toPath = Resolve-QuarantineManifestHostPathLatest -ConfigPath $ConfigPath -SnapshotName $toSnap

    return [pscustomobject]@{
        FromSnap  = $fromSnap
        ToSnap    = $toSnap
        FromPath  = $fromPath
        ToPath    = $toPath
        Refreshed = $doRefresh
        LiveOnly  = $false
    }
}

function Compare-QuarantineVMSnapshots {
    <#
    .SYNOPSIS
      Diff manifests between two snapshots (host sidecars by default; no VM boot).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$From,
        [Parameter(Mandatory)]
        [string]$To,
        [switch]$Refresh,
        [switch]$UseCache,
        [switch]$SkipMark,
        [switch]$StopAfter,
        [switch]$ForceGuestCapture,
        [string]$ReportPath
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath

    $captured = Invoke-QuarantineManifestSnapshotPairCapture -ConfigPath $ConfigPath -From $From -To $To `
        -Refresh:$Refresh -UseCache:$UseCache -SkipMark:$SkipMark -StopAfter:$StopAfter `
        -ForceGuestCapture:$ForceGuestCapture
    $fromPath = $captured.FromPath
    $toPath = $captured.ToPath
    $fromSnap = $captured.FromSnap
    $toSnap = $captured.ToSnap

    if (-not $ReportPath) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $safeFrom = Get-SafeSnapshotFileName -Name $fromSnap
        $safeTo = Get-SafeSnapshotFileName -Name $toSnap
        $ReportPath = Join-Path $settings.LogDir "diff-${safeFrom}-vs-${safeTo}-$stamp.txt"
    }

    $jsonPath = [System.IO.Path]::ChangeExtension($ReportPath, '.diff.json')
    & $settings.CompareScript -From $fromPath -To $toPath -ReportPath $ReportPath -JsonPath $jsonPath -ConfigPath $ConfigPath
    return $ReportPath
}

function Export-QuarantineManifestDiffJson {
    <#
    .SYNOPSIS
      Write structured diff JSON for two on-disk manifest files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FromPath,

        [Parameter(Mandatory)]
        [string]$ToPath,

        [string]$JsonPath,

        [string]$ConfigPath
    )

    if (-not $JsonPath) {
        $fromLeaf = [System.IO.Path]::GetFileNameWithoutExtension($FromPath)
        $toLeaf = [System.IO.Path]::GetFileNameWithoutExtension($ToPath)
        $JsonPath = Join-Path (Split-Path -Parent $FromPath) "diff-${fromLeaf}-vs-${toLeaf}.diff.json"
    }

    $diff = Get-QuarantineManifestDiff -From $FromPath -To $ToPath -ConfigPath $ConfigPath
    $jsonDir = Split-Path -Parent $JsonPath
    if ($jsonDir -and -not (Test-Path -LiteralPath $jsonDir)) {
        New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null
    }
    $diff | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $JsonPath -Encoding UTF8
    if (-not (Test-Path -LiteralPath $JsonPath)) {
        throw "Diff JSON was not written: $JsonPath"
    }
    return $JsonPath
}

function Invoke-QuarantineManifestCaptureLive {
    <#
    .SYNOPSIS
      Re-run live USN/Sysmon/event capture on the running guest (no snapshot restore).
      Registry comes from agent hive dumps at preserve/compare time.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)][string]$SnapshotName,
        [string]$FromBaselineSnapshotName,
        [int]$TimeoutMs = 900000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $snap = Resolve-QuarantineVMSnapshotName -Name $SnapshotName -ConfigPath $ConfigPath
    Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath

    $fromBaseline = $FromBaselineSnapshotName
    if (-not $fromBaseline -and $snap -match '^Evidence-') {
        $fromBaseline = Get-QuarantineVMSessionBaselineSnapshotName -ConfigPath $ConfigPath
    }

    if ($fromBaseline) {
        Invoke-QuarantineLiveSnapshotEventCapture -ConfigPath $ConfigPath -SnapshotName $snap `
            -FromBaselineSnapshotName $fromBaseline -TimeoutMs $TimeoutMs | Out-Null
    } elseif (Test-Path -LiteralPath (Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $snap)) {
        $hostBaseline = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $snap
        Save-QuarantineBaselineEventMarkerSidecars -ConfigPath $ConfigPath -SnapshotName $snap -BaselineHostPath $hostBaseline
    } else {
        Set-QuarantineGuestUsnBaseline -ConfigPath $ConfigPath -SaveToHostForSnapshot $snap -SkipGuestReadyWait -TimeoutMs $TimeoutMs | Out-Null
        $hostBaseline = Get-QuarantineVMManifestBaselineHostPath -ConfigPath $ConfigPath -SnapshotName $snap
        Save-QuarantineBaselineEventMarkerSidecars -ConfigPath $ConfigPath -SnapshotName $snap -BaselineHostPath $hostBaseline
    }

    Write-Host "Live capture complete for '$snap' (USN/Sysmon/events; registry via agent hive dumps)."
    return $true
}

function Open-QuarantineManifestDiffViewer {
    <#
    .SYNOPSIS
      Build diff JSON (if needed) and open the browser viewer.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$From,
        [Parameter(Mandatory)]
        [string]$To,
        [string]$DiffJsonPath,
        [switch]$Refresh,
        [switch]$UseCache,
        [switch]$SkipMark,
        [switch]$StopAfter,
        [switch]$ForceGuestCapture
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath

    $captured = Invoke-QuarantineManifestSnapshotPairCapture -ConfigPath $ConfigPath -From $From -To $To `
        -Refresh:$Refresh -UseCache:$UseCache -SkipMark:$SkipMark -StopAfter:$StopAfter `
        -ForceGuestCapture:$ForceGuestCapture
    $fromPath = $captured.FromPath
    $toPath = $captured.ToPath
    $fromSnap = $captured.FromSnap
    $toSnap = $captured.ToSnap

    if (-not $DiffJsonPath) {
        $safeFrom = Get-SafeSnapshotFileName -Name $fromSnap
        $safeTo = Get-SafeSnapshotFileName -Name $toSnap
        $DiffJsonPath = Join-Path $settings.LogDir "diff-${safeFrom}-vs-${safeTo}.diff.json"
    }

    $DiffJsonPath = Export-QuarantineManifestDiffJson -FromPath $fromPath -ToPath $toPath -JsonPath $DiffJsonPath -ConfigPath $ConfigPath
    Write-Host "Diff JSON: $DiffJsonPath"

    $openScript = Join-Path $script:ManifestRoot 'viewer\Open-ManifestDiffViewer.ps1'
    $sessionPath = & $openScript -DiffJsonPath $DiffJsonPath
    return [pscustomobject]@{
        DiffJson = $DiffJsonPath
        SessionHtml = $sessionPath
        FromManifest = $fromPath
        ToManifest = $toPath
    }
}

function Invoke-QuarantineManifestFileEnrich {
    <#
    .SYNOPSIS
      Hash/content-scan files identified by USN/Sysmon in an existing manifest (targeted, fast).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$SnapshotName,
        [string[]]$Paths,
        [string]$DiffJsonPath,
        [switch]$SkipRestore,
        [int]$TimeoutMs = 300000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $snap = Resolve-QuarantineVMSnapshotName -Name $SnapshotName -ConfigPath $ConfigPath
    $hostManifestPath = Get-QuarantineVMManifestHostPath -ConfigPath $ConfigPath -SnapshotName $snap

    if (-not (Test-Path -LiteralPath $hostManifestPath)) {
        throw "Manifest not found: $hostManifestPath (capture first)."
    }

    $manifest = Get-Content -LiteralPath $hostManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $pathList = New-Object System.Collections.Generic.List[string]
    if ($Paths) {
        foreach ($p in $Paths) {
            if (-not [string]::IsNullOrWhiteSpace($p)) { $pathList.Add($p.Trim()) | Out-Null }
        }
    } elseif ($DiffJsonPath) {
        if (-not (Test-Path -LiteralPath $DiffJsonPath)) { throw "Diff JSON not found: $DiffJsonPath" }
        $diff = Get-Content -LiteralPath $DiffJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($bucket in @($diff.files.added, $diff.files.modified)) {
            foreach ($item in @($bucket)) {
                $p = [string]$item.path
                if ($p) { $pathList.Add($p) | Out-Null }
            }
        }
    } else {
        foreach ($p in (Get-EnrichableFilePathsFromManifest -Manifest $manifest)) {
            $pathList.Add($p) | Out-Null
        }
    }

    $unique = @($pathList | Select-Object -Unique)
    if ($unique.Count -eq 0) {
        Write-Warning 'No paths to enrich (no USN/Sysmon file events in manifest?).'
        return $hostManifestPath
    }

    Write-Host "Enriching $($unique.Count) file path(s) for snapshot: $snap"

    if (-not $SkipRestore) {
        $vmName = $settings.Config.vmName
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -notin @('running', 'paused', 'starting')) {
            Reset-QuarantineVM -ConfigPath $ConfigPath -SnapshotName $snap
            Start-QuarantineVM -ConfigPath $ConfigPath -Type headless -SkipProxy
            Start-Sleep -Seconds 15
        }
    }

    Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath

    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }
    $pathsGuest = Join-Path $guestDir 'enrich-paths.txt'
    $pathsHost = Join-Path $settings.LogDir 'enrich-paths.txt'
    $guestOut = Join-Path $guestDir 'enrich-files.json'
    $hostEnrich = "$hostManifestPath.enrich.json"
    $guestScript = Join-Path $guestDir (Split-Path -Leaf $settings.TargetedFilesScript)

    @($unique) | Set-Content -LiteralPath $pathsHost -Encoding UTF8
    Copy-QuarantineVMGuestFile -Path $settings.TargetedFilesScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Copy-QuarantineVMGuestFile -Path $pathsHost -ConfigPath $ConfigPath -TargetDirectory $guestDir

    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestScript,
            '-PathsFile', $pathsGuest,
            '-OutFile', $guestOut,
            '-HashMaxMb', "$($settings.HashMaxMb)",
            '-ContentMaxKb', "$($settings.ContentMaxKb)"
        )
    if ($output) { $output | ForEach-Object { Write-Host $_ } }

    Copy-QuarantineVMGuestFileFrom -GuestPath $guestOut -HostPath $hostEnrich -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
    $enriched = Get-Content -LiteralPath $hostEnrich -Raw -Encoding UTF8 | ConvertFrom-Json

    $byPath = @{}
    foreach ($f in @($manifest.files)) {
        if ($f.p) { $byPath[[string]$f.p] = $f }
    }
    foreach ($f in @($enriched.files)) {
        if ($f.p) { $byPath[[string]$f.p] = $f }
    }

    $merged = @($byPath.Values)
    $manifest | Add-Member -NotePropertyName files -NotePropertyValue $merged -Force
    $manifest | Add-Member -NotePropertyName fileCount -NotePropertyValue $merged.Count -Force
    $manifest | Add-Member -NotePropertyName enrichedAt -NotePropertyValue ([string]$enriched.enrichedAt) -Force

    Save-QuarantineManifestHostFile -Manifest $manifest -HostPath $hostManifestPath
    Write-Host "Enriched manifest: $hostManifestPath ($($enriched.scanned) files hashed)"
    return $hostManifestPath
}

function Get-QuarantineVMManifestList {
    [CmdletBinding()]
    param([string]$ConfigPath)

    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $settings.LogDir)) {
        Write-Host 'No manifests captured yet.'
        return @()
    }

    Get-ChildItem -LiteralPath $settings.LogDir -Filter '*.json' -File | Sort-Object LastWriteTime -Descending | ForEach-Object {
        try {
            $m = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            [pscustomobject]@{
                File = $_.FullName
                Snapshot = $m.snapshot
                CapturedAt = $m.capturedAt
                Files = $m.fileCount
                Registry = $m.registryCount
                Tasks = $m.taskCount
                SizeKb = [math]::Round($_.Length / 1KB, 1)
            }
        } catch {
            [pscustomobject]@{
                File = $_.FullName
                Snapshot = '?'
                CapturedAt = $_.LastWriteTime.ToString('o')
                Files = $null
                Registry = $null
                Tasks = $null
                SizeKb = [math]::Round($_.Length / 1KB, 1)
            }
        }
    }
}

function Invoke-QuarantineGuestManifestProbe {
    <#
    .SYNOPSIS
      Run interactive manifest prerequisite probes inside the guest (Sysmon, USN, elevation).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [int]$TimeoutMs = 180000
    )

    Initialize-QuarantineManifestConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
    $guestDir = $settings.Config.guest.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath
    $probeScript = Join-Path $script:ManifestRoot 'Invoke-QuarantineGuestManifestProbe.ps1'
    Copy-QuarantineVMGuestFile -Path $probeScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Copy-QuarantineVMGuestFile -Path $settings.UsnDeltaScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Copy-QuarantineVMGuestFile -Path $settings.SysmonScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    if ($settings.ElevatedRunnerScript -and (Test-Path -LiteralPath $settings.ElevatedRunnerScript)) {
        Copy-QuarantineVMGuestFile -Path $settings.ElevatedRunnerScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    }

    $guestProbe = Join-Path $guestDir (Split-Path -Leaf $probeScript)
    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestProbe)

    if ($output) { $output | ForEach-Object { Write-Host $_ } }

    Write-Host '--- privileged export (backup-priv + evtx fallback) ---'
    $usnOut = Join-Path $guestDir 'probe-usn-host.json'
    $sysmonOut = Join-Path $guestDir 'probe-sysmon-host.json'
    try {
        Invoke-QuarantineGuestPrivilegedExportBatchFromHost -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs -Steps @(
            [pscustomobject]@{
                GuestScriptLeaf = (Split-Path -Leaf $settings.UsnDeltaScript)
                GuestOutFile    = $usnOut
            },
            [pscustomobject]@{
                GuestScriptLeaf = (Split-Path -Leaf $settings.SysmonScript)
                GuestOutFile    = $sysmonOut
            }
        )
        $hostUsn = Join-Path $env:TEMP 'quarantine-probe-usn.json'
        Copy-QuarantineVMGuestFileFrom -GuestPath $usnOut -HostPath $hostUsn -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        $u = Read-QuarantineGuestJsonHostFile -HostPath $hostUsn
        Write-Host "HOST_ELEV_USN available=$($u.available) count=$($u.eventCount) msg=$($u.message)"
    } catch {
        Write-Warning "HOST_ELEV_USN_FAIL $($_.Exception.Message)"
    }
    try {
        $hostSysmon = Join-Path $env:TEMP 'quarantine-probe-sysmon.json'
        Copy-QuarantineVMGuestFileFrom -GuestPath $sysmonOut -HostPath $hostSysmon -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs
        Start-Sleep -Milliseconds 500
        $s = Read-QuarantineGuestJsonHostFile -HostPath $hostSysmon
        $msg = if ($s.PSObject.Properties['message']) { $s.message } else { '' }
        Write-Host "HOST_ELEV_SYSMON available=$($s.available) count=$($s.eventCount) msg=$msg"
    } catch {
        Write-Warning "HOST_ELEV_SYSMON_FAIL $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Get-QuarantineVMManifestSettings',
    'Get-QuarantineVMManifestHostPath',
    'Remove-QuarantineSnapshotManifestArtifacts',
    'Get-QuarantineVMManifestBaselineHostPath',
    'Copy-QuarantineVMGuestFileFrom',
    'Invoke-QuarantineVMGuestManifestCapture',
    'Invoke-QuarantineManifestFileEnrich',
    'Invoke-QuarantineManifestSnapshotPairCapture',
    'Export-QuarantineVMManifestFromSnapshot',
    'Compare-QuarantineVMSnapshots',
    'Get-QuarantineVMManifestList',
    'Get-QuarantineManifestDiff',
    'Export-QuarantineManifestDiffJson',
    'Open-QuarantineManifestDiffViewer',
    'Set-QuarantineGuestUsnBaseline',
    'Invoke-QuarantineManifestBaselineMark',
    'Invoke-QuarantineLiveSnapshotManifestMark',
    'Invoke-QuarantineManifestCaptureLive',
    'Get-QuarantineRegistryEngine',
    'Wait-QuarantineVMGuestReady',
    'Test-QuarantineGuestPrivilegedExportTaskReady',
    'Invoke-QuarantineGuestPrivilegedExportFromHost',
    'Invoke-QuarantineGuestPrivilegedExportBatchFromHost',
    'Initialize-QuarantineGuestSysmonReady',
    'Invoke-QuarantineGuestManifestProbe',
    'Deploy-QuarantineGuestManifestScripts'
)
