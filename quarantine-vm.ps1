#Requires -Version 5.1

<#

.SYNOPSIS

  Quarantine lab — single entry point for VM, network, evidence, and UI.



.EXAMPLE

  .\quarantine-vm.ps1 create

  .\quarantine-vm.ps1 start

  .\quarantine-vm.ps1 proxy start

  .\quarantine-vm.ps1 ui

  .\quarantine-vm.ps1 reset -Clean

  .\quarantine-vm.ps1 -Rebuild ui

#>

[CmdletBinding()]

param(

    [Parameter(Position = 0)]

    [ValidateSet('create', 'install', 'start', 'stop', 'snapshot', 'snapshots', 'delete-snapshot', 'baseline', 'preserve', 'reset', 'status', 'mount-iso', 'guest-additions', 'relocate', 'consolidate', 'network', 'proxy', 'capture', 'clipboard', 'inbox', 'guest', 'payload', 'sysmon', 'manifest', 'ui', 'agent', 'setup', 'gateway', 'help')]

    [string]$Action = 'help',



    [Parameter(Position = 1)]

    [string]$SubAction,



    [Parameter()]

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json'),



    [Parameter()]

    [ValidateSet('nat', 'intnet', 'none', 'hostonly', 'quarantine', 'offline', 'gateway')]

    [string]$NetworkMode = 'intnet',



    [Parameter()]

    [switch]$Rebuild,



    [Parameter()]

    [switch]$Force,



    [Parameter()]

    [switch]$Fresh,



    [Parameter()]

    [switch]$Clean,

    [Parameter()]

    [switch]$Mark,

    [Parameter()]

    [switch]$SkipProxy,



    [Parameter()]

    [string]$SnapshotName,



    [Parameter()]

    [string]$SnapshotDescription,



    [Parameter(ValueFromRemainingArguments = $true)]

    [string[]]$SourcePath,



    [Parameter()]

    [string]$GuestUser,



    [Parameter()]

    [string]$GuestPassword,



    [Parameter()]

    [string]$GuestExe,



    [Parameter()]

    [string]$GuestDomain,



    [Parameter()]

    [string]$GuestTargetDir,



    [Parameter()]

    [string]$FromSnapshot,



    [Parameter()]

    [string]$ToSnapshot,



    [Parameter()]

    [switch]$Refresh,



    [Parameter()]

    [switch]$StopAfter,



    [Parameter()]

    [switch]$SkipRestore,



    [Parameter()]

    [switch]$SkipMark,

    [Parameter()]

    [switch]$ForceGuestCapture,



    [Parameter()]

    [switch]$Offline,



    [Parameter()]

    [switch]$UseCache,



    [Parameter()]

    [string]$DiffJsonPath

)



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'

$script:QuarantineRoot = $PSScriptRoot

# --- Go binary build / launch (preferred path for day-to-day commands) ---

$script:WailsExe = Join-Path $script:QuarantineRoot 'go\cmd\quarantine\build\bin\quarantine.exe'
$script:CliExe = Join-Path $script:QuarantineRoot 'go\quarantine.exe'
$script:AgentExe = Join-Path $script:QuarantineRoot 'go\quarantine-agent.exe'
$script:WailsDir = Join-Path $script:QuarantineRoot 'go\cmd\quarantine'
$script:GoRoot = Join-Path $script:QuarantineRoot 'go'
$script:SourceExtensions = @('.go', '.html', '.js', '.css', '.json', '.mod', '.sum')

function Test-QuarantineSourcePathExcluded {
    param([string]$FullName)
    $n = $FullName -replace '/', '\'
    return ($n -match '\\build\\|\\node_modules\\|\\wailsjs\\|\\\.git\\')
}

function Get-QuarantineLatestSourceWriteTime {
    param([string[]]$Roots)
    $latest = [datetime]::MinValue
    foreach ($rootPath in $Roots) {
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $script:SourceExtensions -contains $_.Extension -and
                -not (Test-QuarantineSourcePathExcluded $_.FullName)
            } |
            ForEach-Object {
                if ($_.LastWriteTime -gt $latest) { $latest = $_.LastWriteTime }
            }
    }
    return $latest
}

function Test-QuarantineBinaryStale {
    param([string]$ExePath, [string[]]$SourceRoots)
    if (-not (Test-Path -LiteralPath $ExePath)) { return $true }
    $srcTime = Get-QuarantineLatestSourceWriteTime -Roots $SourceRoots
    if ($srcTime -eq [datetime]::MinValue) { return $false }
    return $srcTime -gt (Get-Item -LiteralPath $ExePath).LastWriteTime
}

function Invoke-QuarantineNativeCommand {
    param([Parameter(Mandatory)][string[]]$Command)
    $exe = $Command[0]
    $argList = @()
    if ($Command.Count -gt 1) {
        $argList = $Command[1..($Command.Count - 1)]
    }
    # Resolve bare tool names (wails often lives in GOPATH\bin, which may be missing from PATH).
    if ($exe -notmatch '[\\/]' -and -not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        $resolved = $null
        if ($exe -eq 'wails') {
            $goBin = ''
            try { $goBin = ((& go env GOPATH) | Select-Object -First 1).Trim() } catch { $goBin = '' }
            if ($goBin) {
                $candidate = Join-Path $goBin "bin\wails.exe"
                if (Test-Path -LiteralPath $candidate) { $resolved = $candidate }
            }
            if (-not $resolved) {
                $fallback = Join-Path $env:USERPROFILE 'go\bin\wails.exe'
                if (Test-Path -LiteralPath $fallback) { $resolved = $fallback }
            }
        }
        if ($resolved) {
            $exe = $resolved
        } else {
            throw "Command not found: $($Command[0]). For Wails UI builds, install with: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        }
    }
    & $exe @argList 2>&1 | ForEach-Object { Write-Host $_ }
    if ($null -eq $LASTEXITCODE -or $LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $exe $($argList -join ' ')"
    }
}

function Ensure-QuarantineCliBinary {
    param([switch]$Force)
    $sources = @($script:GoRoot)
    $needCli = $Force -or (Test-QuarantineBinaryStale -ExePath $script:CliExe -SourceRoots $sources)
    $needAgent = $Force -or (Test-QuarantineBinaryStale -ExePath $script:AgentExe -SourceRoots $sources)
    if (-not $needCli -and -not $needAgent) { return }
    Push-Location $script:GoRoot
    try {
        if ($needCli) {
            Write-Host 'Building quarantine.exe (CLI)...'
            Invoke-QuarantineNativeCommand @('go', 'build', '-o', 'quarantine.exe', './cmd/quarantine')
        }
        if ($needAgent) {
            Write-Host 'Building quarantine-agent.exe...'
            Invoke-QuarantineNativeCommand @('go', 'build', '-o', 'quarantine-agent.exe', './cmd/quarantine-agent')
        }
    } finally {
        Pop-Location
    }
}

function Ensure-QuarantineWailsBinary {
    param([switch]$Force)
    $sources = @(
        (Join-Path $script:GoRoot 'cmd\quarantine')
        (Join-Path $script:GoRoot 'internal')
    )
    if ($Force -or (Test-QuarantineBinaryStale -ExePath $script:WailsExe -SourceRoots $sources)) {
        if (-not $Force -and (Test-Path -LiteralPath $script:WailsExe)) {
            Write-Host 'Wails UI is stale — rebuilding...'
        }
        Write-Host 'Building Wails UI...'
        Push-Location $script:WailsDir
        try {
            Invoke-QuarantineNativeCommand @('wails', 'build')
        } finally {
            Pop-Location
        }
        if (-not (Test-Path -LiteralPath $script:WailsExe)) {
            throw 'Wails build did not produce build\bin\quarantine.exe'
        }
    }
    return ,$script:WailsExe
}

function Test-QuarantineUseWails {
    param([string]$ActionName, [string]$Sub)
    if ($ActionName -eq 'ui') { return $true }
    if ($ActionName -eq 'manifest' -and $Sub -eq 'view') { return $true }
    return $false
}

function Test-QuarantinePreferGo {
    param([string]$ActionName, [string]$Sub)
    # PowerShell-only (or incomplete in Go) — keep legacy path.
    $psOnly = @{
        'create'           = $true
        'install'          = $true
        'mount-iso'        = $true
        'guest-additions'  = $true
        'relocate'         = $true
        'consolidate'      = $true
        'payload'          = $true
        'help'             = $true
    }
    if ($psOnly.ContainsKey($ActionName)) { return $false }
    if ($ActionName -eq 'capture' -and $Sub -eq 'status') { return $false }
    if ($ActionName -eq 'inbox' -and $Sub -in @('push', 'clear', 'status')) { return $false }
    if ($ActionName -eq 'guest' -and $Sub -in @('test', 'ps', 'hosts')) { return $false }
    if ($ActionName -eq 'sysmon' -and $Sub -in @('copy', 'install', 'grant')) { return $false }
    if ($ActionName -eq 'manifest' -and $Sub -in @('mark', 'list', 'enrich', 'probe', 'capture', 'capture-live')) { return $false }
    if ($env:QUARANTINE_FORCE_PS -eq '1') { return $false }
    $goActions = @(
        'ui', 'status', 'start', 'stop', 'snapshot', 'snapshots', 'preserve', 'reset',
        'baseline', 'delete-snapshot', 'manifest', 'network', 'proxy', 'capture',
        'inbox', 'clipboard', 'guest', 'agent', 'setup', 'sysmon', 'gateway'
    )
    return ($goActions -contains $ActionName)
}

function Get-QuarantineGoArgList {
    param(
        [string]$ActionName,
        [string]$Sub,
        [string[]]$Rest
    )
    $goArgs = New-Object System.Collections.Generic.List[string]
    [void]$goArgs.Add($ActionName)
    if (-not [string]::IsNullOrWhiteSpace($Sub)) {
        # Pass through Go-style flags already in SubAction (--clean) or subcommands (start).
        [void]$goArgs.Add($Sub)
    }
    foreach ($r in @($Rest)) {
        if (-not [string]::IsNullOrWhiteSpace($r)) { [void]$goArgs.Add($r) }
    }

    # Map common PowerShell switches → Go flags when not already present.
    $joined = ($goArgs -join ' ')
    switch ($ActionName) {
        'reset' {
            if ($Clean -and $joined -notmatch '(^|\s)--clean(\s|$)') { [void]$goArgs.Add('--clean') }
            if ($SnapshotName -and $joined -notmatch '(^|\s)--snapshot(\s|$)') {
                [void]$goArgs.Add('--snapshot'); [void]$goArgs.Add($SnapshotName)
            }
        }
        'snapshot' {
            if ($SnapshotName -and $joined -notmatch '(^|\s)--name(\s|$)') {
                [void]$goArgs.Add('--name'); [void]$goArgs.Add($SnapshotName)
            }
            if ($SnapshotDescription -and $joined -notmatch '(^|\s)--description(\s|$)') {
                [void]$goArgs.Add('--description'); [void]$goArgs.Add($SnapshotDescription)
            }
            if ($Force -and $joined -notmatch '(^|\s)--force(\s|$)') { [void]$goArgs.Add('--force') }
            if ($Offline -and $joined -notmatch '(^|\s)--offline(\s|$)') { [void]$goArgs.Add('--offline') }
        }
        'preserve' {
            if ($SnapshotName -and $joined -notmatch '(^|\s)--label(\s|$)') {
                [void]$goArgs.Add('--label'); [void]$goArgs.Add($SnapshotName)
            }
        }
        'delete-snapshot' {
            if ($SnapshotName -and $joined -notmatch '(^|\s)--name(\s|$)') {
                [void]$goArgs.Add('--name'); [void]$goArgs.Add($SnapshotName)
            }
            if ($Force -and $joined -notmatch '(^|\s)--force(\s|$)') { [void]$goArgs.Add('--force') }
        }
        'manifest' {
            if ($FromSnapshot -and $joined -notmatch '(^|\s)--from(\s|$)') {
                [void]$goArgs.Add('--from'); [void]$goArgs.Add($FromSnapshot)
            }
            if ($ToSnapshot -and $joined -notmatch '(^|\s)--to(\s|$)') {
                [void]$goArgs.Add('--to'); [void]$goArgs.Add($ToSnapshot)
            }
            if ($Refresh -and $joined -notmatch '(^|\s)--refresh(\s|$)') { [void]$goArgs.Add('--refresh') }
        }
        'stop' {
            if ($Force -and $joined -notmatch '(^|\s)--force(\s|$)') { [void]$goArgs.Add('--force') }
        }
    }
    return ,$goArgs.ToArray()
}

function Invoke-QuarantineGo {
    param([string[]]$GoArgs, [switch]$WantWails, [switch]$ForceRebuild)
    if ($WantWails) {
        $exe = Ensure-QuarantineWailsBinary -Force:$ForceRebuild
    } else {
        Ensure-QuarantineCliBinary -Force:$ForceRebuild
        $exe = $script:CliExe
    }
    & (Get-Item -LiteralPath $exe).FullName --config $ConfigPath @GoArgs
    exit $LASTEXITCODE
}

if (Test-QuarantinePreferGo -ActionName $Action -Sub $SubAction) {
    $goArgs = Get-QuarantineGoArgList -ActionName $Action -Sub $SubAction -Rest $SourcePath
    $wantWails = Test-QuarantineUseWails -ActionName $Action -Sub $SubAction
    Invoke-QuarantineGo -GoArgs $goArgs -WantWails:$wantWails -ForceRebuild:$Rebuild
}

# Rebuild with no action → just build binaries
if ($Rebuild -and $Action -eq 'help') {
    Ensure-QuarantineCliBinary -Force
    Ensure-QuarantineWailsBinary -Force | Out-Null
    Write-Host 'Rebuild complete.'
    exit 0
}

Import-Module (Join-Path $PSScriptRoot 'QuarantineVM.psm1') -Force

Import-Module (Join-Path $PSScriptRoot 'QuarantineNetwork.psm1') -Force

Import-Module (Join-Path $PSScriptRoot 'manifest\QuarantineManifest.psm1') -Force



switch ($Action) {

    'create' {

        New-QuarantineVM -ConfigPath $ConfigPath -Force:$Force

    }

    'install' {

        Install-QuarantineVM -ConfigPath $ConfigPath

    }

    'mount-iso' {

        $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath

        Set-QuarantineVMInstallMedia -VmName $cfg.vmName -ConfigPath $ConfigPath

    }

    'guest-additions' {

        Mount-QuarantineVMGuestAdditions -ConfigPath $ConfigPath

    }

    'relocate' {

        Move-QuarantineVMDisk -ConfigPath $ConfigPath

    }

    'consolidate' {

        Move-QuarantineVMStorage -ConfigPath $ConfigPath

    }

    'start' {

        Start-QuarantineVM -ConfigPath $ConfigPath -Fresh:$Fresh -SkipProxy:$SkipProxy

    }

    'stop' {

        Stop-QuarantineVM -ConfigPath $ConfigPath -Force:$Force

    }

    'snapshot' {

        $snapParams = @{ ConfigPath = $ConfigPath }

        if (-not [string]::IsNullOrWhiteSpace($SnapshotName)) { $snapParams.Name = $SnapshotName }

        if (-not [string]::IsNullOrWhiteSpace($SnapshotDescription)) { $snapParams.Description = $SnapshotDescription }

        if ($Force) { $snapParams.Force = $true }

        if ($Offline) { $snapParams.Offline = $true }

        Save-QuarantineVMSnapshot @snapParams

    }

    'snapshots' {

        Get-QuarantineVMSnapshots -ConfigPath $ConfigPath

    }

    'delete-snapshot' {

        $deleteParams = @{ ConfigPath = $ConfigPath }

        if (-not [string]::IsNullOrWhiteSpace($SnapshotName)) { $deleteParams.SnapshotName = $SnapshotName }

        if ($Force) { $deleteParams.Force = $true }

        Remove-QuarantineVMSnapshot @deleteParams

    }

    'baseline' {

        $baseParams = @{ ConfigPath = $ConfigPath }

        if (-not [string]::IsNullOrWhiteSpace($SnapshotName)) { $baseParams.Name = $SnapshotName }

        if (-not [string]::IsNullOrWhiteSpace($SnapshotDescription)) { $baseParams.Description = $SnapshotDescription }

        New-QuarantineVMBaseline @baseParams

    }

    'preserve' {

        Save-QuarantineVMEvidence -ConfigPath $ConfigPath -Label $SnapshotName -Offline:$Offline

    }

    'reset' {

        $resetParams = @{ ConfigPath = $ConfigPath }

        if ($Clean) {

            $resetParams.Clean = $true

        } elseif (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {

            $resetParams.SnapshotName = $SnapshotName

        }

        $snap = Reset-QuarantineVM @resetParams

        $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
        $vmName = $cfg.vmName
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -eq 'saved') {
            Write-Host 'Resuming logged-in session (live snapshot — no POST)...'
            Start-QuarantineVM -ConfigPath $ConfigPath -Type gui -SkipProxy:$SkipProxy
        } elseif ($state -notin @('running', 'paused', 'starting')) {
            Write-Host 'Snapshot is disk-only; starting a cold boot. For resume-to-desktop, snapshot while logged in.'
            Start-QuarantineVM -ConfigPath $ConfigPath -Type gui -SkipProxy:$SkipProxy
        }

        $doMark = (-not $SkipMark) -and ($Clean -or $Mark)
        if ($doMark) {
            $markSnapName = if ($Clean) {
                (Resolve-QuarantineVMSnapshot -ConfigPath $ConfigPath -Clean).Name
            } else {
                $snap.Name
            }
            $state = Get-QuarantineVMState -VmName $vmName
            if ($state -notin @('running', 'paused', 'starting')) {
                Start-QuarantineVM -ConfigPath $ConfigPath -Type gui -SkipProxy
                Start-Sleep -Seconds 15
            } elseif ($state -eq 'starting') {
                Start-Sleep -Seconds 10
            } else {
                Start-Sleep -Seconds 5
            }
            try {
                Invoke-QuarantineManifestBaselineMark -ConfigPath $ConfigPath -SnapshotName $markSnapName -SkipGuestReadyWait
            } catch {
                Write-Warning "Baseline mark failed: $($_.Exception.Message)"
            }
        } elseif (-not $SkipMark) {
            Write-Host @"

Tip: Mark USN + payload registry baseline before making test changes:
  .\quarantine-vm.ps1 manifest mark -SnapshotName $($snap.Name)
  (or restore again with: .\quarantine-vm.ps1 reset -SnapshotName $($snap.Name) -Mark)
  Live snapshot/preserve also marks automatically when RAM is included.
"@
        }

    }

    'status' {

        Get-QuarantineVMStatus -ConfigPath $ConfigPath | Format-List

    }

    'network' {

        $mode = if ($SubAction) { $SubAction } else { $NetworkMode }

        Set-QuarantineVMNetworkMode -Mode $mode -ConfigPath $ConfigPath -SkipProxy:$SkipProxy

    }

    'proxy' {

        switch ($SubAction) {

            'start' { Start-QuarantineProxy -ConfigPath $ConfigPath }

            'stop' { Stop-QuarantineProxy -ConfigPath $ConfigPath }

            'status' { Get-QuarantineProxyStatus -ConfigPath $ConfigPath | Format-List }

            'export-ca' { Export-QuarantineProxyCA -ConfigPath $ConfigPath }

            default { throw "Usage: .\quarantine-vm.ps1 proxy start|stop|status|export-ca" }

        }

    }

    'capture' {

        switch ($SubAction) {

            'start' { Start-QuarantineCapture -ConfigPath $ConfigPath -Required }

            'stop' { Stop-QuarantineCapture -ConfigPath $ConfigPath }

            'status' { Get-QuarantineCaptureStatus -ConfigPath $ConfigPath | Format-List }

            default { throw "Usage: .\quarantine-vm.ps1 capture start|stop|status" }

        }

    }

    'clipboard' {

        $mode = if ($SubAction) { $SubAction } else { 'hosttoguest' }

        Set-QuarantineVMClipboard -Mode $mode -ConfigPath $ConfigPath

    }

    'inbox' {

        switch ($SubAction) {

            'push' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {

                    throw 'Usage: .\quarantine-vm.ps1 inbox push <file> [file...]'

                }

                Push-QuarantineVMInbox -Path $SourcePath -ConfigPath $ConfigPath

            }

            'open' { Open-QuarantineVMInbox -ConfigPath $ConfigPath }

            'close' { Close-QuarantineVMInbox -ConfigPath $ConfigPath }

            'status' { Get-QuarantineVMInbox -ConfigPath $ConfigPath | Format-List }

            'clear' { Clear-QuarantineVMInbox -ConfigPath $ConfigPath }

            default { throw 'Usage: .\quarantine-vm.ps1 inbox push|open|close|status|clear' }

        }

    }

    'guest' {

        $guestParams = @{
            ConfigPath = $ConfigPath
        }

        if ($GuestUser) { $guestParams.Username = $GuestUser }

        if ($GuestPassword) { $guestParams.Password = $GuestPassword }

        if ($GuestDomain) { $guestParams.Domain = $GuestDomain }

        switch ($SubAction) {

            'run' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {

                    throw 'Usage: .\quarantine-vm.ps1 guest run <command...>'

                }

                if ($GuestExe) { $guestParams.Exe = $GuestExe }

                Invoke-QuarantineVMGuestRun @guestParams -Command $SourcePath

            }

            'ps' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {

                    throw 'Usage: .\quarantine-vm.ps1 guest ps <powershell-command>'

                }

                $guestParams.Exe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

                Invoke-QuarantineVMGuestRun @guestParams -Command @('-NoProfile', '-NonInteractive', '-Command', ($SourcePath -join ' '))

            }

            'copy' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {

                    throw 'Usage: .\quarantine-vm.ps1 guest copy <host-file> [file...]'

                }

                if ($GuestTargetDir) { $guestParams.TargetDirectory = $GuestTargetDir }

                Copy-QuarantineVMGuestFile @guestParams -Path $SourcePath

            }

            'test' { Test-QuarantineVMGuestControl @guestParams | Out-Null }

            'hosts' {
                Invoke-QuarantineGuestHostsEntry -ConfigPath $ConfigPath
            }

            default { throw 'Usage: .\quarantine-vm.ps1 guest run|ps|copy|test|hosts|gateway-setup' }

        }

    }

    'payload' {

        $payloadCred = Resolve-QuarantineVMPayloadCredential -ConfigPath $ConfigPath
        $payloadParams = @{
            ConfigPath = $ConfigPath
            Username   = $payloadCred.Username
            Password   = $payloadCred.Password
            Domain     = $payloadCred.Domain
        }

        switch ($SubAction) {

            'run' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {
                    throw 'Usage: .\quarantine-vm.ps1 payload run <command...>'
                }

                if ($GuestExe) { $payloadParams.Exe = $GuestExe }

                Invoke-QuarantineVMGuestRun @payloadParams -Command $SourcePath

            }

            'ps' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {
                    throw 'Usage: .\quarantine-vm.ps1 payload ps <powershell-command>'
                }

                $payloadParams.Exe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

                Invoke-QuarantineVMGuestRun @payloadParams -Command @('-NoProfile', '-NonInteractive', '-Command', ($SourcePath -join ' '))

            }

            'copy' {

                if (-not $SourcePath -or $SourcePath.Count -eq 0) {
                    throw 'Usage: .\quarantine-vm.ps1 payload copy <host-file> [file...]'
                }

                if ($GuestTargetDir) { $payloadParams.TargetDirectory = $GuestTargetDir }

                Copy-QuarantineVMGuestFile @payloadParams -Path $SourcePath

            }

            default { throw 'Usage: .\quarantine-vm.ps1 payload run|ps|copy  (runs as standard user jkcooper)' }

        }

    }

    'sysmon' {

        switch ($SubAction) {

            'install' {
                & (Join-Path $PSScriptRoot 'guest\Deploy-QuarantineSysmon.ps1') -ConfigPath $ConfigPath -ShowGuestInstructions
            }

            'copy' {
                & (Join-Path $PSScriptRoot 'guest\Deploy-QuarantineSysmon.ps1') -ConfigPath $ConfigPath
            }

            'grant' {
                $grantScript = Join-Path $PSScriptRoot 'guest\Grant-QuarantineGuestEventLogAccess.ps1'
                $workerScript = Join-Path $PSScriptRoot 'guest\Invoke-QuarantinePrivilegedExportWorker.ps1'
                Copy-QuarantineVMGuestFile -Path $grantScript -ConfigPath $ConfigPath -TargetDirectory 'C:\Users\Public\Quarantine'
                if (Test-Path -LiteralPath $workerScript) {
                    Copy-QuarantineVMGuestFile -Path $workerScript -ConfigPath $ConfigPath -TargetDirectory 'C:\Users\Public\Quarantine'
                }
                Write-Host @"

Copied Grant-QuarantineGuestEventLogAccess.ps1 (+ worker) to the guest.

One-time (elevated PowerShell inside the guest GUI):
  Set-ExecutionPolicy Bypass -Scope Process -Force
  & 'C:\Users\Public\Quarantine\Grant-QuarantineGuestEventLogAccess.ps1'

Expect: GRANT_OK and 'Registered scheduled task QuarantineLabPrivilegedExport (SYSTEM)'.
Then snapshot Clean and re-run manifest view -Refresh.
"@
            }

            default {
                throw @'
Usage:
  .\quarantine-vm.ps1 sysmon copy      Copy config + Sysmon64.exe to guest
  .\quarantine-vm.ps1 sysmon install   Copy files, then show one-time guest apply command
  .\quarantine-vm.ps1 sysmon grant     Copy one-time privilege grant script (run elevated in guest GUI)

Place Sysmon64.exe at tools\Sysmon64.exe on the host (Sysinternals zip).
After copy/install, apply config once in elevated guest PowerShell (see install output).
'@
            }

        }

    }

    'manifest' {

        switch ($SubAction) {

            'capture' {

                $snap = if (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {
                    $SnapshotName
                } else {
                    Select-QuarantineVMSnapshot -ConfigPath $ConfigPath
                }

                Export-QuarantineVMManifestFromSnapshot -ConfigPath $ConfigPath -SnapshotName $snap -StopAfter:$StopAfter -SkipRestore:$SkipRestore

            }

            'capture-live' {

                if ([string]::IsNullOrWhiteSpace($SnapshotName)) {
                    throw 'Usage: .\quarantine-vm.ps1 manifest capture-live -SnapshotName Evidence-regtest [-FromSnapshot CleanSession]'
                }

                $fromBaseline = if (-not [string]::IsNullOrWhiteSpace($FromSnapshot)) { $FromSnapshot } else { $null }
                Invoke-QuarantineManifestCaptureLive -ConfigPath $ConfigPath -SnapshotName $SnapshotName `
                    -FromBaselineSnapshotName $fromBaseline

            }

            'diff' {

                if ([string]::IsNullOrWhiteSpace($FromSnapshot) -or [string]::IsNullOrWhiteSpace($ToSnapshot)) {
                    throw 'Usage: .\quarantine-vm.ps1 manifest diff -FromSnapshot CleanSession -ToSnapshot Evidence-regtest [-Refresh] [-ForceGuestCapture]'
                }

                Compare-QuarantineVMSnapshots -ConfigPath $ConfigPath -From $FromSnapshot -To $ToSnapshot `
                    -Refresh:$Refresh -UseCache:$UseCache -SkipMark:$SkipMark -StopAfter:$StopAfter `
                    -ForceGuestCapture:$ForceGuestCapture

            }

            'view' {

                if ([string]::IsNullOrWhiteSpace($FromSnapshot) -or [string]::IsNullOrWhiteSpace($ToSnapshot)) {
                    throw 'Usage: .\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-regtest [-Refresh] [-ForceGuestCapture]'
                }

                Open-QuarantineManifestDiffViewer -ConfigPath $ConfigPath -From $FromSnapshot -To $ToSnapshot `
                    -Refresh:$Refresh -UseCache:$UseCache -SkipMark:$SkipMark -StopAfter:$StopAfter `
                    -ForceGuestCapture:$ForceGuestCapture

            }

            'mark' {

                $markSnap = if (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {
                    Resolve-QuarantineVMSnapshotName -Name $SnapshotName -ConfigPath $ConfigPath
                } else {
                    $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
                    if ($cfg.cleanSnapshotName) { $cfg.cleanSnapshotName } else { 'Clean' }
                }

                Invoke-QuarantineManifestBaselineMark -ConfigPath $ConfigPath -SnapshotName $markSnap

            }

            'list' {

                Get-QuarantineVMManifestList -ConfigPath $ConfigPath | Format-Table -AutoSize

            }

            'enrich' {

                if ([string]::IsNullOrWhiteSpace($SnapshotName)) {
                    throw 'Usage: .\quarantine-vm.ps1 manifest enrich -SnapshotName mydif [-SkipRestore] [-DiffJsonPath path]'
                }

                $enrichParams = @{
                    ConfigPath   = $ConfigPath
                    SnapshotName = $SnapshotName
                    SkipRestore  = $SkipRestore
                }
                if ($DiffJsonPath) { $enrichParams.DiffJsonPath = $DiffJsonPath }

                Invoke-QuarantineManifestFileEnrich @enrichParams

            }

            'probe' {

                Invoke-QuarantineGuestManifestProbe -ConfigPath $ConfigPath

            }

            'deploy' {

                Deploy-QuarantineGuestManifestScripts -ConfigPath $ConfigPath

            }

            default {

                throw @'
Usage:
  .\quarantine-vm.ps1 manifest deploy              Copy latest manifest/USN scripts to guest
  .\quarantine-vm.ps1 manifest capture-live -SnapshotName Evidence-... [-FromSnapshot CleanSession]
  .\quarantine-vm.ps1 manifest diff -FromSnapshot Clean -ToSnapshot Evidence-... [-UseCache] [-SkipMark] [-StopAfter]
  .\quarantine-vm.ps1 manifest view -FromSnapshot Clean -ToSnapshot Evidence-... [-UseCache] [-SkipMark] [-StopAfter]
  .\quarantine-vm.ps1 manifest enrich -SnapshotName mydif [-SkipRestore] [-DiffJsonPath path]
  .\quarantine-vm.ps1 manifest mark [-SnapshotName Clean]
  .\quarantine-vm.ps1 manifest list
  .\quarantine-vm.ps1 manifest probe

  Default scanMode is events (USN + Sysmon + registry; no full disk walk).
  Use manifest enrich to hash specific changed paths after review.
  diff/view refresh manifests by default (use -UseCache to reuse host JSON).
  USN baseline is auto-marked on reset -Clean and during compare unless -SkipMark.
'@

            }

        }

    }

    default {

        Write-Host @'

Quarantine VM utility (VirtualBox)



  create     Create the isolated VM (requires config + Windows ISO)

  install    Start VM for first-time Windows installation

  start      Start the quarantine VM (-Fresh, -SkipProxy)

  stop       Stop the VM (-Force for power off)

  snapshot   Save a snapshot (-SnapshotName, -SnapshotDescription). Running VM = live (RAM + disk). Existing name prompts to replace (child snapshots such as Evidence-* are deleted); -Force replaces without prompt. -Offline for disk-only.

  snapshots  List saved snapshots (live = includes RAM / resume session)

  delete-snapshot  Delete a snapshot (-SnapshotName, or interactive picker). Removes host manifest sidecars. -Force deletes child snapshots or protected baselines.

  baseline   Wipe all snapshots, merge current disk, save fresh disk-only Clean (VM is powered off)

  preserve   Save compromised/session state for analysis (-SnapshotName as label). Live if VM is running.

  reset      Restore a snapshot and start it (interactive); -Clean skips picker. Live snapshots resume the logged-in session (no POST).

  status     Show VM state

  ui         Open the Wails desktop UI (Go)

  agent      install|sync-token|health|set-token (Go)



Guest Additions (host-to-guest paste):

  guest-additions   Mount VirtualBox Guest Additions ISO in the VM



Network (internet-only quarantine vs offline):

  network gateway      Linux gateway VM (routing + capture + transparent TLS MITM)

  network quarantine   NAT + host mitmproxy logging (legacy)

  network offline      Internal network only (alias for intnet)

  network intnet|nat|none|hostonly



Gateway appliance:

  gateway create|start|stop|status|provision|export-ca|sync-logs



Proxy / capture:

  proxy start|stop|status|export-ca

  capture start|stop|status



Clipboard (requires Guest Additions in the guest):

  clipboard hosttoguest   Paste from host into VM (default, one-way)

  clipboard disabled      Turn off clipboard sharing

  clipboard guesttohost   Copy from VM to host only

  clipboard bidirectional Both directions



Sample transfer (one-way host inbox):

  inbox push <file>       Copy sample(s) to host inbox + SHA256 log

  inbox open              Mount read-only share in running guest

  inbox close             Remove transient share

  inbox status            List inbox files and mount state

  inbox clear             Delete inbox files (share must be closed)



Guest control (requires Guest Additions + guest credentials):

  guest test              Verify guest control connectivity

  guest run <cmd...>      Run cmd.exe /c command in guest

  guest ps <script>       Run PowerShell -Command in guest

  guest copy <file>       Copy host file(s) into guest (no shared folder)
  guest gateway-setup     Upload Configure + CA installer + mitm CA for gateway mode



Manifest (filesystem + registry between snapshots):

  manifest capture [-SnapshotName name] [-StopAfter]

  manifest diff -FromSnapshot Clean -ToSnapshot Evidence-... [-UseCache] [-SkipMark] [-StopAfter]

  manifest view -FromSnapshot Clean -ToSnapshot Evidence-... [-UseCache] [-SkipMark] [-StopAfter]

  manifest mark [-SnapshotName Clean]   Set USN baseline (also saved to host for compare)

  manifest list

  diff/view refresh host manifests by default (-UseCache to reuse cached JSON).
  reset -Clean auto-marks unless -SkipMark.



Setup:

  1. Copy config\quarantine-vm.example.json -> config\quarantine-vm.json

  2. Set windowsIsoPath to your Windows ISO

  3. .\quarantine-vm.ps1 create

  4. .\quarantine-vm.ps1 install

  5. Run network\guest\Configure-QuarantineGuestNetwork.ps1 in guest (Admin)

  6. If HTTPS fails, run network\guest\Install-QuarantineProxyCA.ps1 in guest (Admin)

  7. .\quarantine-vm.ps1 baseline



'@

    }

}
 