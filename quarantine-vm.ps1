#Requires -Version 5.1

<#

.SYNOPSIS

  Spin up an isolated VirtualBox Windows host for spam/virus/quarantine work.



.EXAMPLE

  .\quarantine-vm.ps1 create

  .\quarantine-vm.ps1 install

  .\quarantine-vm.ps1 snapshot

  .\quarantine-vm.ps1 start

  .\quarantine-vm.ps1 network quarantine

  .\quarantine-vm.ps1 reset

#>

[CmdletBinding()]

param(

    [Parameter(Position = 0)]

    [ValidateSet('create', 'install', 'start', 'stop', 'snapshot', 'snapshots', 'baseline', 'preserve', 'reset', 'status', 'mount-iso', 'guest-additions', 'relocate', 'consolidate', 'network', 'proxy', 'capture', 'clipboard', 'inbox', 'guest', 'payload', 'sysmon', 'regshot', 'manifest', 'help')]

    [string]$Action = 'help',



    [Parameter(Position = 1)]

    [ValidateSet('start', 'stop', 'status', 'export-ca', 'quarantine', 'offline', 'nat', 'intnet', 'none', 'hostonly', 'hosttoguest', 'guesttohost', 'bidirectional', 'disabled', 'push', 'open', 'close', 'clear', 'run', 'copy', 'test', 'ps', 'hosts', 'install', 'capture', 'capture-live', 'diff', 'view', 'mark', 'list', 'enrich', 'probe', 'grant')]

    [string]$SubAction,



    [Parameter()]

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json'),



    [Parameter()]

    [ValidateSet('nat', 'intnet', 'none', 'hostonly', 'quarantine', 'offline')]

    [string]$NetworkMode = 'intnet',



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
                if ((Get-QuarantineRegistryEngine -ConfigPath $ConfigPath) -eq 'regshot') {
                    Write-Host 'Regshot needs Regshot_cmd-x64-ANSI.exe (not the GUI exe). See tools/regshot/README.md'
                    Write-Host '  .\quarantine-vm.ps1 regshot copy'
                }
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

            default { throw 'Usage: .\quarantine-vm.ps1 guest run|ps|copy|test|hosts' }

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
                & (Join-Path $PSScriptRoot 'guest\Deploy-QuarantineSysmon.ps1') -ConfigPath $ConfigPath
            }

            'copy' {
                & (Join-Path $PSScriptRoot 'guest\Deploy-QuarantineSysmon.ps1') -ConfigPath $ConfigPath -SkipInstall
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
  .\quarantine-vm.ps1 sysmon copy      Copy config + installer to guest
  .\quarantine-vm.ps1 sysmon install   Copy and install (needs Sysmon64.exe in guest sysmon folder)
  .\quarantine-vm.ps1 sysmon grant     Copy one-time privilege grant script (run elevated in guest GUI)

Place Sysmon64.exe in C:\Users\Public\Quarantine\sysmon\ (copy zip from Sysinternals first).
'@
            }

        }

    }

    'regshot' {

        switch ($SubAction) {

            'copy' {
                & (Join-Path $PSScriptRoot 'guest\Deploy-QuarantineRegshot.ps1') -ConfigPath $ConfigPath
            }

            default {
                throw @'
Usage:
  .\quarantine-vm.ps1 regshot copy   Copy RegShot CMD + config to guest

Place Regshot_cmd-x64-ANSI.exe in tools\regshot\ (see tools/regshot/README.md).
Optional GUI: Regshot-x64-Unicode.exe from https://github.com/Seabreg/Regshot
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

            default {

                throw @'
Usage:
  .\quarantine-vm.ps1 manifest capture [-SnapshotName Clean] [-StopAfter]
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

  snapshot   Save a snapshot (-SnapshotName, -SnapshotDescription). Running VM = live (RAM + disk). Existing name prompts to replace; -Force replaces without prompt. -Offline for disk-only.

  snapshots  List saved snapshots (live = includes RAM / resume session)

  baseline   Wipe all snapshots, merge current disk, save fresh disk-only Clean (VM is powered off)

  preserve   Save compromised/session state for analysis (-SnapshotName as label). Live if VM is running.

  reset      Restore a snapshot and start it (interactive); -Clean skips picker. Live snapshots resume the logged-in session (no POST).

  status     Show VM state



Guest Additions (host-to-guest paste):

  guest-additions   Mount VirtualBox Guest Additions ISO in the VM



Network (internet-only quarantine vs offline):

  network quarantine   NAT + mitmproxy logging (internet, no LAN)

  network offline      Internal network only (alias for intnet)

  network intnet|nat|none|hostonly



Proxy / capture (host-side):

  proxy start|stop|status|export-ca

  capture start|stop



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
 