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

    [ValidateSet('create', 'install', 'start', 'stop', 'snapshot', 'snapshots', 'baseline', 'preserve', 'reset', 'status', 'mount-iso', 'guest-additions', 'relocate', 'consolidate', 'network', 'proxy', 'capture', 'clipboard', 'help')]

    [string]$Action = 'help',



    [Parameter(Position = 1)]

    [ValidateSet('start', 'stop', 'status', 'export-ca', 'quarantine', 'offline', 'nat', 'intnet', 'none', 'hostonly', 'hosttoguest', 'guesttohost', 'bidirectional', 'disabled')]

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

    [switch]$SkipProxy,



    [Parameter()]

    [string]$SnapshotName,



    [Parameter()]

    [string]$SnapshotDescription

)



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'



Import-Module (Join-Path $PSScriptRoot 'QuarantineVM.psm1') -Force

Import-Module (Join-Path $PSScriptRoot 'QuarantineNetwork.psm1') -Force



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

        Save-QuarantineVMEvidence -ConfigPath $ConfigPath -Label $SnapshotName

    }

    'reset' {

        $resetParams = @{ ConfigPath = $ConfigPath }

        if ($Clean) {

            $resetParams.Clean = $true

        } elseif (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {

            $resetParams.SnapshotName = $SnapshotName

        }

        Reset-QuarantineVM @resetParams

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

            'start' { Start-QuarantineCapture -ConfigPath $ConfigPath }

            'stop' { Stop-QuarantineCapture -ConfigPath $ConfigPath }

            default { throw "Usage: .\quarantine-vm.ps1 capture start|stop" }

        }

    }

    'clipboard' {

        $mode = if ($SubAction) { $SubAction } else { 'hosttoguest' }

        Set-QuarantineVMClipboard -Mode $mode -ConfigPath $ConfigPath

    }

    default {

        Write-Host @'

Quarantine VM utility (VirtualBox)



  create     Create the isolated VM (requires config + Windows ISO)

  install    Start VM for first-time Windows installation

  start      Start the quarantine VM (-Fresh, -SkipProxy)

  stop       Stop the VM (-Force for power off)

  snapshot   Save a snapshot manually (-SnapshotName, -SnapshotDescription)

  snapshots  List saved snapshots

  baseline   Wipe all snapshots, merge current disk, save fresh Clean baseline

  preserve   Save compromised/session state for analysis (-SnapshotName as label)

  reset      Pick a snapshot to restore (interactive); -Clean skips picker

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



Setup:

  1. Copy config\quarantine-vm.example.json -> config\quarantine-vm.json

  2. Set windowsIsoPath to your Windows ISO

  3. .\quarantine-vm.ps1 create

  4. .\quarantine-vm.ps1 install

  5. Run network\guest\Configure-QuarantineGuestNetwork.ps1 in guest (Admin)

  6. .\quarantine-vm.ps1 baseline



'@

    }

}

