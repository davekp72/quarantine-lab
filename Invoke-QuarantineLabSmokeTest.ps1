#Requires -Version 5.1
<#
.SYNOPSIS
  Copy and run the manifest smoke test on the quarantine VM (admin + payload user).

.DESCRIPTION
  User (jkcooper) changes run via guestcontrol immediately.
  Admin HKLM/system changes need the SYSTEM task QuarantineLabPrivilegedExport — registered once
  from elevated PowerShell inside the guest (cannot be done from the host).

  First-time admin setup (once per VM / after Clean restore):
    .\Invoke-QuarantineLabSmokeTest.ps1 -Grant
  Then in the VM, elevated PowerShell as quarantine:
    & 'C:\Users\Public\Quarantine\Grant-QuarantineGuestEventLogAccess.ps1'

.EXAMPLE
  .\Invoke-QuarantineLabSmokeTest.ps1
  .\Invoke-QuarantineLabSmokeTest.ps1 -Part User
  .\Invoke-QuarantineLabSmokeTest.ps1 -Grant
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',

    [ValidateSet('Admin', 'User', 'All')]
    [string]$Part = 'All',

    [string]$Tag = (Get-Date -Format 'yyyyMMdd-HHmmss'),

    [switch]$Grant
)

$script:QuarantineLabRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $script:QuarantineLabRoot 'config\quarantine-vm.json'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vmModule = Join-Path $script:QuarantineLabRoot 'QuarantineVM.psm1'
$manifestModule = Join-Path $script:QuarantineLabRoot 'manifest\QuarantineManifest.psm1'
Import-Module $vmModule -Force
Import-Module $manifestModule -Force

$guestScript = Join-Path $script:QuarantineLabRoot 'guest\Invoke-QuarantineLabManifestSmokeTest.ps1'
$adminPrivileged = Join-Path $script:QuarantineLabRoot 'guest\Invoke-QuarantineLabSmokeAdminPrivileged.ps1'
$grantScript = Join-Path $script:QuarantineLabRoot 'guest\Grant-QuarantineGuestEventLogAccess.ps1'
$workerScript = Join-Path $script:QuarantineLabRoot 'guest\Invoke-QuarantinePrivilegedExportWorker.ps1'
$privModule = Join-Path $script:QuarantineLabRoot 'manifest\QuarantineGuestPriv.psm1'

Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
$null = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
$cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
$vmName = $cfg.vmName
$guestDir = if ($cfg.guest.copyTargetDir) { [string]$cfg.guest.copyTargetDir } else { 'C:\Users\Public\Quarantine' }
$guestRemote = Join-Path $guestDir (Split-Path -Leaf $guestScript)
$adminPrivilegedLeaf = Split-Path -Leaf $adminPrivileged
$grantRemote = Join-Path $guestDir (Split-Path -Leaf $grantScript)

function Show-GuestOutput {
    param($Output)
    if ($Output) { $Output | ForEach-Object { Write-Host $_ } }
}

function Wait-QuarantineLabSmokeGuestReady {
    param([int]$TimeoutSeconds = 180)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -eq 'starting') {
            Write-Host 'VM is starting; waiting...'
            Start-Sleep -Seconds 3
            continue
        }
        if ($state -notin @('running', 'paused')) {
            throw "VM must be running for smoke test (state: $state). Start with: .\quarantine-vm.ps1 start"
        }
        try {
            Wait-QuarantineVMGuestReady -ConfigPath $ConfigPath -TimeoutSeconds 30
            return
        } catch {
            if ($_.Exception.Message -match 'not ready|timeout') {
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }
    throw 'Guest session did not become ready for smoke test.'
}

function Install-QuarantineLabGuestGrantFiles {
    Write-Host 'Copying privilege grant scripts to guest...'
    Copy-QuarantineVMGuestFile -Path $grantScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    if (Test-Path -LiteralPath $workerScript) {
        Copy-QuarantineVMGuestFile -Path $workerScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    }
    if (Test-Path -LiteralPath $privModule) {
        Copy-QuarantineVMGuestFile -Path $privModule -ConfigPath $ConfigPath -TargetDirectory $guestDir
    }
    Copy-QuarantineVMGuestFile -Path $adminPrivileged -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
}

function Show-QuarantineLabGrantInstructions {
    Write-Host ''
    Write-Host '=== One-time elevated step (inside the VM) ==='
    Write-Host 'Open the VM desktop, right-click PowerShell -> Run as administrator (quarantine account), then:'
    Write-Host ''
    Write-Host '  Set-ExecutionPolicy Bypass -Scope Process -Force'
    Write-Host "  & '$grantRemote'"
    Write-Host ''
    Write-Host 'Expect: GRANT_OK, Registered scheduled task QuarantineLabPrivilegedExport (SYSTEM), and privileged-export-task.ok marker.'
    Write-Host 'Then re-run: .\Invoke-QuarantineLabSmokeTest.ps1'
    Write-Host ''
}

function Test-QuarantineLabPrivilegedExportTask {
    Test-QuarantineGuestPrivilegedExportTaskReady -ConfigPath $ConfigPath
}

function Invoke-AdminSmokePrivileged {
    $resultGuest = Join-Path $guestDir "smoke-admin-$Tag.result.txt"
    $resultHost = Join-Path $env:TEMP "quarantine-smoke-admin-$Tag.result.txt"

    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Copy-QuarantineVMGuestFile -Path $adminPrivileged -ConfigPath $ConfigPath -TargetDirectory $guestDir

    Write-Host "=== Smoke test: Admin (tag=$Tag, SYSTEM privileged task) ==="

    Invoke-QuarantineGuestPrivilegedExportFromHost -ConfigPath $ConfigPath `
        -GuestScriptLeaf $adminPrivilegedLeaf `
        -GuestOutFile $resultGuest `
        -TimeoutMs 300000

    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $resultHost) { Remove-Item -LiteralPath $resultHost -Force -ErrorAction SilentlyContinue }
    Copy-QuarantineVMGuestFileFrom -GuestPath $resultGuest -HostPath $resultHost -ConfigPath $ConfigPath -TimeoutMs 60000
    if (Test-Path -LiteralPath $resultHost) {
        Get-Content -LiteralPath $resultHost | ForEach-Object { Write-Host $_ }
    } else {
        throw "Admin smoke result missing on guest: $resultGuest"
    }
}

function Invoke-UserSmoke {
    $payloadCred = Resolve-QuarantineVMPayloadCredential -ConfigPath $ConfigPath
    $payloadDir = if ($cfg.payload.copyTargetDir) { [string]$cfg.payload.copyTargetDir } else { $guestDir }
    $guestRemotePayload = Join-Path $payloadDir (Split-Path -Leaf $guestScript)
    $resultGuest = Join-Path $payloadDir "smoke-user-$Tag.result.txt"

    Write-Host "=== Smoke test: User (tag=$Tag, payload account) ==="

    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $payloadDir `
        -Username $payloadCred.Username -Password $payloadCred.Password -Domain $payloadCred.Domain

    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 120000 `
        -Username $payloadCred.Username -Password $payloadCred.Password -Domain $payloadCred.Domain `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestRemotePayload,
            '-Part', 'User', '-Tag', $Tag, '-ResultFile', $resultGuest
        )
    Show-GuestOutput $output
}

Wait-QuarantineLabSmokeGuestReady

if ($Grant) {
    Install-QuarantineLabGuestGrantFiles
    Show-QuarantineLabGrantInstructions
    return
}

$taskReady = Test-QuarantineLabPrivilegedExportTask
$adminRan = $false
$adminSkipped = $false

if ($Part -in @('Admin', 'All')) {
    if (-not $taskReady) {
        Install-QuarantineLabGuestGrantFiles
        if ($Part -eq 'Admin') {
            Show-QuarantineLabGrantInstructions
            throw "SYSTEM task 'QuarantineLabPrivilegedExport' is not registered. Complete the elevated guest step above, then re-run."
        }
        Write-Warning 'Admin smoke skipped - SYSTEM privileged task not registered yet.'
        Show-QuarantineLabGrantInstructions
        $adminSkipped = $true
    } else {
        Invoke-AdminSmokePrivileged
        $adminRan = $true
    }
}

if ($Part -in @('User', 'All')) {
    Invoke-UserSmoke
}

Write-Host ''
if ($adminSkipped) {
    Write-Host 'User smoke completed. Admin smoke pending - run the elevated grant in the VM, then:'
    Write-Host "  .\Invoke-QuarantineLabSmokeTest.ps1 -Part Admin -Tag $Tag"
} elseif ($adminRan -or $Part -eq 'User') {
    Write-Host 'Done. Preserve evidence, then diff:'
    Write-Host "  .\quarantine-vm.ps1 preserve -SnapshotName smoke-$Tag"
    Write-Host "  .\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-smoke-$Tag -Refresh"
}
