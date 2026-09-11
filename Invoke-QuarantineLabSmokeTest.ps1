#Requires -Version 5.1
<#
.SYNOPSIS
  Copy and run the manifest smoke test on the quarantine VM (admin + payload user).

.DESCRIPTION
  User (jkcooper) changes run via guestcontrol immediately.
  Admin Sysmon/USN checks run via guestcontrol as the lab admin after one-time grant
  (Event Log Readers + Backup Operators). The legacy SYSTEM polling task is not used.

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
$grantScript = Join-Path $script:QuarantineLabRoot 'guest\Grant-QuarantineGuestEventLogAccess.ps1'
$privModule = Join-Path $script:QuarantineLabRoot 'manifest\QuarantineGuestPriv.psm1'

Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
$null = Get-QuarantineVMManifestSettings -ConfigPath $ConfigPath
$cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
$vmName = $cfg.vmName
$guestDir = if ($cfg.guest.copyTargetDir) { [string]$cfg.guest.copyTargetDir } else { 'C:\Users\Public\Quarantine' }
$guestRemote = Join-Path $guestDir (Split-Path -Leaf $guestScript)
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
            $null = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 15000 `
                -Exe 'C:\Windows\System32\cmd.exe' -Command @('/c', 'echo', 'ready')
            return
        } catch {
            Write-Host 'Guest control not ready yet...'
            Start-Sleep -Seconds 3
        }
    }
    throw 'Guest control did not become ready within timeout.'
}

function Install-QuarantineLabGuestGrantFiles {
    Copy-QuarantineVMGuestFile -Path $grantScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    if (Test-Path -LiteralPath $privModule) {
        Copy-QuarantineVMGuestFile -Path $privModule -ConfigPath $ConfigPath -TargetDirectory $guestDir
    }
    Write-Host "Copied grant script to $grantRemote"
}

function Show-QuarantineLabGrantInstructions {
    Write-Host ''
    Write-Host 'Open the VM desktop, right-click PowerShell -> Run as administrator (quarantine account), then:'
    Write-Host ''
    Write-Host '  Set-ExecutionPolicy Bypass -Scope Process -Force'
    Write-Host "  & '$grantRemote'"
    Write-Host ''
    Write-Host 'Expect: GRANT_OK (Event Log Readers / Backup Operators). Legacy SYSTEM export task is removed if present.'
    Write-Host 'Then re-run: .\Invoke-QuarantineLabSmokeTest.ps1'
    Write-Host ''
}

function Invoke-AdminSmoke {
    $resultGuest = Join-Path $guestDir "smoke-admin-$Tag.result.txt"
    $resultHost = Join-Path $env:TEMP "quarantine-smoke-admin-$Tag.result.txt"

    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    if (Test-Path -LiteralPath $privModule) {
        Copy-QuarantineVMGuestFile -Path $privModule -ConfigPath $ConfigPath -TargetDirectory $guestDir
    }

    Write-Host "=== Smoke test: Admin (tag=$Tag, lab admin via guestcontrol) ==="

    $output = Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs 300000 `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestRemote,
            '-Part', 'Admin', '-Tag', $Tag, '-ResultFile', $resultGuest
        )
    Show-GuestOutput $output

    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $resultHost) { Remove-Item -LiteralPath $resultHost -Force -ErrorAction SilentlyContinue }
    try {
        Copy-QuarantineVMGuestFileFrom -GuestPath $resultGuest -HostPath $resultHost -ConfigPath $ConfigPath -TimeoutMs 60000
    } catch {
        Write-Warning "Could not copy admin result: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $resultHost) {
        Get-Content -LiteralPath $resultHost | ForEach-Object { Write-Host $_ }
    } else {
        throw "Admin smoke result missing on guest: $resultGuest (run -Grant and elevated grant in guest if USN/Sysmon denied)"
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

$adminRan = $false

if ($Part -in @('Admin', 'All')) {
    try {
        Invoke-AdminSmoke
        $adminRan = $true
    } catch {
        Install-QuarantineLabGuestGrantFiles
        Show-QuarantineLabGrantInstructions
        if ($Part -eq 'Admin') { throw }
        Write-Warning "Admin smoke failed: $($_.Exception.Message)"
    }
}

if ($Part -in @('User', 'All')) {
    Invoke-UserSmoke
}

Write-Host ''
if ($adminRan -or $Part -eq 'User') {
    Write-Host 'Done. Preserve evidence, then diff:'
    Write-Host "  .\quarantine-vm.ps1 preserve -SnapshotName smoke-$Tag"
    Write-Host "  .\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-smoke-$Tag -Refresh"
}
