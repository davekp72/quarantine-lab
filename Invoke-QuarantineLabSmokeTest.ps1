#Requires -Version 5.1
<#
.SYNOPSIS
  Copy and run the manifest smoke test on the quarantine VM (admin + payload user).

.EXAMPLE
  .\Invoke-QuarantineLabSmokeTest.ps1
  .\Invoke-QuarantineLabSmokeTest.ps1 -Part Admin
  .\Invoke-QuarantineLabSmokeTest.ps1 -Part User -Tag test1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json'),

    [ValidateSet('Admin', 'User', 'All')]
    [string]$Part = 'All',

    [string]$Tag = (Get-Date -Format 'yyyyMMdd-HHmmss')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vmModule = Join-Path $PSScriptRoot 'QuarantineVM.psm1'
Import-Module $vmModule -Force

$guestScript = Join-Path $PSScriptRoot 'guest\Invoke-QuarantineLabManifestSmokeTest.ps1'
if (-not (Test-Path -LiteralPath $guestScript)) {
    throw "Guest script not found: $guestScript"
}

$cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
$guestDir = if ($cfg.guest.copyTargetDir) { [string]$cfg.guest.copyTargetDir } else { 'C:\Users\Public\Quarantine' }
$guestRemote = Join-Path $guestDir (Split-Path -Leaf $guestScript)
$invoke = "& '$guestRemote' -Part {0} -Tag '$Tag'"

function Invoke-SmokeOnGuest {
    param(
        [Parameter(Mandatory)][string]$WhichPart,
        [Parameter(Mandatory)][scriptblock]$Runner
    )

    Write-Host "=== Smoke test: $WhichPart (tag=$Tag) ==="
    $output = & $Runner
    if ($output) { $output | ForEach-Object { Write-Host $_ } }
}

if ($Part -in @('Admin', 'All')) {
    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    Invoke-SmokeOnGuest -WhichPart Admin -Runner {
        Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath `
            -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Command @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ($invoke -f 'Admin'))
    }
}

if ($Part -in @('User', 'All')) {
    $payloadCred = Resolve-QuarantineVMPayloadCredential -ConfigPath $ConfigPath
    $payloadDir = if ($cfg.payload.copyTargetDir) { [string]$cfg.payload.copyTargetDir } else { $guestDir }
    $guestRemotePayload = Join-Path $payloadDir (Split-Path -Leaf $guestScript)
    $invokePayload = "& '$guestRemotePayload' -Part User -Tag '$Tag'"

    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $payloadDir `
        -Username $payloadCred.Username -Password $payloadCred.Password -Domain $payloadCred.Domain

    Invoke-SmokeOnGuest -WhichPart User -Runner {
        Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath `
            -Username $payloadCred.Username -Password $payloadCred.Password -Domain $payloadCred.Domain `
            -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
            -Command @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $invokePayload)
    }
}

Write-Host ''
Write-Host 'Done. Preserve evidence, then diff:'
Write-Host "  .\quarantine-vm.ps1 preserve -SnapshotName smoke-$Tag"
Write-Host "  .\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot smoke-$Tag -Refresh"
