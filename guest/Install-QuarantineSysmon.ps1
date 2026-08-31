#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install Sysmon and apply the quarantine lab config.
  Uses two-step install (service first, config second) to avoid Sysmon -i config crash on clean systems.
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = 'C:\Users\Public\Quarantine\sysmon\quarantine-lab.xml',
    [string]$SysmonExe = 'C:\Users\Public\Quarantine\sysmon\Sysmon64.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Sysmon {
    param([string[]]$Arguments)
    $output = & $SysmonExe @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($output) { $output | ForEach-Object { Write-Host $_ } }
    return [pscustomobject]@{ ExitCode = $code; Output = ($output -join [Environment]::NewLine) }
}

if (-not (Test-Path -LiteralPath $SysmonExe)) {
    throw @"
Sysmon executable not found: $SysmonExe

Copy Sysmon64.exe from Sysinternals to:
  C:\Users\Public\Quarantine\sysmon\Sysmon64.exe
"@
}

if (-not (Test-Path -LiteralPath $ConfigFile)) {
    throw "Sysmon config not found: $ConfigFile"
}

$service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Host 'Step 1/2: Installing Sysmon service (default config)...'
    $step1 = Invoke-Sysmon -Arguments @('-accepteula', '-i')
    if ($step1.ExitCode -ne 0) {
        throw "Sysmon service install failed (exit $($step1.ExitCode)):`n$($step1.Output)"
    }
    Start-Sleep -Seconds 2
    $service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $service) {
        throw 'Sysmon service not found after install.'
    }
}

Write-Host 'Step 2/2: Applying quarantine lab config...'
$step2 = Invoke-Sysmon -Arguments @('-c', $ConfigFile)
if ($step2.ExitCode -ne 0) {
    throw @"
Sysmon config apply failed (exit $($step2.ExitCode)).
Try manually: Sysmon64.exe -c `"$ConfigFile`"

If it still fails, test the minimal config from the host:
  .\quarantine-vm.ps1 sysmon copy
"@
}

Write-Host 'Sysmon installed and configured.'
Write-Host 'Verify: Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5'
