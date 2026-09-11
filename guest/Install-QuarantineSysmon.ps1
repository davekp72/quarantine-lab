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

function Test-SysmonFastFail {
    param([int]$Code)
    # STATUS_STACK_BUFFER_OVERRUN / STATUS_STACK_OVERFLOW_READ (Sysmon -c parser crash)
    return ($Code -eq -1073740791 -or $Code -eq -1073741571)
}

function Invoke-Sysmon {
    param([string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $SysmonExe @Arguments 2>&1
        $code = 0
        if (Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue) {
            $code = [int]$LASTEXITCODE
        }
        if ($output) { $output | ForEach-Object { Write-Host $_ } }
        return [pscustomobject]@{ ExitCode = $code; Output = ($output -join [Environment]::NewLine) }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Copy-SysmonConfigUtf8 {
    param([string]$Source, [string]$Dest)
    $raw = [System.IO.File]::ReadAllText($Source)
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) {
        $raw = $raw.Substring(1)
    }
    $raw = $raw.Trim() -replace "`r`n", "`n" -replace "`n", "`r`n"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Dest, $raw + "`r`n", $utf8)
}

if (-not (Test-Path -LiteralPath $SysmonExe)) {
    throw @"
Sysmon executable not found: $SysmonExe

On the host run .\scripts\Get-Sysmon.ps1 (downloads Sysmon from Microsoft), then
re-run guest provision / sysmon copy so Sysmon64.exe is staged at:
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
} else {
    Write-Host 'Sysmon64 service already installed — applying config only.'
}

$sysmonDir = Split-Path -Parent $ConfigFile
$applyPath = Join-Path $sysmonDir 'quarantine-lab.applied.xml'
Copy-SysmonConfigUtf8 -Source $ConfigFile -Dest $applyPath
Write-Host "Applying quarantine lab config from $applyPath ..."
$step2 = Invoke-Sysmon -Arguments @('-accepteula', '-c', $applyPath)
if ($step2.ExitCode -ne 0 -and (Test-SysmonFastFail -Code $step2.ExitCode)) {
    Write-Host 'Lab XML FAST_FAIL on -c; applying compact fallback config...'
    $fallbackSrc = Join-Path $sysmonDir 'quarantine-lab-fallback.xml'
    $fallbackPath = Join-Path $sysmonDir 'quarantine-lab-fallback.applied.xml'
    if (-not (Test-Path -LiteralPath $fallbackSrc)) {
        $embedded = @"
<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="end with">SearchIndexer.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $normalized = $embedded.Trim() -replace "`r`n", "`n" -replace "`n", "`r`n"
        [System.IO.File]::WriteAllText($fallbackSrc, $normalized + "`r`n", $utf8)
    }
    Copy-SysmonConfigUtf8 -Source $fallbackSrc -Dest $fallbackPath
    $step2 = Invoke-Sysmon -Arguments @('-accepteula', '-c', $fallbackPath)
}
if ($step2.ExitCode -ne 0) {
    $svcNow = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    $running = $svcNow -and $svcNow.Status -eq 'Running'
    if ($running) {
        Write-Host "Sysmon64 is running with its current config (apply exit $($step2.ExitCode)). Event capture continues."
        Write-Output 'SYSMON_INSTALLED'
        cmd /c exit 0
        return
    }
    throw @"
Sysmon config apply failed (exit $($step2.ExitCode)).
Try manually: Sysmon64.exe -accepteula -c `"$ConfigFile`"
"@
}

Write-Host 'Sysmon installed and configured.'
Write-Host 'Verify: Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5'
cmd /c exit 0
