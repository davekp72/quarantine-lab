#Requires -Version 5.1
<#
.SYNOPSIS
  Elevated first-logon bootstrap for the quarantine Windows guest.

.DESCRIPTION
  Invoked by autounattend FirstLogonCommands from the unattend floppy (A:).
  Copies staged Quarantine\* helpers into C:\Users\Public\Quarantine and runs
  Invoke-QuarantineGuestProvision.ps1 when present (skips missing agent/Sysmon
  binaries until the host stages them after Guest Additions).

  Does NOT register a persistent SYSTEM privileged-export scheduled task.
  Admin membership is enforced by SetupComplete.cmd + FirstLogon net localgroup
  (Win11 often ignores LocalAccounts/Group in unattend).
#>
[CmdletBinding()]
param(
    [string]$MediaRoot = '',
    [string]$PublicDir = 'C:\Users\Public\Quarantine',
    [string]$LabAdmin = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-FirstLog {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    try {
        $logDir = $PublicDir
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -LiteralPath (Join-Path $logDir 'firstlogon.log') -Value $line -Encoding UTF8
    } catch { }
}

function Resolve-MediaRoot {
    param([string]$Hint)
    if ($Hint -and (Test-Path -LiteralPath $Hint)) { return $Hint }
    foreach ($letter in @('D', 'E', 'F', 'A', 'B')) {
        $root = "${letter}:\"
        $probe = Join-Path $root 'Invoke-QuarantineFirstLogon.ps1'
        $probeQ = Join-Path $root 'Quarantine\Invoke-QuarantineGuestProvision.ps1'
        $probeXml = Join-Path $root 'autounattend.xml'
        if ((Test-Path -LiteralPath $probe) -or (Test-Path -LiteralPath $probeQ) -or (Test-Path -LiteralPath $probeXml)) {
            return $root.TrimEnd('\')
        }
    }
    return ''
}

Write-FirstLog 'Quarantine FirstLogon starting'

# Prefer config-derived admin name from staged hints when present.
if (-not $LabAdmin) {
    $hintsPath = Join-Path $PublicDir 'guest-provision.json'
    if (Test-Path -LiteralPath $hintsPath) {
        try {
            $hints = Get-Content -LiteralPath $hintsPath -Raw | ConvertFrom-Json
            if ($hints.labAdmin) { $LabAdmin = [string]$hints.labAdmin }
        } catch { }
    }
}
if (-not $LabAdmin) { $LabAdmin = $env:USERNAME }

try {
    & net.exe localgroup Administrators $LabAdmin /add 2>&1 | ForEach-Object { Write-FirstLog $_ }
} catch {
    Write-FirstLog ("net localgroup Administrators failed: " + $_.Exception.Message)
}

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
Write-FirstLog ("Current user={0} isAdmin={1} labAdmin={2}" -f $env:USERNAME, $isAdmin, $LabAdmin)

$media = Resolve-MediaRoot -Hint $MediaRoot
if (-not $media) {
    Write-FirstLog 'WARN: unattend media not found (expected floppy A:). Creating Public dir only.'
} else {
    Write-FirstLog "Media root: $media"
}

New-Item -ItemType Directory -Path $PublicDir -Force | Out-Null

$srcQuarantine = if ($media) { Join-Path $media 'Quarantine' } else { '' }
if ($srcQuarantine -and (Test-Path -LiteralPath $srcQuarantine)) {
    Write-FirstLog "Copying $srcQuarantine -> $PublicDir"
    Copy-Item -Path (Join-Path $srcQuarantine '*') -Destination $PublicDir -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-FirstLog 'No Quarantine\ folder on media (scripts may be staged later by host).'
}

# Optional: copy firstlogon script itself for later re-runs.
if ($media) {
    $self = Join-Path $media 'Invoke-QuarantineFirstLogon.ps1'
    if (Test-Path -LiteralPath $self) {
        Copy-Item -LiteralPath $self -Destination (Join-Path $PublicDir 'Invoke-QuarantineFirstLogon.ps1') -Force -ErrorAction SilentlyContinue
    }
}

# Desktop shortcut helper for post-GA finish (agent/Sysmon after host stage).
try {
    $desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if (-not $desktop) { $desktop = 'C:\Users\Public\Desktop' }
    $cmd = Join-Path $PublicDir 'Finish-QuarantineProvision.cmd'
    if (Test-Path -LiteralPath $cmd) {
        Copy-Item -LiteralPath $cmd -Destination (Join-Path $desktop 'Finish-QuarantineProvision.cmd') -Force
        Write-FirstLog "Placed Finish-QuarantineProvision.cmd on Public Desktop"
    }
} catch {
    Write-FirstLog ("Desktop helper skipped: " + $_.Exception.Message)
}

# Optional: BypassNRO is also set here; specialize no longer runs fragile scripts.
try {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Name 'BypassNRO' -PropertyType DWord -Value 1 -Force | Out-Null
} catch { }

$prov = Join-Path $PublicDir 'Invoke-QuarantineGuestProvision.ps1'
if (Test-Path -LiteralPath $prov) {
    Write-FirstLog 'Running Invoke-QuarantineGuestProvision.ps1 (elevated FirstLogon)'
    try {
        Set-ExecutionPolicy -Scope Process Bypass -Force
        & $prov
        Write-FirstLog 'Guest provision finished'
    } catch {
        Write-FirstLog ("Guest provision error: " + $_.Exception.Message)
    }
} else {
    Write-FirstLog 'Invoke-QuarantineGuestProvision.ps1 not present yet — run host guest provision after Guest Additions, then Finish-QuarantineProvision.cmd'
}

Set-Content -LiteralPath (Join-Path $PublicDir 'firstlogon.ok') -Value ((Get-Date).ToString('o') + [Environment]::NewLine) -Encoding ASCII
Write-FirstLog 'Quarantine FirstLogon done'
