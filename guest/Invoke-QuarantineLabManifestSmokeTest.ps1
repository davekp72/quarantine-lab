#Requires -Version 5.1
<#
.SYNOPSIS
  Harmless registry + file changes for manifest diff testing (quarantine lab only).

.DESCRIPTION
  Two parts:
    Admin  — HKLM registry + files under Windows/ProgramData (requires elevation)
    User   — HKCU registry + files under the current profile (standard user)

  Run on the VM after a baseline snapshot/mark, before preserve.

.EXAMPLE
  # On the VM (elevated PowerShell):
  .\Invoke-QuarantineLabManifestSmokeTest.ps1 -Part Admin

  # On the VM (payload user PowerShell):
  .\Invoke-QuarantineLabManifestSmokeTest.ps1 -Part User

.EXAMPLE
  # From the host (recommended):
  .\Invoke-QuarantineLabSmokeTest.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Admin', 'User', 'All')]
    [string]$Part = 'All',

    [string]$Tag = (Get-Date -Format 'yyyyMMdd-HHmmss'),

    [string]$ResultFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ResultFile = $ResultFile

$LabKeyName = 'QuarantineLab'
$TestKeyName = 'ManifestSmokeTest'

function Write-SmokeResult {
    param([string]$Message)
    $line = "SMOKE_OK $Message"
    Write-Output $line
    if (-not [string]::IsNullOrWhiteSpace($script:ResultFile)) {
        $dir = Split-Path -Parent $script:ResultFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Set-Content -LiteralPath $script:ResultFile -Value $line -Encoding UTF8
    }
}

function Set-SmokeRegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('String', 'DWord', 'ExpandString')]
        [string]$Type = 'String'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Write-SmokeFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Body
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Body -Encoding UTF8
}

function Invoke-QuarantineLabSmokeAdmin {
    $isAdmin = $false
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }

    if (-not $isAdmin) {
        throw 'Admin part requires elevation. Run as Administrator or use: .\quarantine-vm.ps1 guest ps ... -Part Admin'
    }

    $stamp = (Get-Date).ToUniversalTime().ToString('o')
    $hklmKey = "HKLM:\Software\$LabKeyName\$TestKeyName"

    Set-SmokeRegValue -Path $hklmKey -Name 'Marker' -Value "admin-smoke-$Tag"
    Set-SmokeRegValue -Path $hklmKey -Name 'RecordedAtUtc' -Value $stamp
    Set-SmokeRegValue -Path $hklmKey -Name 'FakeServiceFlag' -Value 1 -Type DWord
    Set-SmokeRegValue -Path "$hklmKey\RunReference" -Name 'ImagePath' -Value 'C:\Windows\Temp\QuarantineLab-smoke-system.dat'
    Set-SmokeRegValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'QuarantineLabSmokeOnce' -Value 'echo lab-smoke-runonce'

    $systemTempFile = 'C:\Windows\Temp\QuarantineLab-smoke-system.dat'
    $programDataFile = 'C:\ProgramData\QuarantineLab\cache\smoke-svc-payload.bin'
    $systemBody = @"
Quarantine lab manifest smoke test (harmless).
Part=Admin Tag=$Tag User=$env:USERNAME
Looks like a staged system artifact for diff testing only.
"@
    Write-SmokeFile -Path $systemTempFile -Body $systemBody
    Write-SmokeFile -Path $programDataFile -Body "ProgramData marker $Tag`n$systemBody"

    Write-SmokeResult "Admin HKLM=$hklmKey files=$systemTempFile;$programDataFile"
}

function Invoke-QuarantineLabSmokeUser {
    $stamp = (Get-Date).ToUniversalTime().ToString('o')
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $hkcuKey = "HKCU:\Software\$LabKeyName\$TestKeyName"

    Set-SmokeRegValue -Path $hkcuKey -Name 'Marker' -Value "user-smoke-$Tag"
    Set-SmokeRegValue -Path $hkcuKey -Name 'RecordedAtUtc' -Value $stamp
    Set-SmokeRegValue -Path $hkcuKey -Name 'SessionId' -Value $sid
    Set-SmokeRegValue -Path "$hkcuKey\PersistenceRef" -Name 'Command' -Value 'powershell -NoProfile -Command Write-Output lab-smoke'
    Set-SmokeRegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'QuarantineLabSmokeUser' -Value 'notepad.exe'

    $localTemp = Join-Path $env:LOCALAPPDATA 'Temp\QuarantineLab-smoke-local.tmp'
    $documentsDrop = Join-Path $env:USERPROFILE 'Documents\QuarantineLab-fake-dropper.ps1'
    $appDataFile = Join-Path $env:APPDATA "Microsoft\Windows\QuarantineLab-staged.exe.txt"
    $userBody = @"
Quarantine lab manifest smoke test (harmless).
Part=User Tag=$Tag User=$env:USERNAME SID=$sid
Fake dropper filename for USN/Sysmon diff testing — not executable code.
"@

    Write-SmokeFile -Path $localTemp -Body $userBody
    Write-SmokeFile -Path $documentsDrop -Body "# QuarantineLab smoke $Tag`n# Harmless placeholder only.`n$userBody"
    Write-SmokeFile -Path $appDataFile -Body $userBody

    Write-SmokeResult "User HKCU=$hkcuKey files=$localTemp;$documentsDrop;$appDataFile"
}

switch ($Part) {
    'Admin' { Invoke-QuarantineLabSmokeAdmin }
    'User'  { Invoke-QuarantineLabSmokeUser }
    'All' {
        Invoke-QuarantineLabSmokeAdmin
        Invoke-QuarantineLabSmokeUser
    }
}
