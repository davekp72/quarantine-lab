#Requires -Version 5.1
<#
.SYNOPSIS
  Open the official Windows 11 ISO download page and verify the local ISO file.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\quarantine-vm.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $Root 'QuarantineVM.psm1') -Force

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$isoDir = Join-Path $Root 'isos'

if (-not (Test-Path -LiteralPath $isoDir)) {
    New-Item -ItemType Directory -Path $isoDir -Force | Out-Null
}

try {
    $isoPath = Resolve-WindowsIsoPath `
        -ConfiguredPath $config.windowsIsoPath `
        -GuestOsType $config.guestOsType `
        -ProjectRoot $Root
    $gb = [math]::Round((Get-Item -LiteralPath $isoPath).Length / 1GB, 2)
    Write-Host "ISO already present ($gb GB): $isoPath"
    exit 0
} catch {
    Write-Verbose $_.Exception.Message
}

Write-Host @"
Windows 11 ISO required in:
  $isoDir

Any Windows *.iso filename is accepted (e.g. Win11_22H2_EnglishInternational_x64_v2.iso).

Opening Microsoft download page...
  1. Download 'Windows 11 (multi-edition ISO)'
  2. Choose English, x64
  3. Save the file to the isos\ folder above
  4. Re-run: .\quarantine-vm.ps1 create

"@

Start-Process 'https://www.microsoft.com/software-download/windows11'
