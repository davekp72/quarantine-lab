#Requires -Version 5.1
<#
.SYNOPSIS
  Copy the ACL-locked ProgramData agent token to a guestcontrol-readable temp file.
  Invoked elevated via Invoke-QuarantineGuestElevated.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutFile,

    [string]$TokenPath = 'C:\ProgramData\QuarantineLab\agent-token.txt'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $TokenPath)) {
    throw "Agent token not found at $TokenPath. Run Install-QuarantineAgent.ps1 elevated in the guest first."
}

$token = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
if (-not $token) {
    throw "Agent token file is empty: $TokenPath"
}

$dir = Split-Path -Parent $OutFile
if ($dir) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
Set-Content -LiteralPath $OutFile -Value ($token + [Environment]::NewLine) -Encoding ASCII -NoNewline
