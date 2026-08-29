#Requires -Version 5.1
<#
.SYNOPSIS
  Start tshark packet capture for quarantine VM NAT traffic.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'config\quarantine-vm.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $ProjectRoot 'QuarantineNetwork.psm1') -Force

Start-QuarantineCapture -ConfigPath $ConfigPath
