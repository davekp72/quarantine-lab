#Requires -Version 5.1
<#
.SYNOPSIS
  Start mitmproxy and PAC file server for quarantine VM networking.
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

Start-QuarantineProxy -ConfigPath $ConfigPath
