#Requires -Version 5.1
<#
.SYNOPSIS
  Stop mitmproxy and PAC server for quarantine VM networking.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $ProjectRoot 'QuarantineNetwork.psm1') -Force

Stop-QuarantineProxy
