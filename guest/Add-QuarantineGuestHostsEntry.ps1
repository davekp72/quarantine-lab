#Requires -Version 5.1
<#
.SYNOPSIS
  Add a harmless line to the guest hosts file (requires full admin token in guest).
#>
[CmdletBinding()]
param(
    [string]$IpAddress = '127.0.0.1',
    [string]$Hostname = 'smoke.lab.test',
    [string]$Marker = '# quarantine-lab-smoke'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
$line = "$IpAddress $Hostname $Marker".Trim()

if (-not (Test-Path -LiteralPath $hostsPath)) {
    throw "Hosts file not found: $hostsPath"
}

$existing = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
if ($existing | Where-Object { $_ -match [regex]::Escape($Hostname) }) {
    Write-Output "HOSTS_ALREADY_SET $line"
    exit 0
}

Add-Content -LiteralPath $hostsPath -Value $line -Encoding ASCII
Write-Output "HOSTS_OK $line"
