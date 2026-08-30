#Requires -Version 5.1
<#
.SYNOPSIS
  Install the host mitmproxy CA into the guest Trusted Root store.
.DESCRIPTION
  Run inside the quarantine VM as Administrator. Fixes HTTPS / SSL errors
  caused by the host proxy intercepting TLS.
#>
[CmdletBinding()]
param(
    [string]$ProxyHost = '10.0.2.2',
    [int]$ProxyPort = 8080,
    [int]$PacPort = 8081,
    [string]$CaPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw 'Run this script as Administrator inside the guest VM.'
}

if (-not $CaPath) {
    $CaPath = Join-Path $env:TEMP 'mitmproxy-ca-cert.cer'
}

$urls = @(
    "http://${ProxyHost}:${PacPort}/mitmproxy-ca-cert.cer",
    "http://${ProxyHost}:${ProxyPort}/mitmproxy-ca-cert.cer"
)

$downloaded = $false
foreach ($url in $urls) {
    Write-Host "Downloading CA: $url"
    try {
        & curl.exe --noproxy '*' -fsSL $url -o $CaPath
        if ((Test-Path -LiteralPath $CaPath) -and ((Get-Item -LiteralPath $CaPath).Length -ge 32)) {
            $downloaded = $true
            break
        }
    } catch {
        Write-Warning "Download failed: $url"
    }
}

if (-not $downloaded) {
    throw "Could not download mitmproxy CA. On the host run: .\quarantine-vm.ps1 proxy export-ca"
}

Import-Certificate -FilePath $CaPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $CaPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null

Write-Host 'mitmproxy CA installed in Trusted Root Certification Authorities.'
Write-Host 'Restart the browser (or the VM) and HTTPS should work.'
Write-Host 'Firefox uses its own store — import this file there if you use Firefox.'
Write-Host "  $CaPath"
