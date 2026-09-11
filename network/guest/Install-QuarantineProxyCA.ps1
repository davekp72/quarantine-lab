#Requires -Version 5.1
<#
.SYNOPSIS
  Install the Linux gateway mitmproxy CA into the guest Trusted Root store.
.DESCRIPTION
  Run inside the quarantine VM as Administrator.

  FakeNet and permissive MITM both sign TLS with the gateway's mitmproxy CA
  (/root/.mitmproxy on Quarantine-Gateway). Do not install the host
  (10.0.2.2) CA unless you are on the legacy host-nat path.

  In FakeNet mode the CA is served over HTTP:
    http://10.66.0.1/mitmproxy-ca-cert.cer
#>
[CmdletBinding()]
param(
    [string]$ProxyHost = '',
    [int]$ProxyPort = 8080,
    [int]$PacPort = 8080,
    [string]$CaPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CaFile {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    if ((Get-Item -LiteralPath $Path).Length -lt 32) { return $null }
    try {
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
    } catch {
        return $null
    }
}

function Save-UrlToFile {
    param(
        [string]$Url,
        [string]$Dest
    )
    Write-Host "Downloading CA: $Url"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & curl.exe --noproxy '*' --http1.1 -fsSL --max-time 15 $Url -o $Dest
        $code = 0
        if (Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue) {
            $code = [int]$LASTEXITCODE
        }
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        # FakeNet/MITM on :80 often returns empty (curl 52). Not a failure if :8080 or a local .cer works.
        Write-Host "  skip $Url (curl $code)"
        return $false
    }
    return $true
}

if (-not (Test-Administrator)) {
    throw 'Run this script as Administrator inside the guest VM.'
}

$dest = $CaPath
if (-not $dest) {
    $dest = Join-Path $env:TEMP 'mitmproxy-ca-cert.cer'
}

$urls = New-Object System.Collections.Generic.List[string]
$urls.Add('http://10.66.0.1:8080/mitmproxy-ca-cert.cer')
$urls.Add('http://10.66.0.1:8081/mitmproxy-ca-cert.cer')
$urls.Add('http://10.66.0.1/mitmproxy-ca-cert.cer')
if ($ProxyHost) {
    $urls.Add("http://${ProxyHost}:${PacPort}/mitmproxy-ca-cert.cer")
    $urls.Add("http://${ProxyHost}:${ProxyPort}/mitmproxy-ca-cert.cer")
}
# Legacy host-nat last — wrong CA for gateway FakeNet/MITM.
$urls.Add('http://10.0.2.2:8081/mitmproxy-ca-cert.cer')
$urls.Add('http://10.0.2.2:8080/mitmproxy-ca-cert.cer')

$cert = $null
$source = $null

$localCandidates = @(
    $CaPath,
    (Join-Path $PSScriptRoot 'mitmproxy-ca-cert.cer'),
    'C:\Users\Public\Quarantine\mitmproxy-ca-cert.cer'
)

foreach ($p in $localCandidates) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $parsed = Test-CaFile -Path $p
    if ($parsed) {
        if ($p -ne $dest) {
            Copy-Item -LiteralPath $p -Destination $dest -Force
        }
        $cert = $parsed
        $source = $p
        break
    }
}

# Explicit MITM :8080, then FakeNet :80. 10.0.2.2 is the host proxy CA — wrong for gateway.
if (-not $cert) {
    foreach ($url in $urls) {
        $tmp = Join-Path $env:TEMP ('qca-{0}.cer' -f [Guid]::NewGuid().ToString('N'))
        try {
            if (-not (Save-UrlToFile -Url $url -Dest $tmp)) { continue }
            $parsed = Test-CaFile -Path $tmp
            if (-not $parsed) {
                Write-Warning "Not a certificate: $url"
                continue
            }
            Copy-Item -LiteralPath $tmp -Destination $dest -Force
            $cert = $parsed
            $source = $url
            break
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
}

if (-not $cert) {
    throw "Could not download the gateway mitmproxy CA. In FakeNet mode use http://10.66.0.1/mitmproxy-ca-cert.cer after switching the gateway to fakenet. In permissive mode use http://10.66.0.1:8080/mitmproxy-ca-cert.cer"
}

Write-Host ("Installing CA: {0}" -f $cert.Subject)
Write-Host ("  Issuer:     {0}" -f $cert.Issuer)
Write-Host ("  Thumbprint: {0}" -f $cert.Thumbprint)
Write-Host ("  Valid:      {0:u} .. {1:u}" -f $cert.NotBefore.ToUniversalTime(), $cert.NotAfter.ToUniversalTime())
Write-Host ("  Source:     {0}" -f $source)
if ($cert.NotAfter -lt [datetime]::UtcNow) {
    Write-Warning 'This CA is already expired. Re-create it (gateway permissive MITM once) and re-run this installer.'
}

Import-Certificate -FilePath $dest -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $dest -CertStoreLocation Cert:\CurrentUser\Root | Out-Null

Write-Host 'Gateway mitmproxy CA installed in Trusted Root Certification Authorities.'
Write-Host 'Restart the browser (or the VM) and HTTPS should work.'
Write-Host 'Firefox uses its own store — import this file there if you use Firefox.'
Write-Host "  $dest"
