#Requires -Version 5.1
<#
.SYNOPSIS
  Confirm permissive HTTPS is MITM'd (issuer mitmproxy), including curl without WinINET.
#>
[CmdletBinding()]
param(
    [string]$Url = 'https://example.com/',
    [string]$Proxy = 'http://10.66.0.1:8080'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-KV([string]$k, [string]$v) { Write-Output ("{0}={1}" -f $k, $v) }

function Get-PeerIssuer([string]$TargetHost) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.ReceiveTimeout = 12000
    $tcp.SendTimeout = 12000
    $tcp.Connect($TargetHost, 443)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
    try {
        $ssl.AuthenticateAsClient($TargetHost)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        return @{ Subject = $cert.Subject; Issuer = $cert.Issuer }
    } finally {
        $ssl.Close()
        $tcp.Close()
    }
}

Write-KV 'utc' ([DateTime]::UtcNow.ToString('o'))

Write-Output '--- curl --noproxy * (direct :443; must hit transparent MITM, including HTTP/3 fallback) ---'
$direct = & curl.exe --noproxy '*' -sS -o NUL -w 'http=%{http_code} ssl=%{ssl_verify_result} ver=%{http_version}\n' --max-time 25 $Url 2>&1 | Out-String
Write-Output $direct.Trim()
$v = & curl.exe --noproxy '*' -v --max-time 20 -o NUL $Url 2>&1 | Out-String
$issuerLine = ($v -split "`n" | Where-Object { $_ -match 'issuer:|subject:|HTTP/' } | Select-Object -First 8) -join ' | '
Write-KV 'direct-verbose' $issuerLine
$failTail = ($v -split "`n" | Select-Object -Last 8) -join ' | '
Write-KV 'direct-tail' $failTail

Write-Output '--- curl -x explicit proxy (browser path) ---'
$via = & curl.exe -x $Proxy --http1.1 -sS -o NUL -w 'http=%{http_code} ssl=%{ssl_verify_result}\n' --max-time 20 $Url 2>&1 | Out-String
Write-Output $via.Trim()

Write-Output '--- HTTP via explicit proxy (PowerShell curl / IWR path) ---'
$httpEx = & curl.exe -x $Proxy --http1.1 -sS -o NUL -w 'http=%{http_code}\n' --max-time 20 'http://example.com/' 2>&1 | Out-String
Write-Output ('example.com ' + $httpEx.Trim())
$httpNs = & curl.exe -x $Proxy --http1.1 -sS -o NUL -w 'http=%{http_code}\n' --max-time 20 'http://neverssl.com/online/' 2>&1 | Out-String
Write-Output ('neverssl ' + $httpNs.Trim())
$httpDirect = & curl.exe --noproxy '*' --http1.1 -sS -o NUL -w 'http=%{http_code}\n' --max-time 20 'http://example.com/' 2>&1 | Out-String
Write-Output ('example.com-noproxy ' + $httpDirect.Trim())

$iwrExampleOk = $false
try {
    $iwr = Invoke-WebRequest -Uri 'http://example.com/' -UseBasicParsing -TimeoutSec 20
    Write-KV 'iwr-example' ([string][int]$iwr.StatusCode)
    if ([int]$iwr.StatusCode -ge 200 -and [int]$iwr.StatusCode -lt 400) { $iwrExampleOk = $true }
} catch {
    Write-KV 'iwr-example' ('fail ' + $_.Exception.Message)
}
try {
    $iwrNs = Invoke-WebRequest -Uri 'http://neverssl.com/online/' -UseBasicParsing -TimeoutSec 20
    Write-KV 'iwr-neverssl' ([string][int]$iwrNs.StatusCode)
} catch {
    Write-KV 'iwr-neverssl' ('fail ' + $_.Exception.Message)
}

$peer = $null
try {
    $peer = Get-PeerIssuer 'example.com'
    Write-KV 'direct-tcp-subject' $peer.Subject
    Write-KV 'direct-tcp-issuer' $peer.Issuer
} catch {
    Write-KV 'direct-tcp' ('fail ' + $_.Exception.Message)
}

$okHttp = ($direct -match 'http=200')
$okVia = ($via -match 'http=200')
$okClear = (($httpEx -match 'http=(200|301|302)') -or ($httpDirect -match 'http=(200|301|302)'))
$okMitm = $false
if ($peer -and $peer.Issuer -match 'mitmproxy') { $okMitm = $true }
if ($issuerLine -match 'mitmproxy') { $okMitm = $true }

if ($okHttp -and $okVia -and $okMitm -and $okClear -and $iwrExampleOk) {
    Write-KV 'result' 'permissive-transparent-ok'
    exit 0
}
Write-KV 'result' 'fail'
exit 1
