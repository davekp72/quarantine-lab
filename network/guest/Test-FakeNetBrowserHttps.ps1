#Requires -Version 5.1
<#
.SYNOPSIS
  Guest-side check of FakeNet HTTPS via the PAC/CONNECT proxy (what Edge/Chrome do).
#>
[CmdletBinding()]
param(
    [string]$ProxyHost = '10.66.0.1',
    [int]$ProxyPort = 8080,
    [string]$TargetHost = 'bbc.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-KV([string]$k, [string]$v) {
    Write-Output ("{0}={1}" -f $k, $v)
}

Write-KV 'local' ((Get-Date).ToString('o'))
Write-KV 'utc' ([DateTime]::UtcNow.ToString('o'))
Write-KV 'tz' ([TimeZoneInfo]::Local.Id)

$roots = @()
foreach ($path in @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')) {
    Get-ChildItem $path -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match 'mitmproxy' } |
        ForEach-Object {
            $roots += $_
            Write-KV 'ca' ("{0} nb={1:o} na={2:o} thumb={3}" -f $path, $_.NotBefore.ToUniversalTime(), $_.NotAfter.ToUniversalTime(), $_.Thumbprint)
        }
}
if ($roots.Count -eq 0) {
    Write-KV 'ca' 'MISSING'
}

$tcp = New-Object System.Net.Sockets.TcpClient
try {
    # Avoid hanging forever when FakeNet :8080 is down (VBox guestcontrol then times out oddly).
    $ar = $tcp.BeginConnect($ProxyHost, $ProxyPort, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(8000, $false)) {
        Write-KV 'connect' 'tcp-timeout'
        try { $tcp.Close() } catch {}
        exit 2
    }
    $tcp.EndConnect($ar)
} catch {
    Write-KV 'connect' ('tcp-fail ' + $_.Exception.Message)
    exit 2
}

$stream = $tcp.GetStream()
$req = [Text.Encoding]::ASCII.GetBytes(("CONNECT {0}:443 HTTP/1.1`r`nHost: {0}:443`r`nProxy-Connection: keep-alive`r`n`r`n" -f $TargetHost))
$stream.Write($req, 0, $req.Length)
$buf = New-Object byte[] 4096
$hdr = New-Object System.Text.StringBuilder
$stream.ReadTimeout = 8000
while ($hdr.ToString() -notmatch "`r`n`r`n") {
    $n = $stream.Read($buf, 0, $buf.Length)
    if ($n -le 0) { break }
    [void]$hdr.Append([Text.Encoding]::ASCII.GetString($buf, 0, $n))
}
$first = (($hdr.ToString() -split "`r`n")[0])
Write-KV 'connect-resp' $first
if ($first -notmatch ' 200 ') {
    Write-KV 'result' 'connect-fail'
    $tcp.Close()
    exit 3
}

$errors = [Net.Security.SslPolicyErrors]::None
$ssl = New-Object System.Net.Security.SslStream($stream, $false, {
        param($sender, $cert, $chain, $sslErr)
        $script:errors = $sslErr
        $true
    })
try {
    $ssl.AuthenticateAsClient($TargetHost)
} catch {
    Write-KV 'tls' ('auth-fail ' + $_.Exception.Message)
    Write-KV 'ssl-errors' ([string]$errors)
    $tcp.Close()
    exit 4
}

$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
$nb = $cert2.NotBefore.ToUniversalTime()
$na = $cert2.NotAfter.ToUniversalTime()
$now = [DateTime]::UtcNow
Write-KV 'leaf-subject' $cert2.Subject
Write-KV 'leaf-issuer' $cert2.Issuer
Write-KV 'leaf-nb-utc' ($nb.ToString('o'))
Write-KV 'leaf-na-utc' ($na.ToString('o'))
Write-KV 'ssl-errors' ([string]$errors)

$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
$chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
$chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(8)
[void]$chain.Build($cert2)
foreach ($st in $chain.ChainStatus) {
    Write-KV 'chain' ("{0} {1}" -f $st.Status, $st.StatusInformation.Trim())
}
if ($chain.ChainStatus.Count -eq 0) {
    Write-KV 'chain' 'OK'
}

$lifeDays = ($na - $nb).TotalDays
Write-KV 'leaf-lifetime-days' ('{0:N1}' -f $lifeDays)
$skewOk = ($nb -le $now.AddHours(-1))
$lifeOk = ($lifeDays -le 398)
$inWindow = ($now -ge $nb -and $now -le $na -and $skewOk -and $lifeOk)
Write-KV 'dates-ok-on-guest' ([string]$inWindow)
if (-not $skewOk) { Write-KV 'dates-why' 'notBefore too close to guest now (Chrome ERR_CERT_DATE_INVALID)' }
if (-not $lifeOk) { Write-KV 'dates-why' 'lifetime > 398 days (Chrome)' }

$get = [Text.Encoding]::ASCII.GetBytes(("GET / HTTP/1.1`r`nHost: {0}`r`nConnection: close`r`n`r`n" -f $TargetHost))
$ssl.Write($get, 0, $get.Length)
$n = $ssl.Read($buf, 0, $buf.Length)
$http = [Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n, 0))
$httpFirst = (($http -split "`r`n")[0])
Write-KV 'http' $httpFirst

$ssl.Close()
$tcp.Close()

$fail = $false
if ($first -notmatch ' 200 ') { $fail = $true }
if (-not $inWindow) { $fail = $true }
if ($httpFirst -notmatch '^HTTP/1\.[01] 200') { $fail = $true }
# Chrome-class failure: time invalid on the chain (maps to NET::ERR_CERT_DATE_INVALID)
foreach ($st in $chain.ChainStatus) {
    if ($st.Status.ToString() -match 'NotTimeValid|NotTimeNested') { $fail = $true }
}
if ($fail) {
    Write-KV 'result' 'fail'
    exit 1
}
Write-KV 'result' 'browser-https-ok'
exit 0
