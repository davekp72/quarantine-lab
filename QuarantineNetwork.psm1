#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:ProjectRoot = $PSScriptRoot
$script:NetworkRoot = Join-Path $PSScriptRoot 'network'

function Get-QuarantineVenvPath {
    return Join-Path $script:ProjectRoot '.venv'
}

function Get-QuarantineVenvPython {
    $python = Join-Path (Get-QuarantineVenvPath) 'Scripts\python.exe'
    if (Test-Path -LiteralPath $python) { return $python }
    return $null
}

function Find-MitmproxyCommand {
    $venvMitmdump = Join-Path (Get-QuarantineVenvPath) 'Scripts\mitmdump.exe'
    if (Test-Path -LiteralPath $venvMitmdump) { return $venvMitmdump }

    $candidates = @(
        (Get-Command mitmdump -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        (Get-Command mitmproxy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    ) | Where-Object { $_ }

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }

    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    $scripts = Join-Path $localAppData 'Programs\Python\Python*\Scripts\mitmdump.exe'
    $found = Get-ChildItem -Path $scripts -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }

    return $null
}

function Find-QuarantinePythonCommand {
    $venvPython = Get-QuarantineVenvPython
    if ($venvPython) { return $venvPython }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return $python.Source }

    $python3 = Get-Command python3 -ErrorAction SilentlyContinue
    if ($python3) { return $python3.Source }

    return $null
}

function Get-QuarantineNetworkConfig {
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json')
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config not found: $ConfigPath"
    }

    $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if (-not $cfg.network) {
        throw 'Config is missing network section.'
    }
    return $cfg
}

function Get-QuarantineNetworkStatePath {
    param([string]$LogRoot)

    $dir = if ($LogRoot) { $LogRoot } else { Join-Path $script:ProjectRoot 'logs\proxy' }
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return Join-Path $dir 'quarantine-network.state.json'
}

function Read-QuarantineNetworkState {
    param([string]$StatePath)

    $skipProps = @('Keys', 'Values', 'Count', 'IsFixedSize', 'IsReadOnly', 'IsSynchronized', 'SyncRoot')
    if (-not (Test-Path -LiteralPath $StatePath)) {
        return [ordered]@{}
    }

    $obj = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $state = [ordered]@{}
    foreach ($prop in $obj.PSObject.Properties) {
        if ($prop.Name -notin $skipProps) {
            $state[$prop.Name] = $prop.Value
        }
    }
    return $state
}

function Write-QuarantineNetworkState {
    param(
        [Parameter(Mandatory)]
        [hashtable]$State,

        [Parameter(Mandatory)]
        [string]$StatePath
    )

    $allowed = @('mitmproxyPid', 'pacPid', 'sessionDir', 'startedAt', 'listenPort', 'pacPort')
    $clean = [ordered]@{}
    foreach ($key in $allowed) {
        if ($null -ne $State[$key]) {
            $clean[$key] = $State[$key]
        }
    }
    ($clean | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Find-TsharkCommand {
    $candidates = @(
        (Get-Command tshark -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "${env:ProgramFiles}\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
    )
    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Test-ProcessRunning {
    param([int]$ProcessId)

    if ($ProcessId -le 0) { return $false }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        return -not $proc.HasExited
    } catch {
        return $false
    }
}

function Stop-QuarantineManagedProcess {
    param(
        [int]$ProcessId,
        [string]$Label
    )

    if (-not (Test-ProcessRunning -ProcessId $ProcessId)) { return }

    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Host "Stopped $Label (PID $ProcessId)."
    } catch {
        Write-Warning "Could not stop $Label (PID $ProcessId): $_"
    }
}

function Start-QuarantinePacServer {
    param(
        [Parameter(Mandatory)]
        [string]$PacDir,

        [Parameter(Mandatory)]
        [int]$Port
    )

    $python = Find-QuarantinePythonCommand
    if (-not $python) {
        Write-Warning 'Python not found; PAC is served from mitmproxy at /quarantine.pac on the proxy port.'
        return $null
    }

    $proc = Start-Process -FilePath $python `
        -ArgumentList @('-m', 'http.server', "$Port", '--bind', '0.0.0.0', '--directory', $PacDir) `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 300
    return $proc
}

function Start-QuarantineProxy {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $proxy = $cfg.network.proxy
    if (-not $proxy.enabled) {
        Write-Host 'Proxy disabled in config.'
        return
    }

    $logDir = $proxy.logDir
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $statePath = Get-QuarantineNetworkStatePath -LogRoot $logDir
    $state = Read-QuarantineNetworkState -StatePath $statePath

    $mitmPid = if ($state['mitmproxyPid']) { [int]$state['mitmproxyPid'] } else { 0 }
    if (Test-ProcessRunning -ProcessId $mitmPid) {
        Write-Host 'Quarantine proxy already running.'
        return
    }

    $mitmdump = Find-MitmproxyCommand
    if (-not $mitmdump) {
        throw 'mitmdump not found. Run .\Setup-Dependencies.ps1 to create .venv and install mitmproxy.'
    }

    $session = Get-Date -Format 'yyyyMMdd-HHmmss'
    $sessionDir = Join-Path $logDir $session
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

    $flowsPath = Join-Path $sessionDir 'flows.mitm'
    $accessLog = Join-Path $sessionDir 'access.log'
    $errorLog = Join-Path $sessionDir 'errors.log'
    $addon = Join-Path $script:NetworkRoot 'proxy\block_private.py'

    $listenHost = if ($proxy.listenHost) { $proxy.listenHost } else { '0.0.0.0' }
    $listenPort = if ($proxy.listenPort) { [int]$proxy.listenPort } else { 8080 }
    $pacPort = if ($proxy.pacPort) { [int]$proxy.pacPort } else { 8081 }
    $pacPath = Join-Path $script:NetworkRoot 'proxy\quarantine.pac'

    $caPath = Publish-QuarantineProxyCA -LogDir $logDir

    $env:QUARANTINE_ACCESS_LOG = $accessLog
    $env:QUARANTINE_ERROR_LOG = $errorLog
    $env:QUARANTINE_PAC_PATH = $pacPath
    if ($caPath) { $env:QUARANTINE_CA_PATH = $caPath }

    $mitmArgs = @(
        '--listen-host', $listenHost,
        '--listen-port', "$listenPort",
        '-s', $addon,
        '-w', $flowsPath,
        '--set', 'block_global=false'
    )

    $mitmProc = Start-Process -FilePath $mitmdump -ArgumentList $mitmArgs -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    if ($mitmProc.HasExited) {
        throw "mitmdump exited immediately (code $($mitmProc.ExitCode)). Check $errorLog"
    }

    if (-not $caPath) {
        $caPath = Publish-QuarantineProxyCA -LogDir $logDir
        if ($caPath) { $env:QUARANTINE_CA_PATH = $caPath }
    }

    $pacDir = Split-Path $pacPath -Parent
    $pacProc = Start-QuarantinePacServer -PacDir $pacDir -Port $pacPort

    $state['mitmproxyPid'] = $mitmProc.Id
    if ($pacProc) { $state['pacPid'] = $pacProc.Id }
    $state['sessionDir'] = $sessionDir
    $state['startedAt'] = (Get-Date).ToString('o')
    $state['listenPort'] = $listenPort
    $state['pacPort'] = $pacPort

    Write-QuarantineNetworkState -State $state -StatePath $statePath

    Write-Host "Quarantine proxy started."
    Write-Host "  mitmdump PID: $($mitmProc.Id) on ${listenHost}:$listenPort"
    if ($pacProc) {
        Write-Host "  PAC server PID: $($pacProc.Id) on port $pacPort"
    } else {
        Write-Host "  PAC URL (via proxy): http://$($cfg.network.guestGateway):$listenPort/quarantine.pac"
    }
    Write-Host "  Logs: $sessionDir"
    if ($caPath) {
        Write-Host "  CA: $caPath"
        Write-Host "  Guest CA URL: http://$($cfg.network.guestGateway):$pacPort/mitmproxy-ca-cert.cer"
    } else {
        Write-Warning 'mitmproxy CA not published yet. Re-run proxy start or proxy export-ca after the first run.'
    }
}

function Stop-QuarantineProxy {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json')
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $logDir = $cfg.network.proxy.logDir
    $statePath = Get-QuarantineNetworkStatePath -LogRoot $logDir
    $state = Read-QuarantineNetworkState -StatePath $statePath

    if ($state['mitmproxyPid']) {
        Stop-QuarantineManagedProcess -ProcessId ([int]$state['mitmproxyPid']) -Label 'mitmdump'
    }
    if ($state['pacPid']) {
        Stop-QuarantineManagedProcess -ProcessId ([int]$state['pacPid']) -Label 'PAC server'
    }

    if (Test-Path -LiteralPath $statePath) {
        Remove-Item -LiteralPath $statePath -Force
    }

    Write-Host 'Quarantine proxy stopped.'
}

function Get-QuarantineProxyStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json')
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $logDir = $cfg.network.proxy.logDir
    $statePath = Get-QuarantineNetworkStatePath -LogRoot $logDir
    $state = Read-QuarantineNetworkState -StatePath $statePath

    $mitmRunning = $false
    $mitmPid = $null
    if ($state['mitmproxyPid']) {
        $mitmPid = [int]$state['mitmproxyPid']
        $mitmRunning = Test-ProcessRunning -ProcessId $mitmPid
    }

    [pscustomobject]@{
        Running    = $mitmRunning
        MitmPid    = $mitmPid
        ListenPort = if ($state['listenPort']) { $state['listenPort'] } else { $cfg.network.proxy.listenPort }
        PacPort    = if ($state['pacPort']) { $state['pacPort'] } else { $cfg.network.proxy.pacPort }
        SessionDir = if ($state['sessionDir']) { $state['sessionDir'] } else { $null }
        LogDir     = $logDir
        Mitmdump   = Find-MitmproxyCommand
    }
}

function Get-QuarantineCaptureInterface {
    param(
        [string]$Preferred,
        [string]$TsharkPath,
        [string]$Mode = 'auto'
    )

    if ($Preferred -and $Preferred -notin @('auto', 'loopback')) {
        return $Preferred
    }

    if (-not $TsharkPath) {
        $TsharkPath = Find-TsharkCommand
    }
    if (-not $TsharkPath) { return $null }

    $output = & $TsharkPath -D 2>&1
    if ($Preferred -eq 'loopback' -or $Mode -eq 'loopback-proxy') {
        foreach ($line in $output) {
            if ($line -match 'loopback' -and $line -match '^(\d+)\.') {
                return $Matches[1]
            }
        }
    }

    foreach ($line in $output) {
        if ($line -match 'VirtualBox|VBox') {
            if ($line -match '^(\d+)\.') {
                return $Matches[1]
            }
        }
    }

    foreach ($line in $output) {
        if ($line -match 'loopback' -and $line -match '^(\d+)\.') {
            return $Matches[1]
        }
    }

    foreach ($line in $output) {
        if ($line -match '^(\d+)\.') {
            return $Matches[1]
        }
    }
    return $null
}

function Get-QuarantineCaptureFilter {
    param(
        [string]$Mode,
        [string]$GuestIp,
        [int]$ProxyPort,
        [int]$PacPort,
        [string]$InterfaceName
    )

    if ($Mode -eq 'loopback-proxy' -or ($InterfaceName -and $InterfaceName -match 'loopback')) {
        return "tcp port $ProxyPort or tcp port $PacPort"
    }
    if ($GuestIp) {
        return "host $GuestIp"
    }
    return "tcp port $ProxyPort or tcp port $PacPort"
}

function Get-QuarantineCaptureStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json')
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $logDir = $cfg.network.capture.logDir
    $statePath = Join-Path $logDir 'capture.state.json'
    $state = $null
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }

    $running = $false
    $pcapBytes = 0
    if ($state -and $state.pid) {
        $running = Test-ProcessRunning -ProcessId ([int]$state.pid)
    }
    if ($state -and $state.pcapPath -and (Test-Path -LiteralPath $state.pcapPath)) {
        $pcapBytes = (Get-Item -LiteralPath $state.pcapPath).Length
    }

    [pscustomobject]@{
        Running   = $running
        Pid       = if ($state) { $state.pid } else { $null }
        PcapPath  = if ($state) { $state.pcapPath } else { $null }
        PcapBytes = $pcapBytes
        Interface = if ($state) { $state.interface } else { $null }
        Filter    = if ($state) { $state.filter } else { $null }
        LogDir    = $logDir
        Tshark    = Find-TsharkCommand
    }
}

function Start-QuarantineCapture {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$Required
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $capture = $cfg.network.capture
    if (-not $capture.enabled) {
        Write-Host 'Capture disabled in config.'
        return
    }

    $tshark = Find-TsharkCommand
    if (-not $tshark) {
        $msg = 'tshark not found. Packet capture skipped. Install Wireshark (includes Npcap) for PCAPs: https://www.wireshark.org/download.html'
        if ($Required) { throw $msg }
        Write-Warning $msg
        return
    }

    $logDir = $capture.logDir
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $statePath = Join-Path $logDir 'capture.state.json'
    if (Test-Path -LiteralPath $statePath) {
        $existing = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($existing.pid -and (Test-ProcessRunning -ProcessId ([int]$existing.pid))) {
            Write-Host "Capture already running (PID $($existing.pid))."
            Write-Host "  PCAP: $($existing.pcapPath)"
            return
        }
    }

    $captureMode = if ($capture.mode) { $capture.mode } else { 'loopback-proxy' }
    $iface = Get-QuarantineCaptureInterface -Preferred $capture.interface -TsharkPath $tshark -Mode $captureMode
    if (-not $iface) {
        throw 'Could not detect capture interface. Set network.capture.interface in config (use "loopback" for NAT VMs).'
    }

    $guestIp = if ($capture.guestIp) { $capture.guestIp } else { '10.0.2.15' }
    $proxyPort = [int]$cfg.network.proxy.listenPort
    $pacPort = [int]$cfg.network.proxy.pacPort
    $ifaceLine = (& $tshark -D 2>&1 | Where-Object { $_ -match "^$iface\." } | Select-Object -First 1)
    $bpf = Get-QuarantineCaptureFilter -Mode $captureMode -GuestIp $guestIp -ProxyPort $proxyPort -PacPort $pacPort -InterfaceName $ifaceLine
    $session = Get-Date -Format 'yyyyMMdd-HHmmss'
    $pcapPath = Join-Path $logDir "quarantine-$session.pcap"

    $pcapPathEsc = $pcapPath -replace '"', '\"'
    $bpfEsc = $bpf -replace '"', '\"'
    $argString = "-i $iface -f `"$bpfEsc`" -w `"$pcapPathEsc`""
    $proc = Start-Process -FilePath $tshark -ArgumentList $argString -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) {
        throw "tshark exited immediately (code $($proc.ExitCode)). Capture filter: $bpf on interface $iface"
    }

    $capState = [ordered]@{
        pid       = $proc.Id
        pcapPath  = $pcapPath
        interface = $iface
        filter    = $bpf
        guestIp   = $guestIp
        mode      = $captureMode
        startedAt = (Get-Date).ToString('o')
    }
    ($capState | ConvertTo-Json) | Set-Content -LiteralPath $statePath -Encoding UTF8

    Write-Host "Packet capture started (PID $($proc.Id))."
    Write-Host "  Interface: $iface ($ifaceLine)"
    Write-Host "  Filter: $bpf"
    Write-Host "  PCAP: $pcapPath"
    if ($captureMode -eq 'loopback-proxy') {
        Write-Host '  Note: loopback capture records proxy/PAC traffic (guest NAT IP is not visible on host NICs).'
    }
}

function Initialize-QuarantineNetworkServices {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$SkipProxy,

        [Parameter()]
        [switch]$SkipCapture
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $networkMode = if ($cfg.network.mode) { $cfg.network.mode.ToLowerInvariant() } else { '' }
    if ($networkMode -ne 'quarantine') { return }

    if (-not $SkipProxy -and $cfg.network.proxy.enabled) {
        Start-QuarantineProxy -ConfigPath $ConfigPath
        $proxy = Get-QuarantineProxyStatus -ConfigPath $ConfigPath
        if ($proxy.Running -and $proxy.SessionDir) {
            Write-Host "  Access log: $(Join-Path $proxy.SessionDir 'access.log')"
        }
    }
    if (-not $SkipCapture -and $cfg.network.capture.enabled) {
        Start-QuarantineCapture -ConfigPath $ConfigPath
    }
}

function Stop-QuarantineCapture {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json')
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $logDir = $cfg.network.capture.logDir
    $statePath = Join-Path $logDir 'capture.state.json'

    if (-not (Test-Path -LiteralPath $statePath)) {
        Write-Host 'No capture session found.'
        return
    }

    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Stop-QuarantineManagedProcess -ProcessId ([int]$state.pid) -Label 'tshark'
    Write-Host "PCAP saved: $($state.pcapPath)"
    Remove-Item -LiteralPath $statePath -Force
}

function Set-QuarantineVMNatPortForwards {
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$VBoxManagePath,

        [Parameter()]
        [int]$ProxyPort = 8080,

        [Parameter()]
        [int]$PacPort = 8081,

        [Parameter()]
        [switch]$Remove
    )

    $rules = @(
        @{ Name = 'quarantine-proxy'; HostPort = $ProxyPort; GuestPort = $ProxyPort },
        @{ Name = 'quarantine-pac'; HostPort = $PacPort; GuestPort = $PacPort }
    )

    foreach ($rule in $rules) {
        & $VBoxManagePath modifyvm $VmName --natpf1 delete $rule.Name 2>$null | Out-Null
        if (-not $Remove) {
            $spec = "$($rule.Name),tcp,,$($rule.HostPort),,$($rule.GuestPort)"
            & $VBoxManagePath modifyvm $VmName --natpf1 $spec 2>&1 | Out-Null
        }
    }
}

function Enable-QuarantineVMNetwork {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$SkipProxy,

        [Parameter()]
        [switch]$SkipCapture
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $vmName = $cfg.vmName
    $vbox = if ($cfg.vboxManagePath) { $cfg.vboxManagePath } else { throw 'vboxManagePath missing in config.' }

    if (-not (Test-Path -LiteralPath $vbox)) {
        throw "VBoxManage not found: $vbox"
    }

    $state = & $vbox showvminfo $vmName --machinereadable 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "VM '$vmName' not found."
    }

    $powerState = (& $vbox showvminfo $vmName --machinereadable 2>&1 | Where-Object { $_ -match '^VMState=' }) -replace '^VMState="(.*)"$', '$1'
    if ($powerState -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM before enabling quarantine network...'
        & $vbox controlvm $vmName poweroff 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    & $vbox modifyvm $vmName --nic1 nat --cableconnected1 on 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to set VM NIC to NAT.'
    }

    $proxyPort = [int]$cfg.network.proxy.listenPort
    $pacPort = [int]$cfg.network.proxy.pacPort
    Set-QuarantineVMNatPortForwards -VmName $vmName -VBoxManagePath $vbox -ProxyPort $proxyPort -PacPort $pacPort

    if (-not $SkipProxy -and $cfg.network.proxy.enabled) {
        Start-QuarantineProxy -ConfigPath $ConfigPath
    }
    if (-not $SkipCapture -and $cfg.network.capture.enabled) {
        Start-QuarantineCapture -ConfigPath $ConfigPath
    }

    Write-Host @"

Quarantine network enabled for '$vmName':
  NIC: NAT (guest gateway $($cfg.network.guestGateway), DNS $($cfg.network.guestDns))
  HTTP(S) proxy: $($cfg.network.guestGateway):$proxyPort
  PAC URL: http://$($cfg.network.guestGateway):$pacPort/quarantine.pac

Run Configure-QuarantineGuestNetwork.ps1 inside the guest once, then baseline.
"@
}

function Find-QuarantineProxyCA {
    param([string]$LogDir)

    $candidates = @(
        (Join-Path $env:USERPROFILE '.mitmproxy\mitmproxy-ca-cert.cer'),
        (Join-Path $env:USERPROFILE '.mitmproxy\mitmproxy-ca-cert.pem'),
        (Join-Path $LogDir 'certs\mitmproxy-ca-cert.cer'),
        (Join-Path $script:NetworkRoot 'proxy\mitmproxy-ca-cert.cer')
    )
    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Publish-QuarantineProxyCA {
    param([string]$LogDir)

    $src = Find-QuarantineProxyCA -LogDir $LogDir
    if (-not $src) { return $null }

    $srcFull = [System.IO.Path]::GetFullPath($src)
    $pacDir = Join-Path $script:NetworkRoot 'proxy'
    $certsDir = Join-Path $LogDir 'certs'
    foreach ($dir in @($pacDir, $certsDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $dest = [System.IO.Path]::GetFullPath((Join-Path $dir 'mitmproxy-ca-cert.cer'))
        if ($srcFull -ne $dest) {
            Copy-Item -LiteralPath $src -Destination $dest -Force
        }
    }
    return (Join-Path $pacDir 'mitmproxy-ca-cert.cer')
}

function Export-QuarantineProxyCA {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $script:ProjectRoot 'config\quarantine-vm.json'),

        [Parameter()]
        [string]$OutDir
    )

    $cfg = Get-QuarantineNetworkConfig -ConfigPath $ConfigPath
    $logDir = $cfg.network.proxy.logDir
    $published = Publish-QuarantineProxyCA -LogDir $logDir

    if (-not $published) {
        Write-Warning @"
mitmproxy CA not found.
Start the proxy once (.\quarantine-vm.ps1 proxy start) so mitmproxy generates its CA, then re-run proxy export-ca.
Install in the guest with network\guest\Install-QuarantineProxyCA.ps1 (Admin).
Note: certificate pinning, HSTS preload, and many system services will still not be decryptable.
"@
        return
    }

    $dest = if ($OutDir) { $OutDir } else { Join-Path $logDir 'certs-export' }
    if (-not (Test-Path -LiteralPath $dest)) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
    }
    $target = Join-Path $dest 'mitmproxy-ca-cert.cer'
    Copy-Item -LiteralPath $published -Destination $target -Force
    $gateway = $cfg.network.guestGateway
    $pacPort = [int]$cfg.network.proxy.pacPort
    Write-Host "CA certificate exported to: $target"
    Write-Host "Also served at: http://${gateway}:${pacPort}/mitmproxy-ca-cert.cer"
    Write-Host "In the guest (Admin): powershell -ExecutionPolicy Bypass -File .\Install-QuarantineProxyCA.ps1"
}

Export-ModuleMember -Function @(
    'Get-QuarantineNetworkConfig',
    'Start-QuarantineProxy',
    'Stop-QuarantineProxy',
    'Get-QuarantineProxyStatus',
    'Start-QuarantineCapture',
    'Stop-QuarantineCapture',
    'Get-QuarantineCaptureStatus',
    'Initialize-QuarantineNetworkServices',
    'Enable-QuarantineVMNetwork',
    'Export-QuarantineProxyCA',
    'Find-MitmproxyCommand',
    'Find-TsharkCommand'
)
