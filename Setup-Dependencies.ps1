#Requires -Version 5.1
<#
.SYNOPSIS
  Verify dependencies and ensure config\quarantine-vm.json is ready.
.EXAMPLE
  .\Setup-Dependencies.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('win11', 'win10')]
    [string]$WindowsEdition = 'win11',

    [Parameter()]
    [switch]$RefreshConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = $PSScriptRoot
$IsoDir = Join-Path $Root 'isos'
$VmDataDir = 'C:\QuarantineLab'
$ConfigPath = Join-Path $Root 'config\quarantine-vm.json'
$Autounattend = Join-Path $Root 'templates\autounattend.xml'

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Get-VBoxManagePath {
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox' -ErrorAction SilentlyContinue
    if ($reg -and $reg.InstallDir) {
        $regPath = Join-Path $reg.InstallDir 'VBoxManage.exe'
        if (Test-Path -LiteralPath $regPath) { return $regPath }
    }

    $candidates = @(
        "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
    )
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}

function Install-VirtualBoxIfMissing {
    if (Get-VBoxManagePath) { return (Get-VBoxManagePath) }

    Write-Step 'VirtualBox not found — installing via winget...'
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'Install VirtualBox from https://www.oracle.com/virtualization/virtualbox/ then re-run this script.'
    }

    & winget install Oracle.VirtualBox `
        --accept-package-agreements `
        --accept-source-agreements `
        --disable-interactivity

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath"

    $vbox = Get-VBoxManagePath
    if (-not $vbox) {
        throw 'VirtualBox install finished but VBoxManage.exe not found. Re-open PowerShell and re-run.'
    }
    return $vbox
}

function Write-QuarantineConfig {
    param(
        [string]$VBoxPath,
        [string]$IsoPath
    )

    $vmName = if ($WindowsEdition -eq 'win11') { 'Quarantine-Win11' } else { 'Quarantine-Win10' }
    $guestOs = if ($WindowsEdition -eq 'win11') { 'Windows11_64' } else { 'Windows10_64' }
    $isoName = if ($WindowsEdition -eq 'win11') { 'Win11_English_x64.iso' } else { 'Win10_English_x64.iso' }
    $resolvedIso = if ($IsoPath) { $IsoPath } else { (Join-Path $IsoDir $isoName) }

    $config = [ordered]@{
        '$schema'            = 'https://json-schema.org/draft/2020-12/schema'
        vmName               = $vmName
        guestOsType          = $guestOs
        memoryMb             = 4096
        cpuCount             = 2
        diskSizeGb           = 80
        vmDataDir            = $VmDataDir
        diskPath             = ''
        windowsIsoPath       = $resolvedIso
        autounattendPath     = $Autounattend
        vboxManagePath       = $VBoxPath
        network              = [ordered]@{
            mode             = 'gateway'
            hostOnlyAdapter  = 'VirtualBox Host-Only Ethernet Adapter'
            intnetName       = 'quarantine-net'
            guestGateway     = '10.66.0.1'
            guestDns         = '10.66.0.1'
            proxy            = [ordered]@{
                enabled      = $true
                listenHost   = '0.0.0.0'
                listenPort   = 8080
                pacPort      = 8081
                logDir       = 'C:\QuarantineLab\logs\proxy'
            }
            capture          = [ordered]@{
                enabled      = $true
                mode         = 'gateway'
                logDir       = 'C:\QuarantineLab\logs\pcap'
                interface    = 'gateway-lan'
                guestIp      = '10.66.0.15'
            }
            gateway          = [ordered]@{
                enabled      = $true
                vmName       = 'Quarantine-Gateway'
                lanCidr      = '10.66.0.0/24'
                lanGateway   = '10.66.0.1'
                guestIp      = '10.66.0.15'
                intnetName   = 'quarantine-net'
                uplink       = 'nat'
                trafficMode  = 'fakenet'
                passwordFile = 'C:\QuarantineLab\secrets\gateway-password.txt'
                sshPrivateKey = 'C:\QuarantineLab\secrets\gateway-id_ed25519'
                sshPublicKey  = 'C:\QuarantineLab\secrets\gateway-id_ed25519.pub'
                permissive   = [ordered]@{
                    tcpPorts           = @(80, 443)
                    udpPorts           = @()
                    forceDnsToGateway  = $true
                    allowIcmp          = $true
                }
            }
        }
        isolation            = [ordered]@{
            disableClipboard     = $false
            clipboardMode        = 'hosttoguest'
            disableDragDrop      = $true
            disableUsb           = $true
            disableAudio         = $true
            disableSharedFolders = $true
        }
        inbox                = [ordered]@{
            hostPath          = 'C:\QuarantineLab\quarantine-inbox'
            shareName         = 'quarantine-in'
            readOnly          = $true
            requireNetworkOff = $false
            logDir            = 'C:\QuarantineLab\logs\inbox'
        }
        guest                = [ordered]@{
            username      = 'quarantine'
            password      = ''
            passwordFile  = 'C:\QuarantineLab\secrets\guest-password.txt'
            domain        = ''
            defaultExe    = 'C:\Windows\System32\cmd.exe'
            copyTargetDir = 'C:\Users\Public\Quarantine'
            timeoutMs     = 60000
        }
        payload              = [ordered]@{
            username      = 'analyst'
            password      = ''
            passwordFile  = 'C:\QuarantineLab\secrets\payload-password.txt'
            domain        = ''
            defaultExe    = 'C:\Windows\System32\cmd.exe'
            copyTargetDir = 'C:\Users\Public\Quarantine'
            timeoutMs     = 120000
        }
        sysmon               = [ordered]@{
            hostConfigPath  = 'config\sysmon\quarantine-lab.xml'
            hostSysmonExe   = 'tools\Sysmon64.exe'
            guestDir        = 'C:\Users\Public\Quarantine\sysmon'
            guestConfigName = 'quarantine-lab.xml'
            guestSysmonExe  = 'C:\Users\Public\Quarantine\sysmon\Sysmon64.exe'
            eventLog        = 'Microsoft-Windows-Sysmon/Operational'
        }
        ui                   = [ordered]@{
            warnPublicIpBeforeLaunch = $true
            homeIspPatterns          = @()
        }
        cleanSnapshotName    = 'Clean'
        firmware             = 'efi'
    }

    $configDir = Split-Path $ConfigPath -Parent
    if (-not (Test-Path -LiteralPath $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    ($config | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
    Write-Host "Config: $ConfigPath"
    Write-Host "Next: .\\quarantine-vm.ps1 setup secrets   # unique passwords + gateway SSH keys"
}

function Test-DependencyStatus {
    param(
        [string]$VBoxPath,
        $Config
    )

    $issues = @()

    if (-not $VBoxPath) {
        $issues += 'VirtualBox: NOT INSTALLED'
    } else {
        $ver = & $VBoxPath --version 2>&1
        Write-Host "VirtualBox: OK ($ver)"
        Write-Host "  $VBoxPath"
    }

    try {
        $isoPath = Resolve-WindowsIsoPath `
            -ConfiguredPath $Config.windowsIsoPath `
            -GuestOsType $Config.guestOsType `
            -ProjectRoot $Root
        $gb = [math]::Round((Get-Item -LiteralPath $isoPath).Length / 1GB, 2)
        Write-Host "Windows ISO: OK ($gb GB)"
        Write-Host "  $isoPath"
    } catch {
        $issues += "Windows ISO: MISSING ($($Config.windowsIsoPath); any *.iso in isos\ is auto-detected)"
    }

    if (Test-Path -LiteralPath $Autounattend) {
        Write-Host "Autounattend: OK"
    } else {
        $issues += 'Autounattend template: MISSING'
    }
    $FirstLogon = Join-Path $Root 'templates\firstlogon\Invoke-QuarantineFirstLogon.ps1'
    if (Test-Path -LiteralPath $FirstLogon) {
        Write-Host "FirstLogon script: OK"
    } else {
        $issues += 'FirstLogon script: MISSING'
    }

    return $issues
}

function Install-QuarantinePythonVenv {
    param([string]$ProjectRoot)

    $venv = Join-Path $ProjectRoot '.venv'
    $mitmdump = Join-Path $venv 'Scripts\mitmdump.exe'
    if (Test-Path -LiteralPath $mitmdump) {
        Write-Host "Python venv: OK ($venv)"
        return $null
    }

    $requirements = Join-Path $ProjectRoot 'requirements.txt'
    if (-not (Test-Path -LiteralPath $requirements)) {
        return @('requirements.txt missing — cannot install mitmproxy venv')
    }

    Write-Step 'Creating .venv and installing mitmproxy'
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyLauncher -and -not $python) {
        return @('Python not found — install Python 3 from https://www.python.org/downloads/ then re-run Setup-Dependencies.ps1')
    }

    if ($pyLauncher) {
        & py -3 -m venv $venv
    } else {
        & python -m venv $venv
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $venv 'Scripts\pip.exe'))) {
        return @("Failed to create venv at $venv")
    }

    $pip = Join-Path $venv 'Scripts\pip.exe'
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    & $venvPython -m pip install --upgrade pip 2>&1 | Out-Null
    & $venvPython -m pip install -r $requirements
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $mitmdump)) {
        return @('mitmproxy install in .venv failed — check pip output above')
    }

    Write-Host "mitmproxy installed in venv: $mitmdump"
    return $null
}

function Test-QuarantineNetworkTools {
    param([string]$ProjectRoot)

    $issues = @()

    $venvIssues = Install-QuarantinePythonVenv -ProjectRoot $ProjectRoot
    if ($venvIssues) { $issues += $venvIssues }

    $mitm = Find-MitmproxyCommand
    if ($mitm) {
        Write-Host "mitmproxy: OK"
        Write-Host "  $mitm"
    } else {
        $issues += 'mitmproxy: NOT FOUND — run .\Setup-Dependencies.ps1'
    }

    $tshark = Find-TsharkCommand
    if ($tshark) {
        Write-Host "tshark: OK"
        Write-Host "  $tshark"
    } else {
        $issues += 'tshark/Wireshark: NOT FOUND (optional) — needed for packet capture'
    }

    foreach ($dir in @('C:\QuarantineLab\logs\proxy', 'C:\QuarantineLab\logs\pcap')) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    return $issues
}

function Initialize-VirtualBoxHostNetwork {
    param([string]$VBoxPath)

    Write-Step 'Checking VirtualBox host-only network'
    $existing = & $VBoxPath list hostonlyifs 2>&1
    if ($LASTEXITCODE -eq 0 -and ($existing -match 'Name:')) {
        Write-Host 'Host-only adapter: OK'
        return
    }

    Write-Warning @'
Host-only network could not be listed/created (may need Administrator).
If VM creation fails on networking, run PowerShell as Admin and execute:
  VBoxManage hostonlyif create
'@
}

# --- Main ---
Import-Module (Join-Path $Root 'QuarantineVM.psm1') -Force
Import-Module (Join-Path $Root 'QuarantineNetwork.psm1') -Force

Write-Step 'Preparing directories'
foreach ($dir in @($IsoDir, $VmDataDir, (Split-Path $ConfigPath -Parent), (Join-Path $Root 'scripts'))) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$vboxPath = Install-VirtualBoxIfMissing

$existingIso = $null
if ((Test-Path -LiteralPath $ConfigPath) -and -not $RefreshConfig) {
    $existing = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($existing.windowsIsoPath) { $existingIso = $existing.windowsIsoPath }
}

if ($RefreshConfig -or -not (Test-Path -LiteralPath $ConfigPath)) {
    Write-Step 'Writing config\quarantine-vm.json'
    Write-QuarantineConfig -VBoxPath $vboxPath -IsoPath $existingIso
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
Write-Step 'Dependency check'
$issues = Test-DependencyStatus -VBoxPath $vboxPath -Config $config
$issues += Test-QuarantineNetworkTools -ProjectRoot $Root
Initialize-VirtualBoxHostNetwork -VBoxPath $vboxPath

Write-Step 'Sysmon (download from Microsoft; not redistributed)'
try {
    & (Join-Path $Root 'scripts\Get-Sysmon.ps1') -ProjectRoot $Root
} catch {
    $issues += "Sysmon: $($_.Exception.Message)"
}

if ($issues -match 'ISO: MISSING') {
    Write-Step 'Windows ISO required'
    & (Join-Path $Root 'scripts\Get-WindowsIso.ps1') -ConfigPath $ConfigPath
    $issues = Test-DependencyStatus -VBoxPath $vboxPath -Config $config
}

Write-Step 'Summary'
if ($issues.Count -eq 0) {
    Write-Host @'
All dependencies ready.

  .\quarantine-vm.ps1 create
  .\quarantine-vm.ps1 install
  .\quarantine-vm.ps1 snapshot

'@ -ForegroundColor Green
} else {
    Write-Host 'Outstanding items:' -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
