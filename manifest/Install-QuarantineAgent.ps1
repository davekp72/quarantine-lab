#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove any existing Quarantine Lab Agent Windows service and install the newest guest agent binary.

.DESCRIPTION
  Deployed by: quarantine agent install (host)
  Run inside the guest VM in an elevated PowerShell window:

    Set-ExecutionPolicy -Scope Process Bypass
    & 'C:\Users\Public\Quarantine\Install-QuarantineAgent.ps1'

  Reads optional settings from C:\Users\Public\Quarantine\agent\agent-install.json (written by host deploy).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Users\Public\Quarantine',
    [string]$ServiceName = 'QuarantineLabAgent',
    [string]$ConfigDir = 'C:\Users\Public\Quarantine\agent',
    [int]$WaitSeconds = 45,
    [switch]$UninstallOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Wait-ServiceRemoved {
    param([string]$Name, [int]$TimeoutSec)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Stop-AgentProcesses {
    Get-Process -Name 'quarantine-agent*' -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Step "Stopping process $($_.Name) (pid $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

function Remove-AgentService {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Step "Service $Name is not registered"
        return
    }
    Write-Step "Stopping service $Name"
    try {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    } catch {
        sc.exe stop $Name | Out-Null
    }
    Start-Sleep -Seconds 2
    Stop-AgentProcesses
    Write-Step "Deleting service $Name"
    sc.exe delete $Name | Out-Null
    if (-not (Wait-ServiceRemoved -Name $Name -TimeoutSec $WaitSeconds)) {
        throw "Service $Name is still marked for deletion. Close services.msc, wait, or reboot the VM, then re-run this script."
    }
}

function Remove-InstallScheduledTask {
    $taskName = 'QuarantineLabAgentInstall'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Step "Removing scheduled task $taskName"
        schtasks.exe /Delete /TN $taskName /F | Out-Null
    }
}

function Get-NewestAgentExe {
    param([string]$Dir, [string]$PreferVersion = '')
    $versioned = @(Get-ChildItem -LiteralPath $Dir -Filter 'quarantine-agent-v*.exe' -File -ErrorAction SilentlyContinue)
    if ($PreferVersion) {
        $tag = ($PreferVersion -replace '\.', '-')
        # Newest build for this version tag (includes -new / deploy-* fallbacks locked by the old service).
        $matched = @($versioned | Where-Object {
                $_.Name -eq ("quarantine-agent-v{0}.exe" -f $tag) -or
                $_.Name -like ("quarantine-agent-v{0}-*.exe" -f $tag)
            } | Sort-Object { $_.LastWriteTimeUtc } -Descending)
        if ($matched.Count -gt 0) {
            return $matched[0].FullName
        }
    }
    $versioned = @($versioned | Sort-Object { $_.LastWriteTimeUtc } -Descending)
    if ($versioned.Count -gt 0) {
        return $versioned[0].FullName
    }
    $stable = Join-Path $Dir 'quarantine-agent.exe'
    if (Test-Path -LiteralPath $stable) {
        return $stable
    }
    throw ("No quarantine-agent-v*.exe or quarantine-agent.exe found in {0}. Run 'quarantine agent install' on the host first." -f $Dir)
}

function Read-InstallConfig {
    param([string]$Dir)
    $path = Join-Path $Dir 'agent-install.json'
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{}
    }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    return ($raw | ConvertFrom-Json)
}

function Resolve-Token {
    param([string]$ConfigDir, $Config)
    $tokenPath = Join-Path $ConfigDir 'agent-token.txt'
    if (Test-Path -LiteralPath $tokenPath) {
        $existing = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
        if ($existing) {
            Write-Step "Using existing token from $tokenPath"
            return $existing
        }
    }
    if ($Config.token) {
        $tok = [string]$Config.token
        Write-Step 'Using token from agent-install.json'
        return $tok.Trim()
    }
    Write-Step 'Generating new bearer token'
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

Write-Step 'Quarantine Lab Agent install (elevated)'
Remove-InstallScheduledTask
Remove-AgentService -Name $ServiceName

if ($UninstallOnly) {
    Write-Host 'Uninstall complete.' -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $InstallDir)) {
    throw "Install directory missing: $InstallDir"
}
if (-not (Test-Path -LiteralPath $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$config = Read-InstallConfig -Dir $ConfigDir
$preferVer = if ($config.version) { [string]$config.version } else { '' }
$agentExe = $null
if ($config.binary) {
    $cfgBin = [string]$config.binary
    if (Test-Path -LiteralPath $cfgBin) {
        Write-Step "Using binary from agent-install.json: $cfgBin"
        $agentExe = $cfgBin
    }
}
if (-not $agentExe) {
    $agentExe = Get-NewestAgentExe -Dir $InstallDir -PreferVersion $preferVer
}
$token = Resolve-Token -ConfigDir $ConfigDir -Config $config
$port = if ($config.port) { [int]$config.port } else { 9443 }
$payloadUser = if ($config.payloadUser) { [string]$config.payloadUser } else { 'jkcooper' }
$sysmonLog = if ($config.sysmonLog) { [string]$config.sysmonLog } else { 'Microsoft-Windows-Sysmon/Operational' }

Write-Step "Installing from $agentExe"
Write-Host "    Selected binary LastWriteTime: $((Get-Item -LiteralPath $agentExe).LastWriteTime)"
$installArgs = @(
    'install',
    "-token=$token",
    "-port=$port",
    "-payload-user=$payloadUser",
    "-sysmon-log=$sysmonLog"
)
& $agentExe @installArgs
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Agent install failed with exit code $LASTEXITCODE"
}

$tokenPath = Join-Path $ConfigDir 'agent-token.txt'
Set-Content -LiteralPath $tokenPath -Value ($token.Trim() + [Environment]::NewLine) -Encoding ASCII -NoNewline
Write-Step "Token saved to $tokenPath"

Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    throw "Service $ServiceName is not running after install. Check $ConfigDir\agent.log"
}

Write-Host ''
Write-Host 'Quarantine Lab Agent installed successfully.' -ForegroundColor Green
Write-Host "  Service : $ServiceName (Running)"
Write-Host "  Binary  : $agentExe"
Write-Host "  Token   : $tokenPath"
Write-Host ''
Write-Host 'On the host run:  .\quarantine-vm.ps1 agent sync-token' -ForegroundColor Yellow
