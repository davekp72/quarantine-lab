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

  Copies the staged binary into Program Files, stores the token and config under
  ProgramData with a SYSTEM + Administrators DACL, and removes leftover Public secrets.
#>
[CmdletBinding()]
param(
    [string]$StagingDir = 'C:\Users\Public\Quarantine\agent-staging',
    [string]$InstallDir = 'C:\Program Files\QuarantineLab',
    [string]$DataDir = 'C:\ProgramData\QuarantineLab',
    [string]$ServiceName = 'QuarantineLabAgent',
    [int]$WaitSeconds = 45,
    [string]$Token = '',
    [switch]$UninstallOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Protect-QuarantineAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $isDir = (Get-Item -LiteralPath $Path).PSIsContainer
    $sys = '*S-1-5-18:F'
    $adm = '*S-1-5-32-544:F'
    $acct = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    $user = $acct + ':(RX)'
    if ($isDir) {
        $sys = '*S-1-5-18:(OI)(CI)F'
        $adm = '*S-1-5-32-544:(OI)(CI)F'
        $user = $acct + ':(OI)(CI)RX'
    }
    $null = icacls.exe $Path /inheritance:r /grant:r $sys $adm $user
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "icacls failed for $Path (exit $LASTEXITCODE)"
    }
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
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) {
            $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
            return ($raw | ConvertFrom-Json)
        }
    }
    return [pscustomobject]@{}
}

function Resolve-Token {
    param([string]$TokenPath, [string]$Explicit, $Config, [string[]]$SearchPaths = @())
    if ($Explicit) {
        Write-Step 'Using token from -Token'
        return $Explicit.Trim()
    }
    foreach ($p in @($TokenPath) + @($SearchPaths)) {
        if (-not $p) { continue }
        if (Test-Path -LiteralPath $p) {
            $existing = (Get-Content -LiteralPath $p -Raw).Trim()
            if ($existing) {
                Write-Step "Using existing token from $p"
                return $existing
            }
        }
    }
    if ($Config.PSObject.Properties['token'] -and $Config.token) {
        Write-Step 'Using token from agent-install.json (legacy)'
        return ([string]$Config.token).Trim()
    }
    Write-Step 'Generating new bearer token'
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Remove-PublicSecrets {
    $legacy = @(
        'C:\Users\Public\Quarantine\agent\agent-token.txt',
        'C:\Users\Public\Quarantine\agent-token.txt',
        'C:\Users\Public\Quarantine\agent-staging\agent-token.txt',
        'C:\Users\Public\Quarantine\agent-token-sync.txt'
    )
    foreach ($p in $legacy) {
        if (Test-Path -LiteralPath $p) {
            Write-Step "Removing leftover public secret $p"
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Step 'Quarantine Lab Agent install (elevated)'
Remove-InstallScheduledTask
Remove-AgentService -Name $ServiceName

if ($UninstallOnly) {
    Write-Host 'Uninstall complete.' -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$gcUser = Join-Path $DataDir 'guestcontrol.user'
Set-Content -LiteralPath $gcUser -Value (('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) + [Environment]::NewLine) -Encoding ASCII -NoNewline
Protect-QuarantineAcl -Path $InstallDir
Protect-QuarantineAcl -Path $DataDir

$config = Read-InstallConfig -Paths @(
    'C:\Users\Public\Quarantine\agent-install.json',
    'C:\Users\Public\Quarantine\agent\agent-install.json',
    (Join-Path $DataDir 'agent-install.json')
)
$preferVer = if ($config.PSObject.Properties['version'] -and $config.version) { [string]$config.version } else { '' }
$agentExe = $null
if ($config.PSObject.Properties['binary'] -and $config.binary) {
    $cfgBin = [string]$config.binary
    if (Test-Path -LiteralPath $cfgBin) {
        Write-Step "Using staged binary from agent-install.json: $cfgBin"
        $agentExe = $cfgBin
    }
}
if (-not $agentExe) {
    $searchDirs = @($StagingDir, 'C:\Users\Public\Quarantine', $InstallDir)
    foreach ($dir in $searchDirs) {
        if (Test-Path -LiteralPath $dir) {
            try {
                $agentExe = Get-NewestAgentExe -Dir $dir -PreferVersion $preferVer
                break
            } catch {
                $agentExe = $null
            }
        }
    }
}
if (-not $agentExe) {
    throw "No quarantine-agent binary found. Run 'quarantine agent install' on the host first."
}

$tokenPath = Join-Path $DataDir 'agent-token.txt'
$token = Resolve-Token -TokenPath $tokenPath -Explicit $Token -Config $config -SearchPaths @(
    'C:\Users\Public\Quarantine\agent-staging\agent-token.txt',
    'C:\Users\Public\Quarantine\agent\agent-token.txt',
    'C:\Users\Public\Quarantine\agent-token.txt'
)
$port = if ($config.PSObject.Properties['port'] -and $config.port) { [int]$config.port } else { 9443 }
$payloadUser = if ($config.PSObject.Properties['payloadUser'] -and $config.payloadUser) { [string]$config.payloadUser } else { 'analyst' }
$sysmonLog = if ($config.PSObject.Properties['sysmonLog'] -and $config.sysmonLog) { [string]$config.sysmonLog } else { 'Microsoft-Windows-Sysmon/Operational' }

$finalExe = Join-Path $InstallDir 'quarantine-agent.exe'
Write-Step "Installing service binary $finalExe"
Copy-Item -LiteralPath $agentExe -Destination $finalExe -Force
Protect-QuarantineAcl -Path $finalExe
Protect-QuarantineAcl -Path $InstallDir

Set-Content -LiteralPath $tokenPath -Value ($token.Trim() + [Environment]::NewLine) -Encoding ASCII -NoNewline
Protect-QuarantineAcl -Path $tokenPath
Remove-PublicSecrets

Write-Step "Installing from $finalExe"
Write-Host "    Selected binary LastWriteTime: $((Get-Item -LiteralPath $finalExe).LastWriteTime)"
$installArgs = @(
    'install',
    "-token=$token",
    "-port=$port",
    "-payload-user=$payloadUser",
    "-sysmon-log=$sysmonLog"
)
& $finalExe @installArgs
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Agent install failed with exit code $LASTEXITCODE"
}

Protect-QuarantineAcl -Path $DataDir
Protect-QuarantineAcl -Path $InstallDir
Remove-PublicSecrets

Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    throw "Service $ServiceName is not running after install. Check $DataDir\agent.log"
}

Write-Host ''
Write-Host 'Quarantine Lab Agent installed successfully.' -ForegroundColor Green
Write-Host "  Service : $ServiceName (Running)"
Write-Host "  Binary  : $finalExe"
Write-Host "  Data    : $DataDir (SYSTEM + Administrators DACL)"
Write-Host "  Token   : $tokenPath"
Write-Host "  Bearer  : $token"
Write-Host ''
Write-Host 'On the host, the token from "quarantine agent install" should already match. Try:' -ForegroundColor Yellow
Write-Host '  .\quarantine-vm.ps1 agent health'
Write-Host 'If health is 401, sync or paste this bearer token:' -ForegroundColor Yellow
Write-Host '  .\quarantine-vm.ps1 agent sync-token'
Write-Host "  .\quarantine-vm.ps1 agent set-token --token $token"
