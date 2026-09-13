# Live upgrade from agent-staging without deleting the Windows service first.
# Designed for manual guest upgrades after host "agent install" stages files.
# Prefer running Install-QuarantineAgent.ps1 elevated in the guest.
param()

$ErrorActionPreference = 'Continue'
$ServiceName = 'QuarantineLabAgent'
$InstallDir = 'C:\Program Files\QuarantineLab'
$StagingDir = 'C:\Users\Public\Quarantine\agent-staging'
$FinalExe = Join-Path $InstallDir 'quarantine-agent.exe'
$LogPath = Join-Path $StagingDir 'upgrade.log'

function Write-UpgradeLog([string]$Message) {
    $line = '{0} {1}' -f (Get-Date).ToUniversalTime().ToString('o'), $Message
    Add-Content -LiteralPath $LogPath -Value $line -ErrorAction SilentlyContinue
    Write-Host $line
}

function Get-StagedAgentExe {
    $cfgPath = Join-Path $StagingDir 'agent-install.json'
    if (Test-Path -LiteralPath $cfgPath) {
        try {
            $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.binary -and (Test-Path -LiteralPath ([string]$cfg.binary))) {
                return [string]$cfg.binary
            }
        } catch { }
    }
    $hit = @(Get-ChildItem -LiteralPath $StagingDir -Filter 'quarantine-agent*.exe' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($hit.Count -gt 0) {
        return $hit[0].FullName
    }
    return $null
}

function Start-AgentServiceBestEffort {
    try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
    sc.exe start $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return ($svc -and $svc.Status -eq 'Running')
}

New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
Write-UpgradeLog 'upgrade begin'

$src = Get-StagedAgentExe
if (-not $src) {
    Write-UpgradeLog 'ERROR: no staged quarantine-agent*.exe'
    [void](Start-AgentServiceBestEffort)
    exit 2
}
Write-UpgradeLog "source=$src"

try {
    Write-UpgradeLog 'stopping service (keep registration)'
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Get-Process -Name 'quarantine-agent*' -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-UpgradeLog "copy → $FinalExe"
    Copy-Item -LiteralPath $src -Destination $FinalExe -Force

    if (-not (Start-AgentServiceBestEffort)) {
        Write-UpgradeLog 'simple start failed; falling back to Install-QuarantineAgent.ps1'
        $installer = Join-Path $StagingDir 'Install-QuarantineAgent.ps1'
        if (Test-Path -LiteralPath $installer) {
            & $installer *>&1 | ForEach-Object { Write-UpgradeLog "$_" }
        } else {
            Write-UpgradeLog 'ERROR: Install-QuarantineAgent.ps1 missing in staging'
        }
        [void](Start-AgentServiceBestEffort)
    }
} catch {
    Write-UpgradeLog "EXCEPTION: $_"
    [void](Start-AgentServiceBestEffort)
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Write-UpgradeLog 'ERROR: service not running after upgrade'
    exit 1
}
Write-UpgradeLog "upgrade ok status=$($svc.Status)"
exit 0
