#Requires -Version 5.1
<#
.SYNOPSIS
  Disable Windows Update, Delivery Optimization, and Store auto-updates in the guest.
.DESCRIPTION
  Run inside the quarantine VM as Administrator before taking the Clean baseline.
  Do not try to run Windows Update through the quarantine proxy — WinHTTP and
  Microsoft endpoints ignore the mitmproxy CA (pinned TLS).

  If you want a patched Clean image, update once on raw NAT with outbound
  allowed, then run this script and baseline.
#>
[CmdletBinding()]
param()

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

Write-Host 'Disabling Windows Update in the guest...'

$wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$auPolicy = Join-Path $wuPolicy 'AU'
foreach ($path in @($wuPolicy, $auPolicy)) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

Set-ItemProperty -Path $wuPolicy -Name DoNotConnectToWindowsUpdateInternetLocations -Value 1 -Type DWord
Set-ItemProperty -Path $wuPolicy -Name DisableWindowsUpdateAccess -Value 1 -Type DWord
Set-ItemProperty -Path $auPolicy -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty -Path $auPolicy -Name AUOptions -Value 1 -Type DWord

$doPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
if (-not (Test-Path -LiteralPath $doPolicy)) {
    New-Item -Path $doPolicy -Force | Out-Null
}
Set-ItemProperty -Path $doPolicy -Name DODownloadMode -Value 99 -Type DWord

$storePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
if (-not (Test-Path -LiteralPath $storePolicy)) {
    New-Item -Path $storePolicy -Force | Out-Null
}
Set-ItemProperty -Path $storePolicy -Name AutoDownload -Value 2 -Type DWord

$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
if (Test-Path -LiteralPath $ux) {
    Set-ItemProperty -Path $ux -Name FlightSettingsMaxPauseDays -Value 3650 -Type DWord
    Set-ItemProperty -Path $ux -Name PauseFeatureUpdatesStartTime -Value ((Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Set-ItemProperty -Path $ux -Name PauseFeatureUpdatesEndTime -Value ((Get-Date).AddYears(10).ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Set-ItemProperty -Path $ux -Name PauseQualityUpdatesStartTime -Value ((Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ'))
    Set-ItemProperty -Path $ux -Name PauseQualityUpdatesEndTime -Value ((Get-Date).AddYears(10).ToString('yyyy-MM-ddTHH:mm:ssZ'))
}

$taskPaths = @('\Microsoft\Windows\WindowsUpdate\', '\Microsoft\Windows\UpdateOrchestrator\')
foreach ($taskPath in $taskPaths) {
    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
        ForEach-Object {
            Disable-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue | Out-Null
        }
}

foreach ($name in @('wuauserv', 'UsoSvc', 'DoSvc', 'WaaSMedicSvc')) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    try {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $name -Force -ErrorAction Stop
        }
    } catch {
        Write-Warning "Could not stop ${name}: $_"
    }
    try {
        Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
        Write-Host "  Service disabled: $name"
    } catch {
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        if (Test-Path -LiteralPath $svcKey) {
            Set-ItemProperty -Path $svcKey -Name Start -Value 4 -Type DWord
            Write-Host "  Service start=disabled via registry: $name"
        } else {
            Write-Warning "Could not disable ${name}: $_"
        }
    }
}

Write-Host @'

Windows Update is disabled for this guest.

Do not enable it while quarantine networking is on — it will fail TLS
and is already blocked by the outbound firewall except via the proxy.

Next: shut down and run .\quarantine-vm.ps1 baseline on the host.
'@
