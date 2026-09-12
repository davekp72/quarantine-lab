#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  One-time elevated guest provisioning for a new quarantine lab VM.

.DESCRIPTION
  Host can restage binaries with:  .\quarantine-vm.ps1 guest provision
  FirstLogon (autounattend / setup ISO) already runs this script elevated once.
  Re-run elevated if needed:

    Set-ExecutionPolicy -Scope Process Bypass -Force
    & 'C:\Users\Public\Quarantine\Invoke-QuarantineGuestProvision.ps1'

  Runs whatever helpers were copied (agent, ACLs, gateway network, CA, Sysmon,
  event-log grant, autologon). Missing files are skipped so a partial stage still works.
#>
[CmdletBinding()]
param(
    [string]$PublicDir = 'C:\Users\Public\Quarantine',
    [string]$PayloadUser = '',
    [string]$LabAdmin = '',
    [ValidateSet('gateway')]
    [string]$NetworkMode = 'gateway'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process Bypass -Force

function Write-Prov {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "==> $Message" -ForegroundColor $Color
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw 'Run this script from an elevated PowerShell window in the guest (Run as administrator).'
}

$hintsPath = Join-Path $PublicDir 'guest-provision.json'
if (Test-Path -LiteralPath $hintsPath) {
    $hints = Get-Content -LiteralPath $hintsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $PayloadUser -and $hints.PSObject.Properties['payloadUser'] -and $hints.payloadUser) {
        $PayloadUser = [string]$hints.payloadUser
    }
    if (-not $LabAdmin -and $hints.PSObject.Properties['labAdmin'] -and $hints.labAdmin) {
        $LabAdmin = [string]$hints.labAdmin
    }
    if ($hints.PSObject.Properties['networkMode'] -and $hints.networkMode) {
        $NetworkMode = [string]$hints.networkMode
    }
}
if (-not $LabAdmin) { $LabAdmin = $env:USERNAME }
if (-not $PayloadUser) { $PayloadUser = 'analyst' }

$ran = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]
$failed = New-Object System.Collections.Generic.List[string]

function Invoke-ProvScript {
    param(
        [Parameter(Mandatory)][string]$Leaf,
        [hashtable]$NamedArgs = @{},
        [string]$SubDir = ''
    )
    $dir = $PublicDir
    if ($SubDir) { $dir = Join-Path $PublicDir $SubDir }
    $path = Join-Path $dir $Leaf
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Prov "SKIP $Leaf (not staged)" 'DarkYellow'
        [void]$skipped.Add($Leaf)
        return
    }
    Write-Prov $Leaf
    try {
        # Hashtable splat so -Mode gateway binds as a named parameter (array splat is positional).
        if ($NamedArgs.Count -gt 0) {
            & $path @NamedArgs
        } else {
            & $path
        }
        [void]$ran.Add($Leaf)
    } catch {
        $msg = [string]$_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = [string]$_ }
        Write-Host "FAILED $Leaf : $msg" -ForegroundColor Red
        [void]$failed.Add("$Leaf : $msg")
    }
}

function Protect-GuestControlAcl {
    $dataDir = 'C:\ProgramData\QuarantineLab'
    $tokenPath = Join-Path $dataDir 'agent-token.txt'
    $acct = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    $gcUser = Join-Path $dataDir 'guestcontrol.user'
    Set-Content -LiteralPath $gcUser -Value ($acct + [Environment]::NewLine) -Encoding ASCII -NoNewline
    $dirGrant = $acct + ':(OI)(CI)RX'
    $fileGrant = $acct + ':(RX)'
    $null = icacls.exe $dataDir /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' $dirGrant
    if (Test-Path -LiteralPath $tokenPath) {
        $null = icacls.exe $tokenPath /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' $fileGrant
    }
    Write-Prov "guestcontrol ACL for $acct" 'Green'
    [void]$ran.Add('guestcontrol-acl')
}

Write-Host ''
Write-Host 'Quarantine guest provision (elevated)' -ForegroundColor Green
Write-Host "  Public   : $PublicDir"
Write-Host "  Lab admin: $LabAdmin"
Write-Host "  Payload  : $PayloadUser"
Write-Host "  Network  : $NetworkMode"
Write-Host ''

Invoke-ProvScript -Leaf 'Disable-QuarantineAutoLogon.ps1'
Invoke-ProvScript -Leaf 'Disable-QuarantineGuestUpdates.ps1'
Invoke-ProvScript -Leaf 'Grant-QuarantineGuestEventLogAccess.ps1' -NamedArgs @{ LabAdmin = $LabAdmin }
Invoke-ProvScript -Leaf 'Configure-QuarantineGuestNetwork.ps1' -NamedArgs @{ Mode = $NetworkMode }
Invoke-ProvScript -Leaf 'Harden-QuarantineGuestNetwork.ps1' -NamedArgs @{ Mode = $NetworkMode; PayloadUser = $PayloadUser }

$ca = Join-Path $PublicDir 'mitmproxy-ca-cert.cer'
$caSplat = @{}
if (Test-Path -LiteralPath $ca) { $caSplat['CaPath'] = $ca }
Invoke-ProvScript -Leaf 'Install-QuarantineProxyCA.ps1' -NamedArgs $caSplat

$sysmonExe = Join-Path $PublicDir 'sysmon\Sysmon64.exe'
if (Test-Path -LiteralPath $sysmonExe) {
    Invoke-ProvScript -Leaf 'Install-QuarantineSysmon.ps1' -SubDir 'sysmon'
} else {
    Write-Prov 'SKIP Sysmon (Sysmon64.exe not staged — run .\scripts\Get-Sysmon.ps1 on the host and re-run guest provision)' 'DarkYellow'
    [void]$skipped.Add('Install-QuarantineSysmon.ps1')
}

$agentScript = Join-Path $PublicDir 'Install-QuarantineAgent.ps1'
$staging = Join-Path $PublicDir 'agent-staging'
$hasAgent = (Test-Path -LiteralPath $agentScript) -and (
    (Test-Path -LiteralPath (Join-Path $staging 'quarantine-agent.exe')) -or
    @(Get-ChildItem -LiteralPath $staging -Filter 'quarantine-agent*.exe' -ErrorAction SilentlyContinue).Count -gt 0 -or
    @(Get-ChildItem -LiteralPath $PublicDir -Filter 'quarantine-agent*.exe' -ErrorAction SilentlyContinue).Count -gt 0
)
if ($hasAgent) {
    Invoke-ProvScript -Leaf 'Install-QuarantineAgent.ps1'
} else {
    Write-Prov 'SKIP agent install (run host: .\quarantine-vm.ps1 agent install  then re-run this script)' 'DarkYellow'
    [void]$skipped.Add('Install-QuarantineAgent.ps1')
}

Protect-GuestControlAcl

Write-Host ''
Write-Host 'Provision summary' -ForegroundColor Green
if ($ran.Count -gt 0) { Write-Host ("  RAN    : " + ($ran -join ', ')) }
if ($skipped.Count -gt 0) { Write-Host ("  SKIPPED: " + ($skipped -join ', ')) -ForegroundColor DarkYellow }
if ($failed.Count -gt 0) {
    Write-Host ("  FAILED : " + ($failed -join ' | ')) -ForegroundColor Red
    throw 'Guest provision completed with failures. Fix the errors above and re-run this script.'
}

Write-Host ''
Write-Host 'On the host:' -ForegroundColor Yellow
Write-Host '  .\quarantine-vm.ps1 agent health'
Write-Host '  .\quarantine-vm.ps1 guest disable-autologon   # if Autologon step was skipped'
Write-Host 'Then shut down and: .\quarantine-vm.ps1 baseline'
Write-Output 'PROVISION_OK'
