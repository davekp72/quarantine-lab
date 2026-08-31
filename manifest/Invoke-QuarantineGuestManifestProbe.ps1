#Requires -Version 5.1
<#
.SYNOPSIS
  Diagnostic probe for manifest capture prerequisites (run inside guest).
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Test-Probe {
    param([string]$Name, [scriptblock]$Block)
    try {
        $result = & $Block
        Write-Output "PROBE_OK $Name $result"
    } catch {
        Write-Output "PROBE_FAIL $Name $($_.Exception.Message)"
    }
}

Write-Output "PROBE_WHOAMI $((whoami.exe 2>&1 | Out-String).Trim())"

Test-Probe 'sysmon_inline' {
    $null = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
    $svc = Get-Service -Name Sysmon64 -ErrorAction Stop
    "log=ok service=$($svc.Status)"
}

Test-Probe 'usn_read_filtered' {
    $baseline = 'C:\Users\Public\Quarantine\usn-baseline.json'
    if (-not (Test-Path -LiteralPath $baseline)) { throw 'no baseline file' }
    $b = Get-Content -LiteralPath $baseline -Raw | ConvertFrom-Json
    $start = [string]$b.startUsn
    $raw = & fsutil.exe usn readjournal C: csv "startusn=$start" 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($raw -join ' ') }
    "startUsn=$start"
}

Write-Output 'PROBE_DONE'
