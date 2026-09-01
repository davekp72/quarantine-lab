#Requires -Version 5.1
<#
.SYNOPSIS
  Guest-side probe for the SYSTEM privileged-export polling task (always exit 0).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$marker = 'C:\Users\Public\Quarantine\privileged-export-task.ok'
if (Test-Path -LiteralPath $marker) {
    Write-Output 'PRIV_TASK_OK'
} else {
    Write-Output 'PRIV_TASK_MISSING'
}
exit 0
