#Requires -Version 5.1
<#
.SYNOPSIS
  Record the current NTFS USN journal position as a change baseline (run in guest at test start).
#>
[CmdletBinding()]
param(
    [string]$Volume = 'C:',
    [string]$OutFile = 'C:\Users\Public\Quarantine\usn-baseline.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-UsnJournalInfo {
    param([string]$Vol)

    $raw = & fsutil.exe usn queryjournal $Vol 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "fsutil usn queryjournal failed: $($raw -join ' ')"
    }

    $info = [ordered]@{}
    foreach ($line in $raw) {
        if ($line -match '^\s*([^:]+)\s*:\s*(.+)$') {
            $key = ($Matches[1].Trim() -replace '\s+', '')
            $info[$key] = $Matches[2].Trim()
        }
    }
    return [pscustomobject]$info
}

$journal = Get-UsnJournalInfo -Vol $Volume
$baseline = [ordered]@{
    version    = 1
    volume     = $Volume
    recordedAt = (Get-Date).ToUniversalTime().ToString('o')
    journalId  = $journal.UsnJournalID
    startUsn   = $journal.NextUsn
    firstUsn   = $journal.FirstUsn
    computer   = $env:COMPUTERNAME
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$baseline | ConvertTo-Json -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "USN_BASELINE_WRITTEN $OutFile startUsn=$($journal.NextUsn)"
