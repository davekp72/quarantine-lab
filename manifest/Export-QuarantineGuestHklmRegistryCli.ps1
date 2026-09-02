#Requires -Version 5.1
<#
.SYNOPSIS
  Export HKLM registry subtrees via reg.exe (SYSTEM / elevated context).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutDir,
    [string]$OutMetaFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
if (-not (Test-Path -LiteralPath $regExe)) {
    throw "reg.exe not found: $regExe"
}

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$keys = @(
    'HKLM\Software\QuarantineLab',
    'HKLM\Software\Microsoft\Windows\CurrentVersion',
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion',
    'HKLM\Software\Microsoft\Windows NT\CurrentVersion',
    'HKLM\SYSTEM\CurrentControlSet\Services',
    'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager',
    'HKLM\Software\Oracle\VirtualBox Guest Additions'
)

$regFiles = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]

foreach ($key in $keys) {
    $safeName = ($key -replace '[\\:*?"<>|]', '_')
    $outFile = Join-Path $OutDir "hklm-$safeName.reg"
    if (Test-Path -LiteralPath $outFile) {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }

    $procExit = 0
    try {
        & $regExe export $key $outFile /y 2>&1 | Out-Null
        $procExit = $LASTEXITCODE
    } catch {
        $procExit = 1
        [void]$errors.Add("reg export $key failed: $($_.Exception.Message)")
    }

    if ($procExit -eq 0 -and (Test-Path -LiteralPath $outFile)) {
        $regFiles.Add($outFile) | Out-Null
    } else {
        [void]$errors.Add("reg export $key exit $procExit")
    }
}

$meta = [ordered]@{
    engine     = 'cli'
    scope      = 'hklm'
    capturedAt = (Get-Date).ToUniversalTime().ToString('o')
    computerName = $env:COMPUTERNAME
    regFiles   = $regFiles.ToArray()
    errors     = $errors.ToArray()
}

if ([string]::IsNullOrWhiteSpace($OutMetaFile)) {
    $OutMetaFile = Join-Path $OutDir 'hklm-registry-meta.json'
}

$meta | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutMetaFile -Encoding UTF8
Write-Output "HKLM registry CLI export -> $($regFiles.Count) reg file(s)"
