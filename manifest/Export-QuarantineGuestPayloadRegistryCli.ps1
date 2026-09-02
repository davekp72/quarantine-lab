#Requires -Version 5.1
<#
.SYNOPSIS
  Export payload-user registry via reg.exe (live session context).
  Run via guest control as the standard test user (e.g. jkcooper), not the lab admin.
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

$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$userName = $env:USERNAME

$keys = @(
    'HKCU\Software',
    'HKCU\Environment',
    'HKCU\Volatile Environment',
    'HKCU\Console',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$regFiles = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]

foreach ($key in $keys) {
    $safeName = ($key -replace '[\\:*?"<>|]', '_')
    $outFile = Join-Path $OutDir "payload-$safeName.reg"
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
    capturedAt = (Get-Date).ToUniversalTime().ToString('o')
    userName   = $userName
    sid        = $sid
    regFiles   = $regFiles.ToArray()
    errors     = $errors.ToArray()
}

if ([string]::IsNullOrWhiteSpace($OutMetaFile)) {
    $OutMetaFile = Join-Path $OutDir 'payload-registry-meta.json'
}

$meta | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutMetaFile -Encoding UTF8
Write-Output "Payload registry CLI export: $userName ($sid) -> $($regFiles.Count) reg file(s)"
