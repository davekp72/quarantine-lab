#Requires -Version 5.1
<#
.SYNOPSIS
  Run RegShot CMD inside the guest (1st shot save or compare vs saved .hivu).
#>
[CmdletBinding()]
param(
    [ValidateSet('Shot', 'Compare')]
    [string]$Action = 'Shot',

    [Parameter(Mandatory)]
    [string]$BaselineHive,

    [string]$RegshotDir = 'C:\Users\Public\Quarantine\regshot',
    [string]$OutLog = '',
    [int]$TimeoutSec = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RegshotCmdExe {
    param([string]$Dir)

    $names = @(
        'Regshot_cmd-x64-Unicode.exe',
        'Regshot_cmd-x64-ANSI.exe',
        'RegShot_CMD.exe',
        'Regshot_cmd-x86-Unicode.exe',
        'Regshot_cmd-x86-ANSI.exe'
    )
    foreach ($name in $names) {
        $path = Join-Path $Dir $name
        if (Test-Path -LiteralPath $path) { return $path }
    }

    $guiOnly = @('Regshot-x64-Unicode.exe', 'Regshot-x64-ANSI.exe', 'Regshot-x86-Unicode.exe', 'Regshot-x86-ANSI.exe')
    foreach ($name in $guiOnly) {
        if (Test-Path -LiteralPath (Join-Path $Dir $name)) {
            throw @"
Found GUI Regshot ($name) but not RegShot CMD. Automated manifest capture requires Regshot_cmd-x64-ANSI.exe from:
  https://sourceforge.net/projects/regshot/files/regcmd/
Place it in tools/regshot/ then run .\quarantine-vm.ps1 regshot copy
"@
        }
    }
    throw "RegShot CMD not found in $Dir. See tools/regshot/README.md"
}

function Get-NewestRegshotCompareLog {
    param([string[]]$SearchDirs)

    $found = @()
    foreach ($dir in $SearchDirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $found += Get-ChildItem -LiteralPath $dir -Filter '~res*.txt' -File -ErrorAction SilentlyContinue
    }
    if ($found.Count -eq 0) { return $null }
    return ($found | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
}

$cmd = Resolve-RegshotCmdExe -Dir $RegshotDir
$hiveDir = Split-Path -Parent $BaselineHive
if ($hiveDir -and -not (Test-Path -LiteralPath $hiveDir)) {
    New-Item -ItemType Directory -Path $hiveDir -Force | Out-Null
}

if (-not $BaselineHive.EndsWith('.hivu', [System.StringComparison]::OrdinalIgnoreCase)) {
    $BaselineHive = "$BaselineHive.hivu"
}

Push-Location $RegshotDir
try {
    if ($Action -eq 'Shot') {
        if (Test-Path -LiteralPath $BaselineHive) {
            Remove-Item -LiteralPath $BaselineHive -Force
        }
        Write-Output "REGSHOT_SHOT_START $BaselineHive"
        $proc = Start-Process -FilePath $cmd -ArgumentList @($BaselineHive) -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            throw "Regshot shot failed (exit $($proc.ExitCode))."
        }
        if (-not (Test-Path -LiteralPath $BaselineHive)) {
            throw "Regshot shot did not create: $BaselineHive"
        }
        Write-Output "REGSHOT_SHOT_OK $BaselineHive"
        return
    }

    if (-not (Test-Path -LiteralPath $BaselineHive)) {
        throw "Baseline hive missing: $BaselineHive"
    }

    $before = Get-NewestRegshotCompareLog -SearchDirs @(
        (Join-Path $env:SystemRoot 'System32'),
        (Join-Path $RegshotDir 'logs'),
        $RegshotDir
    )

    Write-Output "REGSHOT_COMPARE_START $BaselineHive"
    $proc = Start-Process -FilePath $cmd -ArgumentList @($BaselineHive, '-C') -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "Regshot compare failed (exit $($proc.ExitCode))."
    }

    Start-Sleep -Seconds 2
    $after = Get-NewestRegshotCompareLog -SearchDirs @(
        (Join-Path $env:SystemRoot 'System32'),
        (Join-Path $RegshotDir 'logs'),
        $RegshotDir
    )

    $logFile = $null
    if ($after -and (-not $before -or $after.FullName -ne $before.FullName -or $after.LastWriteTime -gt $before.LastWriteTime)) {
        $logFile = $after
    } elseif ($after) {
        $logFile = $after
    }

    if (-not $logFile) {
        throw 'Regshot compare finished but no ~res*.txt log was found under System32 or regshot logs.'
    }

    if ([string]::IsNullOrWhiteSpace($OutLog)) {
        $OutLog = Join-Path $RegshotDir 'regshot-compare.txt'
    }
    $outDir = Split-Path -Parent $OutLog
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $logFile.FullName -Destination $OutLog -Force
    Write-Output "REGSHOT_COMPARE_OK $OutLog"
} finally {
    Pop-Location
}
