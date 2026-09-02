#Requires -Version 5.1
<#
.SYNOPSIS
  Launcher for the Go quarantine binary (replaces quarantine-vm.ps1 over time).
.NOTES
  Wails build\bin\quarantine.exe is the GUI build (used for ui / manifest view).
  go\quarantine.exe is the console CLI build (agent health, start, snapshots, etc.).
  Rebuilds automatically when source files are newer than the binary (or missing).
  Pass -Rebuild to force a rebuild regardless of timestamps.
#>
param(
    [switch]$Rebuild,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$config = Join-Path $root 'config\quarantine-vm.json'

$wailsExe = Join-Path $root 'go\cmd\quarantine\build\bin\quarantine.exe'
$cliExe = Join-Path $root 'go\quarantine.exe'
$agentExe = Join-Path $root 'go\quarantine-agent.exe'
$wailsDir = Join-Path $root 'go\cmd\quarantine'
$goRoot = Join-Path $root 'go'

$script:SourceExtensions = @('.go', '.html', '.js', '.css', '.json', '.mod', '.sum')

function Test-SourcePathExcluded {
    param([string]$FullName)
    $n = $FullName -replace '/', '\'
    return ($n -match '\\build\\|\\node_modules\\|\\wailsjs\\|\\\.git\\')
}

function Get-LatestSourceWriteTime {
    param([string[]]$Roots)
    $latest = [datetime]::MinValue
    foreach ($rootPath in $Roots) {
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $script:SourceExtensions -contains $_.Extension -and
                -not (Test-SourcePathExcluded $_.FullName)
            } |
            ForEach-Object {
                if ($_.LastWriteTime -gt $latest) { $latest = $_.LastWriteTime }
            }
    }
    return $latest
}

function Test-BinaryStale {
    param(
        [string]$ExePath,
        [string[]]$SourceRoots
    )
    if (-not (Test-Path -LiteralPath $ExePath)) {
        return $true
    }
    $srcTime = Get-LatestSourceWriteTime -Roots $SourceRoots
    if ($srcTime -eq [datetime]::MinValue) {
        return $false
    }
    return $srcTime -gt (Get-Item -LiteralPath $ExePath).LastWriteTime
}

function Get-CliSourceRoots {
    return @($goRoot)
}

function Get-WailsSourceRoots {
    return @(
        (Join-Path $goRoot 'cmd\quarantine')
        (Join-Path $goRoot 'internal')
    )
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )
    & $Command[0] @($Command[1..($Command.Count - 1)]) 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $($Command -join ' ')"
    }
}

function Ensure-CliBinary {
    param([switch]$Force)
    $sources = Get-CliSourceRoots
    $needCli = $Force -or (Test-BinaryStale -ExePath $cliExe -SourceRoots $sources)
    $needAgent = $Force -or (Test-BinaryStale -ExePath $agentExe -SourceRoots $sources)
    if (-not $needCli -and -not $needAgent) {
        return
    }
    Push-Location $goRoot
    try {
        if ($needCli) {
            Write-Host 'Building quarantine.exe (CLI console binary)...'
            Invoke-NativeCommand @('go', 'build', '-o', 'quarantine.exe', './cmd/quarantine')
        }
        if ($needAgent) {
            Write-Host 'Building quarantine-agent.exe...'
            Invoke-NativeCommand @('go', 'build', '-o', 'quarantine-agent.exe', './cmd/quarantine-agent')
        }
    } finally {
        Pop-Location
    }
}

function Build-WailsBinary {
    Write-Host 'Building Wails UI (go\cmd\quarantine\build\bin\quarantine.exe)...'
    Push-Location $wailsDir
    try {
        Invoke-NativeCommand @('wails', 'build')
    } finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $wailsExe)) {
        throw 'Wails build did not produce build\bin\quarantine.exe'
    }
}

function Ensure-WailsBinary {
    param([switch]$Force)
    $sources = Get-WailsSourceRoots
    if ($Force -or (Test-BinaryStale -ExePath $wailsExe -SourceRoots $sources)) {
        if (-not $Force -and (Test-Path -LiteralPath $wailsExe)) {
            Write-Host 'Wails UI is stale — rebuilding...'
        }
        Build-WailsBinary | Out-Null
    }
    return ,$wailsExe
}

function Test-UseWailsBinary {
    param([string[]]$SubCommands)
    if ($null -eq $SubCommands -or $SubCommands.Count -eq 0) {
        return $false
    }
    switch ($SubCommands[0]) {
        'ui' { return $true }
        'manifest' {
            return ($SubCommands.Count -ge 2 -and $SubCommands[1] -eq 'view')
        }
        default { return $false }
    }
}

$wantWails = Test-UseWailsBinary -SubCommands $CommandArgs

if ($wantWails) {
    $exe = Ensure-WailsBinary -Force:$Rebuild
} else {
    Ensure-CliBinary -Force:$Rebuild
    $exe = $cliExe
}

& (Get-Item -LiteralPath $exe).FullName --config $config @CommandArgs
exit $LASTEXITCODE
