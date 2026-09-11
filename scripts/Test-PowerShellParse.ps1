#Requires -Version 5.1
<#
.SYNOPSIS
  Parse every PowerShell script in the repo; optionally run PSScriptAnalyzer.
#>
[CmdletBinding()]
param(
    [string]$Root = '',
    [switch]$Analyze
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Root) {
    $Root = Split-Path -Parent $PSScriptRoot
}

$files = Get-ChildItem -LiteralPath $Root -Recurse -Include *.ps1, *.psm1, *.psd1 |
    Where-Object {
        $_.FullName -notmatch '[\\/]\.git[\\/]' -and
        $_.FullName -notmatch '[\\/]\.venv[\\/]' -and
        $_.Name -ne 'PSScriptAnalyzerSettings.psd1'
    }

$parseFailed = 0
foreach ($f in $files) {
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        $parseFailed++
        Write-Host "PARSE FAIL $($f.FullName)" -ForegroundColor Red
        $errs | ForEach-Object { Write-Host "  $($_.Message) ($($_.Extent.StartLineNumber))" }
    }
}

if ($parseFailed -gt 0) {
    throw "$parseFailed PowerShell file(s) failed to parse"
}
Write-Host "Parsed $($files.Count) PowerShell files."

if (-not $Analyze) { return }

$settings = Join-Path $Root 'PSScriptAnalyzerSettings.psd1'
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Install-Module PSScriptAnalyzer -Force -Scope CurrentUser -SkipPublisherCheck
}
Import-Module PSScriptAnalyzer -Force

$raw = @(Invoke-ScriptAnalyzer -Path $Root -Recurse -Settings $settings -ErrorAction SilentlyContinue)
$issues = @($raw | Where-Object {
        $_ -and $_.ScriptPath -notmatch '[\\/]\.venv[\\/]' -and
        $_.ScriptPath -notmatch '[\\/]\.git[\\/]'
    })

$errorCount = @($issues | Where-Object { $_.Severity -eq 'Error' }).Count
$issues | Sort-Object Severity, ScriptName, Line | ForEach-Object {
    Write-Host ("{0,-8} {1}:{2} {3} {4}" -f $_.Severity, $_.ScriptName, $_.Line, $_.RuleName, $_.Message)
}

if ($errorCount -gt 0) {
    throw "PSScriptAnalyzer reported $errorCount error(s)"
}
Write-Host "PSScriptAnalyzer: 0 errors ($($issues.Count) remaining findings after settings)."
