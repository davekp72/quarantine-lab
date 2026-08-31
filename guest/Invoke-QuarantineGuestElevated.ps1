#Requires -Version 5.1
<#
.SYNOPSIS
  Run a PowerShell script in the guest with highest available token (schtasks).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ScriptPath,

    [string[]]$ScriptArguments = @(),

    [string]$OutFile = '',

    [int]$TimeoutSeconds = 600,

    [string]$TaskUser = '',

    [string]$TaskPassword = '',

    [string]$CredentialFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-SchtasksSilently {
    param([string]$ArgumentString)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'schtasks.exe'
    $psi.Arguments = $ArgumentString
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Script not found: $ScriptPath"
}

if ($CredentialFile -and (Test-Path -LiteralPath $CredentialFile)) {
    try {
        $cred = Get-Content -LiteralPath $CredentialFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cred.user) { $TaskUser = [string]$cred.user }
        if ($cred.password) { $TaskPassword = [string]$cred.password }
    } finally {
        Remove-Item -LiteralPath $CredentialFile -Force -ErrorAction SilentlyContinue
    }
}

if ($OutFile) {
    $ScriptArguments = @('-OutFile', $OutFile) + @($ScriptArguments)
}

if ([string]::IsNullOrWhiteSpace($TaskUser)) {
    $TaskUser = "$env:USERDOMAIN\$env:USERNAME"
}
if ($TaskUser -notmatch '\\') {
    $TaskUser = "$env:COMPUTERNAME\$TaskUser"
}

$taskName = "QuarantineElevated-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$argText = ($ScriptArguments | ForEach-Object {
    if ($_ -match '\s|"') { '"{0}"' -f ($_ -replace '"', '""') } else { $_ }
}) -join ' '

$trCommand = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
if ($argText) { $trCommand += " $argText" }

$startDate = (Get-Date).ToString('dd/MM/yyyy')
$startTime = (Get-Date).AddMinutes(2).ToString('HH:mm')

try {
    $createArgs = "/Create /TN `"$taskName`" /TR `"$trCommand`" /SC ONCE /ST $startTime /SD $startDate /RU `"$TaskUser`" /RL HIGHEST /F"
    if (-not [string]::IsNullOrWhiteSpace($TaskPassword)) {
        $createArgs += " /RP `"$TaskPassword`""
    }

    $create = Invoke-SchtasksSilently -ArgumentString $createArgs
    if ($create.ExitCode -ne 0 -and $create.StdOut -notmatch 'SUCCESS') {
        throw "schtasks /Create failed ($($create.ExitCode)): $($create.StdOut) $($create.StdErr)"
    }

    $run = Invoke-SchtasksSilently -ArgumentString "/Run /TN `"$taskName`""
    if ($run.ExitCode -ne 0 -and $run.StdOut -notmatch 'SUCCESS') {
        throw "schtasks /Run failed ($($run.ExitCode)): $($run.StdOut) $($run.StdErr)"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastResult = 267009
    do {
        Start-Sleep -Milliseconds 750
        $query = Invoke-SchtasksSilently -ArgumentString "/Query /TN `"$taskName`" /FO LIST /V"
        if ($query.ExitCode -ne 0) { continue }
        $text = $query.StdOut
        if ($text -match 'Last Run Result:\s+(\d+)') {
            $lastResult = [int]$Matches[1]
        } elseif ($text -match 'Last Result:\s+(\d+)') {
            $lastResult = [int]$Matches[1]
        }
        if ($text -match 'Status:\s+Ready' -and $lastResult -ne 267009) { break }
    } while ((Get-Date) -lt $deadline)

    if ($OutFile -and -not (Test-Path -LiteralPath $OutFile)) {
        throw "Elevated script did not create output: $OutFile (task result $lastResult)"
    }
    if ($lastResult -ne 0) {
        throw "Elevated task last result $lastResult"
    }

    Write-Output "ELEVATED_OK $ScriptPath"
} finally {
    $null = Invoke-SchtasksSilently -ArgumentString "/Delete /TN `"$taskName`" /F"
}
