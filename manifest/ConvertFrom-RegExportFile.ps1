#Requires -Version 5.1
<#
.SYNOPSIS
  Parse Windows reg.exe export (.reg) files into quarantine manifest registry entries.
#>
Set-StrictMode -Version Latest

function Get-StringHash {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-RegExportManifestKey {
    param(
        [Parameter(Mandatory)][string]$RegKey,
        [Parameter(Mandatory)][string]$Sid
    )

    $key = $RegKey.Trim()
    if ($key -match '^HKEY_CURRENT_USER\\(.+)$') {
        return "HKU:\$Sid\$($Matches[1])"
    }
    if ($key -match '^HKCU\\(.+)$') {
        return "HKU:\$Sid\$($Matches[1])"
    }
    if ($key -match '^HKEY_USERS\\(.+)$') {
        return "HKU:\$($Matches[1])"
    }
    if ($key -match '^HKU\\(.+)$') {
        return "HKU:\$($Matches[1])"
    }
    if ($key -match '^HKEY_LOCAL_MACHINE\\(.+)$') {
        return "HKLM:\$($Matches[1])"
    }
    if ($key -match '^HKLM\\(.+)$') {
        return "HKLM:\$($Matches[1])"
    }
    return $key
}

function ConvertFrom-RegExportValue {
    param(
        [Parameter(Mandatory)][string]$RawValue
    )

    $raw = $RawValue.Trim()
    if ($raw.StartsWith('"') -and $raw.EndsWith('"')) {
        $text = $raw.Substring(1, $raw.Length - 2) -replace '\\"', '"'
        return [pscustomobject]@{ Type = 'String'; Value = $text }
    }
    if ($raw -match '^dword:(.+)$') {
        $hex = $Matches[1].Trim()
        try {
            $num = [Convert]::ToUInt32($hex, 16)
            return [pscustomobject]@{ Type = 'DWord'; Value = [string]$num }
        } catch {
            return [pscustomobject]@{ Type = 'DWord'; Value = $hex }
        }
    }
    if ($raw -match '^hex(?:\((\d+)\))?:(.+)$') {
        $kind = if ($Matches[1]) { "Binary($($Matches[1]))" } else { 'Binary' }
        $hexBody = ($Matches[2] -replace '\\\s*[\r\n]+', '' -replace '\s', '').ToLowerInvariant()
        if ($hexBody.Length -gt 256) { $hexBody = $hexBody.Substring(0, 256) }
        return [pscustomobject]@{ Type = $kind; Value = $hexBody }
    }
    if ($raw -match '^hex\(7\):(.+)$') {
        $hexBody = ($Matches[1] -replace '\\\s*[\r\n]+', '' -replace '\s', '')
        $bytes = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $hexBody.Length; $i += 2) {
            if ($i + 1 -ge $hexBody.Length) { break }
            $bytes.Add([Convert]::ToByte($hexBody.Substring($i, 2), 16)) | Out-Null
        }
        $text = [System.Text.Encoding]::Unicode.GetString($bytes.ToArray()).TrimEnd([char]0)
        if ($text.Length -gt 512) { $text = $text.Substring(0, 512) }
        return [pscustomobject]@{ Type = 'MultiString'; Value = $text }
    }
    return [pscustomobject]@{ Type = 'String'; Value = $raw }
}

function Read-RegExportFileText {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function ConvertFrom-RegExportFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sid,
        [string]$UserName = ''
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Reg export file not found: $Path"
    }

    $text = Read-RegExportFileText -Path $Path
    $lines = $text -split '\r?\n'
    $entries = New-Object System.Collections.Generic.List[object]
    $currentKey = $null
    $pendingValueLine = $null

    foreach ($line in $lines) {
        if ($null -ne $pendingValueLine) {
            if ($line -match '\\\s*$') {
                $pendingValueLine += ($line.TrimEnd('\').Trim())
                continue
            }
            $line = $pendingValueLine + $line
            $pendingValueLine = $null
        }

        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -match '^Windows Registry Editor Version') { continue }
        if ($trimmed -match '^\[(.+)\]$') {
            $currentKey = ConvertTo-RegExportManifestKey -RegKey $Matches[1] -Sid $Sid
            continue
        }
        if (-not $currentKey) { continue }

        if ($trimmed -match '^@=(.+)$') {
            $parsed = ConvertFrom-RegExportValue -RawValue $Matches[1]
            $val = [string]$parsed.Value
            $entries.Add([pscustomobject][ordered]@{
                k = $currentKey
                n = '(Default)'
                t = [string]$parsed.Type
                v = $val
                h = (Get-StringHash $val)
            }) | Out-Null
            continue
        }

        if ($trimmed -match '^"([^"]+)"=(.+)$') {
            $name = $Matches[1]
            $rawVal = $Matches[2]
            if ($rawVal -match '\\\s*$') {
                $pendingValueLine = "`"$name`"=$rawVal"
                continue
            }
            $parsed = ConvertFrom-RegExportValue -RawValue $rawVal
            $val = [string]$parsed.Value
            $entries.Add([pscustomobject][ordered]@{
                k = $currentKey
                n = $name
                t = [string]$parsed.Type
                v = $val
                h = (Get-StringHash $val)
            }) | Out-Null
        }
    }

    return [pscustomobject]@{
        userName   = $UserName
        sid        = $Sid
        sourceFile = $Path
        entryCount = $entries.Count
        registry   = $entries.ToArray()
    }
}
