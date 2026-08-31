#Requires -Version 5.1
<#
.SYNOPSIS
  Parse Regshot 1.8/1.9 text compare logs into manifest diff registry shape.
#>
Set-StrictMode -Version Latest

function ConvertTo-RegshotNormalizedKey {
    param([string]$Key)

    $k = $Key.Trim()
    if ([string]::IsNullOrWhiteSpace($k)) { return '' }
    $k = $k -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\'
    $k = $k -replace '^HKEY_CURRENT_USER\\', 'HKCU\'
    $k = $k -replace '^HKEY_USERS\\', 'HKU\'
    $k = $k -replace '^HKEY_CLASSES_ROOT\\', 'HKCR\'
    return $k
}

function Get-RegshotSectionKind {
    param([string]$Line)

    $t = $Line.Trim().ToLowerInvariant()
    if ($t -match 'registry deleted|keys deleted|values deleted|reg deleted') { return 'removed' }
    if ($t -match 'registry added|keys added|values added|reg added') { return 'added' }
    if ($t -match 'registry modified|values modified|reg modified') { return 'modified' }
    return $null
}

function Test-RegshotRegistryKeyLine {
    param([string]$Line)

    $t = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { return $false }
    return ($t -match '^(HKLM|HKCU|HKU|HKCR|HKEY_)')
}

function Split-RegshotValueLine {
    param(
        [string]$Line,
        [string]$DefaultKey
    )

    $t = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }

    if ($t -match '^(.+?):\s*(.+)$') {
        return [pscustomobject]@{
            key   = $DefaultKey
            name  = $Matches[1].Trim()
            value = $Matches[2].Trim()
            type  = 'REG_SZ'
        }
    }

    if ($t -match '^(.+?)\s{2,}(.+)$') {
        return [pscustomobject]@{
            key   = $DefaultKey
            name  = $Matches[1].Trim()
            value = $Matches[2].Trim()
            type  = 'REG_SZ'
        }
    }

    if ($t -match '^@:\s*(.+)$') {
        return [pscustomobject]@{
            key   = $DefaultKey
            name  = '(Default)'
            value = $Matches[1].Trim()
            type  = 'REG_SZ'
        }
    }

    return [pscustomobject]@{
        key   = $DefaultKey
        name  = $t
        value = ''
        type  = 'REG_SZ'
    }
}

function ConvertFrom-RegshotCompareLog {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Regshot log not found: $Path"
    }

    $added = New-Object System.Collections.Generic.List[object]
    $removed = New-Object System.Collections.Generic.List[object]
    $modified = New-Object System.Collections.Generic.List[object]

    $section = $null
    $currentKey = ''
    $pendingMod = $null

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ($line -match '^-{5,}') {
            $section = $null
            continue
        }

        $kind = Get-RegshotSectionKind -Line $line
        if ($kind) {
            $section = $kind
            $currentKey = ''
            $pendingMod = $null
            continue
        }

        if ($section -notin @('added', 'removed', 'modified')) { continue }
        if ($line -match '^(Files|Folders|Total|Comments|Computer|User|DateTime)\b') { continue }

        if (Test-RegshotRegistryKeyLine -Line $line) {
            $currentKey = ConvertTo-RegshotNormalizedKey -Key $line
            if ($section -eq 'removed') {
                $removed.Add([pscustomobject]@{
                    key   = $currentKey
                    name  = '(key)'
                    type  = 'REG_KEY'
                    value = ''
                })
            } elseif ($section -eq 'added') {
                $added.Add([pscustomobject]@{
                    key   = $currentKey
                    name  = '(key)'
                    type  = 'REG_KEY'
                    value = ''
                })
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($currentKey)) { continue }

        if ($section -eq 'modified') {
            if ($line -match '^\s*old:\s*(.*)$') {
                $pendingMod = @{ key = $currentKey; fromValue = $Matches[1].Trim() }
                continue
            }
            if ($line -match '^\s*new:\s*(.*)$' -and $pendingMod) {
                $modified.Add([pscustomobject]@{
                    key       = $pendingMod.key
                    name      = if ($pendingMod.name) { $pendingMod.name } else { '(value)' }
                    fromValue = $pendingMod.fromValue
                    toValue   = $Matches[1].Trim()
                })
                $pendingMod = $null
                continue
            }
            $val = Split-RegshotValueLine -Line $line -DefaultKey $currentKey
            if ($line -match '->') {
                $parts = $line -split '->', 2
                $modified.Add([pscustomobject]@{
                    key       = $currentKey
                    name      = $val.name
                    fromValue = ($parts[0].Trim() -replace '^[^:]+:\s*', '')
                    toValue   = $parts[1].Trim()
                })
            } else {
                $pendingMod = @{ key = $currentKey; name = $val.name; fromValue = $val.value }
            }
            continue
        }

        $entry = Split-RegshotValueLine -Line $line -DefaultKey $currentKey
        if ($section -eq 'added') {
            $added.Add([pscustomobject]@{
                key   = $entry.key
                name  = $entry.name
                type  = $entry.type
                value = $entry.value
            })
        } else {
            $removed.Add([pscustomobject]@{
                key   = $entry.key
                name  = $entry.name
                type  = $entry.type
                value = $entry.value
            })
        }
    }

    return [pscustomobject]@{
        added    = @($added)
        removed  = @($removed)
        modified = @($modified)
        source   = $Path
        engine   = 'regshot'
    }
}
