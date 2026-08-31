#Requires -Version 5.1

<#

.SYNOPSIS

  Export NTFS USN journal records since the guest baseline (requires elevation).

#>

[CmdletBinding()]

param(

    [string]$BaselineFile = 'C:\Users\Public\Quarantine\usn-baseline.json',

    [string]$Volume = 'C:',

    [int]$MaxEvents = 50000,

    [string]$OutFile = ''

)



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'

$privModule = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'QuarantineGuestPriv.psm1'
if (Test-Path -LiteralPath $privModule) {
    Import-Module $privModule -Force
    Enable-QuarantineManifestReadPrivileges
}



function Get-UsnJournalInfo {

    param([string]$Vol)

    $raw = & fsutil.exe usn queryjournal $Vol 2>&1

    if ($LASTEXITCODE -ne 0) { return $null }

    $info = @{}

    foreach ($line in $raw) {

        if ($line -match '^\s*([^:]+)\s*:\s*(.+)$') {

            $info[($Matches[1].Trim() -replace '\s+', '')] = $Matches[2].Trim()

        }

    }

    return $info

}



function ConvertFrom-HexUsn {

    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $v = $Value.Trim()

    if ($v.StartsWith('0x')) { return [uint64]::Parse($v.Substring(2), 'AllowHexSpecifier') }

    return [uint64]::Parse($v, 'AllowHexSpecifier')

}



function Get-UsnReasonLabels {

    param([string]$ReasonHex)

    $labels = New-Object System.Collections.Generic.List[string]

    try {

        $reason = [uint32]::Parse($ReasonHex.Trim().Replace('0x', ''), 'AllowHexSpecifier')

    } catch {

        return @($ReasonHex)

    }



    $map = [ordered]@{

        0x00000001 = 'data_extend'

        0x00000002 = 'data_truncation'

        0x00000004 = 'named_data_overwrite'

        0x00000010 = 'data_overwrite'

        0x00000100 = 'file_create'

        0x00000200 = 'file_delete'

        0x00000400 = 'ea_change'

        0x00000800 = 'security_change'

        0x00001000 = 'rename_old_name'

        0x00002000 = 'rename_new_name'

        0x00004000 = 'indexable_change'

        0x00008000 = 'basic_info_change'

        0x00010000 = 'hard_link_change'

        0x00020000 = 'compression_change'

        0x00080000 = 'reparse_point_change'

        0x00100000 = 'stream_change'

        0x00200000 = 'close'

    }



    foreach ($entry in $map.GetEnumerator()) {

        if (($reason -band $entry.Key) -ne 0) { [void]$labels.Add($entry.Value) }

    }

    if ($labels.Count -eq 0) { [void]$labels.Add($ReasonHex) }

    return @($labels)

}



function Export-QuarantineGuestUsnDelta {

    param(

        [string]$BaselineFilePath,

        [string]$VolumePath,

        [int]$MaxEventCount

    )



    $events = New-Object System.Collections.Generic.List[object]



    if (-not (Test-Path -LiteralPath $BaselineFilePath)) {

        return [pscustomobject]@{

            available  = $false

            eventCount = 0

            message    = 'No USN baseline - run manifest mark after snapshot restore to track all file changes on C:.'

            events     = @()

        }

    }



    try {

        $baseline = Get-Content -LiteralPath $BaselineFilePath -Raw -Encoding UTF8 | ConvertFrom-Json

        $startUsn = [string]$baseline.startUsn

        if ([string]::IsNullOrWhiteSpace($startUsn)) {

            throw 'Baseline missing startUsn.'

        }



        if ($baseline.volume) { $VolumePath = [string]$baseline.volume }



        $current = Get-UsnJournalInfo -Vol $VolumePath

        if (-not $current) {

            throw 'Could not query USN journal (admin required?).'

        }



        $endUsn = [string]$current.NextUsn

        $startVal = ConvertFrom-HexUsn -Value $startUsn

        $endVal = ConvertFrom-HexUsn -Value $endUsn



        if ($null -ne $startVal -and $null -ne $endVal -and $endVal -le $startVal) {

            return [pscustomobject]@{

                available  = $true

                eventCount = 0

                volume     = $VolumePath

                startUsn   = $startUsn

                endUsn     = $endUsn

                recordedAt = (Get-Date).ToUniversalTime().ToString('o')

                message    = 'No USN activity since baseline.'

                events     = @()

            }

        }



        $fsArgs = @('usn', 'readjournal', $VolumePath, 'csv', "startusn=$startUsn")

        $lines = & fsutil.exe @fsArgs 2>&1

        if ($LASTEXITCODE -ne 0) {

            throw "fsutil usn readjournal failed: $($lines -join ' ')"

        }



        $header = $null

        foreach ($line in $lines) {

            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            if ($line -match '^Major Version,') { $header = $line; continue }

            if (-not $header) { continue }



            $cols = $line -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)'

            if ($cols.Count -lt 12) { continue }



            $fileName = $cols[11].Trim('"')

            if ([string]::IsNullOrWhiteSpace($fileName)) { continue }



            $reasonLabels = Get-UsnReasonLabels -ReasonHex $cols[6].Trim('"')

            [void]$events.Add([pscustomobject][ordered]@{

                usn        = $cols[4].Trim('"')

                timestamp  = $cols[5].Trim('"')

                reasons    = @($reasonLabels)

                fileName   = $fileName

                attributes = $cols[10].Trim('"')

            })



            if ($events.Count -ge $MaxEventCount) { break }

        }



        return [pscustomobject]@{

            available  = $true

            eventCount = $events.Count

            volume     = $VolumePath

            startUsn   = $startUsn

            endUsn     = $endUsn

            baselineAt = [string]$baseline.recordedAt

            recordedAt = (Get-Date).ToUniversalTime().ToString('o')

            truncated  = ($events.Count -ge $MaxEventCount)

            events     = @($events)

        }

    } catch {

        return [pscustomobject]@{

            available  = $false

            eventCount = 0

            message    = $_.Exception.Message

            events     = @()

        }

    }

}



$result = Export-QuarantineGuestUsnDelta -BaselineFilePath $BaselineFile -VolumePath $Volume -MaxEventCount $MaxEvents

if ($OutFile) {
    Write-QuarantineGuestJsonFile -Object $result -Path $OutFile -Depth 12
    Write-Output "USN_DELTA_WRITTEN $OutFile events=$($result.eventCount)"
}

