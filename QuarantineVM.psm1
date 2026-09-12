#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-QuarantineVMConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json')
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config not found at '$ConfigPath'. Copy config\quarantine-vm.example.json to config\quarantine-vm.json and edit it."
    }

    $raw = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($raw.vmName)) {
        throw 'vmName is required in config.'
    }

    return $raw
}

function Initialize-QuarantineVMContext {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json')
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    return $script:Config
}

function Get-QuarantineVMDataDir {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    if ($Config.vmDataDir -and -not [string]::IsNullOrWhiteSpace($Config.vmDataDir)) {
        return $Config.vmDataDir
    }

    return 'C:\QuarantineLab'
}

function Get-QuarantineVMFolder {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    return Join-Path (Get-QuarantineVMDataDir -Config $Config) $Config.vmName
}

function Get-QuarantineVMDiskPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    if ($Config.diskPath -and -not [string]::IsNullOrWhiteSpace($Config.diskPath)) {
        return $Config.diskPath
    }

    $vmName = $Config.vmName
    return Join-Path (Get-QuarantineVMDataDir -Config $Config) "$vmName\$vmName.vdi"
}

function Resolve-WindowsIsoPath {
    <#
    .SYNOPSIS
      Resolve the Windows ISO path from config, auto-detecting files in isos\ when the
      configured filename does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfiguredPath,

        [Parameter()]
        [string]$GuestOsType = 'Windows11_64',

        [Parameter()]
        [string]$ProjectRoot = $PSScriptRoot
    )

    if ($ConfiguredPath -and (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $ConfiguredPath).Path
    }

    $searchDirs = [System.Collections.Generic.List[string]]::new()
    if ($ConfiguredPath) {
        if (Test-Path -LiteralPath $ConfiguredPath -PathType Container) {
            $searchDirs.Add($ConfiguredPath)
        } else {
            $parent = Split-Path -Parent $ConfiguredPath
            if ($parent) { $searchDirs.Add($parent) }
        }
    }
    $defaultIsoDir = Join-Path $ProjectRoot 'isos'
    if (-not $searchDirs.Contains($defaultIsoDir)) {
        $searchDirs.Add($defaultIsoDir)
    }

    $candidates = @()
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $candidates += Get-ChildItem -LiteralPath $dir -Filter '*.iso' -File -ErrorAction SilentlyContinue
    }

    if ($candidates.Count -eq 0) {
        $searched = ($searchDirs | Where-Object { Test-Path -LiteralPath $_ }) -join ', '
        throw @"
Windows ISO not found.
  Configured: $ConfiguredPath
  Searched:   $searched
Place a Windows ISO in the isos\ folder or set windowsIsoPath in config.
"@
    }

    if ($candidates.Count -eq 1) {
        Write-Host "Using ISO: $($candidates[0].Name) (auto-detected)"
        return $candidates[0].FullName
    }

    $preferWin11 = $GuestOsType -match '11'
    $ranked = foreach ($iso in $candidates) {
        $name = $iso.Name.ToLowerInvariant()
        $score = 0
        if ($name -match 'win(dows)?[_-]?11|win11') { $score += 20 }
        elseif ($name -match 'win(dows)?[_-]?10|win10') { $score += 10 }
        if ($name -match 'x64|amd64|64') { $score += 5 }
        if ($name -match 'english') { $score += 2 }
        if ($preferWin11 -and $name -match 'win(dows)?[_-]?11|win11') { $score += 10 }
        if (-not $preferWin11 -and $name -match 'win(dows)?[_-]?10|win10') { $score += 10 }
        if ($name -match 'windows|win\d') { $score += 1 }

        [pscustomobject]@{
            Path  = $iso.FullName
            Name  = $iso.Name
            Score = $score
            Size  = $iso.Length
        }
    }

    $best = $ranked | Sort-Object Score, Size -Descending | Select-Object -First 1
    if ($best.Score -le 0) {
        $names = ($ranked | ForEach-Object { $_.Name }) -join ', '
        throw "Multiple ISOs found but none look like Windows: $names. Set windowsIsoPath explicitly in config."
    }

    Write-Host "Using ISO: $($best.Name) (auto-detected from $($candidates.Count) candidates)"
    return $best.Path
}

function Get-VBoxManagePath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfiguredPath = ''
    )

    if ($ConfiguredPath -and (Test-Path -LiteralPath $ConfiguredPath)) {
        return (Resolve-Path -LiteralPath $ConfiguredPath).Path
    }

    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox' -ErrorAction SilentlyContinue
    if ($reg -and $reg.InstallDir) {
        $regPath = Join-Path $reg.InstallDir 'VBoxManage.exe'
        if (Test-Path -LiteralPath $regPath) {
            return (Resolve-Path -LiteralPath $regPath).Path
        }
    }

    $candidates = @(
        "${env:ProgramFiles}\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
    )

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }

    $fromPath = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }

    throw 'VBoxManage.exe not found. Install VirtualBox or set vboxManagePath in config.'
}

function Invoke-VBoxManage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter()]
        [switch]$AllowFailure
    )

    $vbox = Get-VBoxManagePath -ConfiguredPath $script:Config.vboxManagePath
    $displayArgs = ($Arguments -join ' ')
    Write-Verbose "VBoxManage $displayArgs"

    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $vbox @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() } else { "$_" }
        }
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousEap
    }

    if ($output) {
        $output | ForEach-Object { Write-Verbose $_ }
    }

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        $text = if ($output) { ($output | Out-String).Trim() } else { 'Unknown VirtualBox error.' }
        throw "VBoxManage failed ($exitCode) running: VBoxManage $displayArgs`n$text"
    }

    return ,@($output)
}

function Test-QuarantineVMExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    $result = Invoke-VBoxManage -Arguments @('list', 'vms') -AllowFailure
    $pattern = '^"([^"]+)"\s+\{'
    foreach ($line in $result) {
        if ($line -match $pattern -and $Matches[1] -eq $VmName) {
            return $true
        }
    }
    return $false
}

function Get-QuarantineVMState {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$VmName = $script:Config.vmName
    )

    if (-not (Test-QuarantineVMExists -VmName $VmName)) {
        return 'notfound'
    }

    $info = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable')
    foreach ($line in $info) {
        $trimmed = "$line".Trim()
        if ($trimmed -match '^VMState="(?<state>[^"]+)"') {
            return $Matches['state'].ToLowerInvariant()
        }
    }

    return 'unknown'
}

function Initialize-QuarantineVMMutable {
    <#
    .SYNOPSIS
      VirtualBox cannot modifyvm while a VM is running or in saved (live snapshot) state.
      Discards saved RAM or powers off so NIC and other settings can be changed.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [Parameter(Mandatory)]
        [string]$VmName,
        [string]$Reason = 'change VM settings'
    )

    $state = 'unknown'
    for ($i = 0; $i -lt 10; $i++) {
        $state = Get-QuarantineVMState -VmName $VmName
        if ($state -ne 'unknown') { break }
        Start-Sleep -Milliseconds 500
    }

    if ($state -eq 'saved') {
        Write-Host "VM is in saved (live snapshot) state; discarding RAM so we can $Reason. Disk snapshot state is unchanged."
        Invoke-VBoxManage -Arguments @('discardstate', $VmName) | Out-Null
        Start-Sleep -Seconds 1
        $state = Get-QuarantineVMState -VmName $VmName
    } elseif ($state -eq 'unknown') {
        Invoke-VBoxManage -Arguments @('discardstate', $VmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
        $state = Get-QuarantineVMState -VmName $VmName
    }

    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host "Stopping VM before $($Reason)..."
        Stop-QuarantineVM -ConfigPath $ConfigPath -Force
        Start-Sleep -Seconds 2
        $state = Get-QuarantineVMState -VmName $VmName
    }

    if ($state -eq 'saved') {
        throw "VM '$VmName' is still in saved state; cannot $Reason. Discard the saved RAM or restore a disk-only snapshot first."
    }
}

function Get-QuarantineHostOnlyAdapter {
    <#
    .SYNOPSIS
      Return an existing host-only adapter name, or try to create one. Returns $null if unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$PreferredName = $script:Config.network.hostOnlyAdapter
    )

    $existing = Invoke-VBoxManage -Arguments @('list', 'hostonlyifs') -AllowFailure
    $names = @()
    foreach ($line in $existing) {
        if ($line -match '^Name:\s+(.+)$') {
            $names += $Matches[1].Trim()
        }
    }

    if ($PreferredName -and ($names -contains $PreferredName)) {
        return $PreferredName
    }
    if ($names.Count -gt 0) {
        Write-Verbose "Using existing host-only adapter: $($names[0])"
        return $names[0]
    }

    Write-Host 'Creating host-only network adapter...'
    Invoke-VBoxManage -Arguments @('hostonlyif', 'create') -AllowFailure | Out-Null

    $after = Invoke-VBoxManage -Arguments @('list', 'hostonlyifs') -AllowFailure
    foreach ($line in $after) {
        if ($line -match '^Name:\s+(.+)$') {
            return $Matches[1].Trim()
        }
    }

    return $null
}

function Get-QuarantineClipboardMode {
    param($Isolation)

    if ($Isolation.disableClipboard -eq $true) {
        return 'disabled'
    }
    if ($Isolation.clipboardMode) {
        return $Isolation.clipboardMode.ToString().ToLowerInvariant()
    }
    return 'hosttoguest'
}

function Get-QuarantineVMModifyContext {
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -in @('running', 'paused', 'starting')) {
        return 'live'
    }
    if ($state -eq 'saved') {
        return 'saved'
    }
    return 'off'
}

function Set-QuarantineVMNormalBoot {
    <#
    .SYNOPSIS
      Boot from disk and eject install ISO so cold boots reach the installed OS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [switch]$KeepIsoAttached
    )

    $ctx = Get-QuarantineVMModifyContext -VmName $VmName
    if ($ctx -eq 'saved') {
        Write-Host 'Discarding saved state so boot settings can be applied safely...'
        Invoke-VBoxManage -Arguments @('discardstate', $VmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    } elseif ($ctx -eq 'live') {
        Write-Host 'Stopping VM before applying normal boot order...'
        Invoke-VBoxManage -Arguments @('controlvm', $VmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 2
    }

    Invoke-VBoxManage -Arguments @(
        'modifyvm', $VmName,
        '--boot1', 'disk',
        '--boot2', 'none',
        '--boot3', 'none',
        '--boot4', 'none'
    ) | Out-Null

    if (-not $KeepIsoAttached) {
        Initialize-QuarantineVMDvdDrive -VmName $VmName -Empty | Out-Null
    } else {
        Initialize-QuarantineVMDvdDrive -VmName $VmName | Out-Null
    }
}

function Test-QuarantineVMDvdDrive {
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    $lines = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--details')
    foreach ($line in $lines) {
        if ($line -match 'Port 1,\s*Unit 0:') {
            return $true
        }
    }
    return $false
}

function Get-VBoxGuestAdditionsIsoPath {
    param([string]$ConfiguredVBoxPath)

    $roots = @()
    if ($ConfiguredVBoxPath) {
        $roots += Split-Path $ConfiguredVBoxPath -Parent
    }
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox' -ErrorAction SilentlyContinue
    if ($reg -and $reg.InstallDir) {
        $roots += $reg.InstallDir
    }
    $roots += @(
        "${env:ProgramFiles}\Oracle\VirtualBox",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox"
    )

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not $root) { continue }
        $iso = Join-Path $root 'VBoxGuestAdditions.iso'
        if (Test-Path -LiteralPath $iso) { return $iso }
    }

    return $null
}

function Initialize-QuarantineVMDvdDrive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [switch]$Empty
    )

    if (Test-QuarantineVMDvdDrive -VmName $VmName) {
        if ($Empty) {
            Invoke-VBoxManage -Arguments @(
                'storageattach', $VmName,
                '--storagectl', 'SATA',
                '--port', '1',
                '--device', '0',
                '--type', 'dvddrive',
                '--medium', 'none'
            ) -AllowFailure | Out-Null
        }
        return
    }

    Invoke-VBoxManage -Arguments @(
        'storageattach', $VmName,
        '--storagectl', 'SATA',
        '--port', '1',
        '--device', '0',
        '--type', 'dvddrive',
        '--medium', 'emptydrive'
    ) | Out-Null
}

function Mount-QuarantineVMGuestAdditions {
    <#
    .SYNOPSIS
      Attach an empty DVD drive if needed and insert the VirtualBox Guest Additions ISO.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -notin @('running', 'paused', 'poweredoff', 'saved', 'aborted')) {
        throw "VM '$vmName' is in state '$state'; cannot mount Guest Additions."
    }

    Initialize-QuarantineVMDvdDrive -VmName $vmName | Out-Null

    $output = Invoke-VBoxManage -Arguments @(
        'storageattach', $vmName,
        '--storagectl', 'SATA',
        '--port', '1',
        '--device', '0',
        '--type', 'dvddrive',
        '--medium', 'additions'
    ) -AllowFailure

    $text = if ($output) { ($output | Out-String).Trim() } else { '' }
    if ($text -match 'No drive attached') {
        Initialize-QuarantineVMDvdDrive -VmName $vmName | Out-Null
        Invoke-VBoxManage -Arguments @(
            'storageattach', $vmName,
            '--storagectl', 'SATA',
            '--port', '1',
            '--device', '0',
            '--type', 'dvddrive',
            '--medium', 'additions'
        ) | Out-Null
    } elseif ($text -match 'error:') {
        $iso = Get-VBoxGuestAdditionsIsoPath -ConfiguredVBoxPath $script:Config.vboxManagePath
        if (-not $iso) {
            throw "Failed to mount Guest Additions: $text"
        }
        Invoke-VBoxManage -Arguments @(
            'storageattach', $vmName,
            '--storagectl', 'SATA',
            '--port', '1',
            '--device', '0',
            '--type', 'dvddrive',
            '--medium', $iso
        ) | Out-Null
    }

    $isoPath = Get-VBoxGuestAdditionsIsoPath -ConfiguredVBoxPath $script:Config.vboxManagePath
    Write-Host "Guest Additions ISO mounted on SATA port 1."
    if ($isoPath) {
        Write-Host "  $isoPath"
    }
    Write-Host @'

In the guest:
  1. Open File Explorer -> DVD drive (VirtualBox Guest Additions)
  2. Run VBoxWindowsAdditions.exe (or VBoxWindowsAdditions-amd64.exe)
  3. Reboot when prompted

Host-to-guest paste works after reboot.
'@
}

function Set-QuarantineVMIsolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        $Isolation = $script:Config.isolation,

        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\quarantine-vm.json')
    )

    $args = @('modifyvm', $VmName)

    $clipboardMode = Get-QuarantineClipboardMode -Isolation $Isolation
    $args += '--clipboard-mode', $clipboardMode

    if ($Isolation.disableDragDrop) {
        $args += '--draganddrop', 'disabled'
    }
    if ($Isolation.disableUsb) {
        $args += '--usb', 'off'
        $args += '--usbehci', 'off'
        $args += '--usbxhci', 'off'
    }
    if ($Isolation.disableAudio) {
        $args += '--audio-driver', 'none'
        $args += '--audioin', 'off'
    }

    $args += '--recording', 'off'
    $args += '--vrde', 'off'
    $args += '--teleporter', 'off'
    $args += '--accelerate3d', 'off'

    $ctx = Get-QuarantineVMModifyContext -VmName $VmName
    if ($ctx -eq 'live') {
        Invoke-VBoxManage -Arguments @('controlvm', $VmName, 'clipboard', 'mode', $clipboardMode) -AllowFailure | Out-Null
        if ($Isolation.disableSharedFolders) {
            Remove-QuarantineVMInboxShare -VmName $VmName
        }
        return
    }
    if ($ctx -eq 'saved') {
        Write-Host 'Discarding saved state before applying isolation settings...'
        Invoke-VBoxManage -Arguments @('discardstate', $VmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    }

    Invoke-VBoxManage -Arguments $args | Out-Null

    if ($Isolation.disableSharedFolders) {
        Remove-QuarantineVMInboxShare -VmName $VmName
    }

    Set-QuarantineVMStealth -VmName $VmName -Isolation $Isolation -ConfigPath $ConfigPath | Out-Null
}

function Set-QuarantineVMStealth {
    <#
    .SYNOPSIS
      Soften common VirtualBox guest fingerprints (DMI/ACPI/MAC/CPU profile).
      Keeps Guest Additions and VBoxSVGA — required for guestcontrol, clipboard, resize.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        $Isolation = $script:Config.isolation,

        [Parameter()]
        [string]$ConfigPath
    )

    $stealth = $null
    if ($Isolation -and $Isolation.PSObject.Properties['stealth']) {
        $stealth = $Isolation.stealth
    }
    if (-not $stealth) {
        # Defaults even without a stealth block — lab still benefits.
        $stealth = [pscustomobject]@{ enabled = $true }
    }
    if ($null -ne $stealth.enabled -and -not [bool]$stealth.enabled) {
        Write-Host 'Stealth: disabled in config (isolation.stealth.enabled=false)'
        return
    }

    $ctx = Get-QuarantineVMModifyContext -VmName $VmName
    if ($ctx -eq 'live') {
        Write-Warning 'Stealth skipped while VM is running (power off, then .\quarantine-vm.ps1 stealth).'
        return
    }
    if ($ctx -eq 'saved') {
        Write-Warning 'Stealth skipped: VM has saved state. Power off (or discard saved state), then re-run stealth.'
        return
    }

    $cpuProfile = 'Intel Core i7-6700K'
    if ($stealth.cpuProfile) { $cpuProfile = [string]$stealth.cpuProfile }

    # Detect firmware early — EFI + forced Skylake (etc.) profiles often triple-fault
    # during Windows Setup / early boot (Guru Meditation VINF_EM_TRIPLE_FAULT).
    $firmware = 'bios'
    try {
        $infoFw = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable') -AllowFailure
        $infoFwText = ($infoFw | Out-String)
        if ($infoFwText -match 'firmware="?([^"\r\n]+)"?') {
            $firmware = $Matches[1].ToLowerInvariant()
        }
    } catch { }

    if ($firmware -eq 'efi') {
        Invoke-VBoxManage -Arguments @('modifyvm', $VmName, '--cpu-profile', 'host') -AllowFailure | Out-Null
        Write-Host 'Stealth: EFI guest uses host CPU profile (custom profiles break Win11 Setup).'
    } elseif ($cpuProfile -and $cpuProfile -notin @('host', 'none', '')) {
        Invoke-VBoxManage -Arguments @('modifyvm', $VmName, '--cpu-profile', $cpuProfile) -AllowFailure | Out-Null
    }

    if ($stealth.paravirtProvider) {
        Invoke-VBoxManage -Arguments @('modifyvm', $VmName, '--paravirtprovider', [string]$stealth.paravirtProvider) -AllowFailure | Out-Null
    }

    $macRaw = if ($stealth.macAddress) { [string]$stealth.macAddress } else { 'auto' }
    $generatedMac = $false
    if (-not $macRaw -or $macRaw -eq 'auto') {
        $curMac = ''
        try {
            $info = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable') -AllowFailure
            $infoText = ($info | Out-String)
            if ($infoText -match 'macaddress1="?([0-9A-Fa-f]{12})"?' ) {
                $curMac = $Matches[1].ToUpperInvariant()
            }
        } catch { }
        if ($curMac.Length -eq 12 -and -not $curMac.StartsWith('080027')) {
            $macRaw = $curMac
        } else {
            $oui = if ($stealth.macOui) {
                ([string]$stealth.macOui) -replace '[:\-]', ''
            } else {
                'F8B156' # Dell Inc.
            }
            $oui = $oui.ToUpperInvariant()
            if ($oui.Length -ne 6) { throw "isolation.stealth.macOui must be 6 hex digits (got '$oui')" }
            $macRaw = ($oui + ('{0:X6}' -f (Get-Random -Maximum 0xFFFFFF))).ToUpperInvariant()
            $generatedMac = $true
        }
    }
    $mac = ($macRaw -replace '[:\-]', '').ToUpperInvariant()
    if ($mac.Length -ne 12 -or $mac -notmatch '^[0-9A-F]{12}$') {
        throw "isolation.stealth.macAddress must be 12 hex digits (got '$macRaw')"
    }
    Invoke-VBoxManage -Arguments @('modifyvm', $VmName, '--macaddress1', $mac) | Out-Null

    if ($generatedMac -and $ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
        try {
            $raw = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            if (-not $raw.isolation) {
                $raw | Add-Member -NotePropertyName isolation -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            if (-not $raw.isolation.stealth) {
                $raw.isolation | Add-Member -NotePropertyName stealth -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $raw.isolation.stealth | Add-Member -NotePropertyName macAddress -NotePropertyValue $mac -Force
            $raw.isolation.stealth | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force
            $json = $raw | ConvertTo-Json -Depth 20
            Set-Content -LiteralPath $ConfigPath -Value $json -Encoding UTF8
            if ($script:Config -and $script:Config.isolation) {
                if (-not $script:Config.isolation.stealth) {
                    $script:Config.isolation | Add-Member -NotePropertyName stealth -NotePropertyValue ([pscustomobject]@{}) -Force
                }
                $script:Config.isolation.stealth | Add-Member -NotePropertyName macAddress -NotePropertyValue $mac -Force
            }
        } catch {
            Write-Warning "Could not persist generated MAC to config: $($_.Exception.Message)"
        }
    }

    $dmiDefaults = [ordered]@{
        DmiSystemVendor    = 'Dell Inc.'
        DmiSystemProduct   = 'OptiPlex 7090'
        DmiSystemVersion   = '1.0.0'
        DmiSystemSerial    = 'JQ-LAB-7K90A1'
        DmiSystemFamily    = 'OptiPlex'
        DmiSystemSKU       = '0A54'
        DmiBoardVendor     = 'Dell Inc.'
        DmiBoardProduct    = '0A54'
        DmiBoardVersion    = 'A00'
        DmiBoardSerial     = '/BN0A54-LAB001/'
        DmiBoardAssetTag   = ' '
        DmiChassisVendor   = 'Dell Inc.'
        DmiChassisType     = '3'
        DmiChassisVersion  = 'N/A'
        DmiChassisSerial   = 'CN-LAB-7090-001'
        DmiChassisAssetTag = ' '
        DmiBIOSVendor      = 'Dell Inc.'
        DmiBIOSVersion     = '1.18.0'
        DmiBIOSReleaseDate = '12/15/2023'
    }
    if ($stealth.dmi) {
        foreach ($p in $stealth.dmi.PSObject.Properties) {
            if ($null -ne $p.Value -and [string]$p.Value -ne '') {
                $dmiDefaults[$p.Name] = [string]$p.Value
            }
        }
    }

    # EFI guests: any VBoxInternal/Devices/pcbios/0/Config/* replaces the CFGM
    # tree and drops BootDevice0 → start fails with VERR_CFGM_VALUE_NOT_FOUND.
    # Keep MAC/ACPI only; clear leftover pcbios Config keys if present.
    # ($firmware already resolved above for cpu-profile)
    $dmiNote = 'acpi only (EFI - pcbios DMI skipped)'
    if ($firmware -eq 'efi') {
        try {
            $extra = Invoke-VBoxManage -Arguments @('getextradata', $VmName, 'enumerate') -AllowFailure
            foreach ($line in @($extra)) {
                if ($line -match 'Key: (VBoxInternal/Devices/pcbios/0/Config/[^,]+),') {
                    Invoke-VBoxManage -Arguments @('setextradata', $VmName, $Matches[1]) -AllowFailure | Out-Null
                }
            }
        } catch { }
    } else {
        # Legacy BIOS: setting any pcbios Config key requires BootDevice* too.
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/BootDevice0', 'IDE') -AllowFailure | Out-Null
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/BootDevice1', 'DVD') -AllowFailure | Out-Null
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/BootDevice2', 'NONE') -AllowFailure | Out-Null
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/BootDevice3', 'NONE') -AllowFailure | Out-Null
        foreach ($key in $dmiDefaults.Keys) {
            $path = "VBoxInternal/Devices/pcbios/0/Config/$key"
            Invoke-VBoxManage -Arguments @('setextradata', $VmName, $path, [string]$dmiDefaults[$key]) -AllowFailure | Out-Null
        }
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer', ' ') -AllowFailure | Out-Null
        Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev', ' ') -AllowFailure | Out-Null
        $dmiNote = 'pcbios DMI + acpi'
    }
    Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/acpi/0/Config/AcpiOemId', 'DELL  ') -AllowFailure | Out-Null
    Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/acpi/0/Config/AcpiCreatorId', 'DELL') -AllowFailure | Out-Null
    Invoke-VBoxManage -Arguments @('setextradata', $VmName, 'VBoxInternal/Devices/acpi/0/Config/AcpiCreatorRev', '0x00000001') -AllowFailure | Out-Null

    $macPretty = '{0}:{1}:{2}:{3}:{4}:{5}' -f @(
        $mac.Substring(0, 2), $mac.Substring(2, 2), $mac.Substring(4, 2),
        $mac.Substring(6, 2), $mac.Substring(8, 2), $mac.Substring(10, 2)
    )
    $cpuNote = if ($firmware -eq 'efi') { 'host (EFI)' } else { $cpuProfile }
    Write-Host "Stealth applied: cpu-profile=$cpuNote; mac=$macPretty; $dmiNote (Guest Additions / VBoxSVGA kept)"
}

function Get-QuarantineVMInboxSettings {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    $dataDir = Get-QuarantineVMDataDir -Config $Config
    $settings = [ordered]@{
        hostPath          = Join-Path $dataDir 'quarantine-inbox'
        shareName         = 'quarantine-in'
        readOnly          = $true
        requireNetworkOff = $false
        logDir            = Join-Path $dataDir 'logs\inbox'
    }

    if ($Config.inbox) {
        foreach ($key in @($settings.Keys)) {
            $value = $Config.inbox.$key
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace("$value")) {
                $settings[$key] = $value
            }
        }
    }

    return [pscustomobject]$settings
}

function Initialize-QuarantineVMInboxDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostPath,

        [Parameter()]
        [string]$LogDir
    )

    if (-not (Test-Path -LiteralPath $HostPath)) {
        New-Item -ItemType Directory -Path $HostPath -Force | Out-Null
        Write-Verbose "Created inbox directory: $HostPath"
    }

    if ($LogDir -and -not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
}

function Get-QuarantineVMInboxShareName {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    return (Get-QuarantineVMInboxSettings -Config $Config).shareName
}

function Test-QuarantineVMInboxShareOpen {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [string]$ShareName
    )

    if (-not $ShareName) {
        $ShareName = Get-QuarantineVMInboxShareName
    }

    $lines = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable') -AllowFailure
    foreach ($line in $lines) {
        if ($line -match '^SharedFolderNameMachineMapping\d+="([^"]+)"$' -and $Matches[1] -eq $ShareName) {
            return $true
        }
    }

    return $false
}

function Remove-QuarantineVMInboxShare {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [string]$ShareName,

        [Parameter()]
        [switch]$Quiet
    )

    if (-not $ShareName) {
        $ShareName = Get-QuarantineVMInboxShareName
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -notin @('running', 'paused')) {
        return $false
    }

    if (-not (Test-QuarantineVMInboxShareOpen -VmName $VmName -ShareName $ShareName)) {
        return $false
    }

    Invoke-VBoxManage -Arguments @(
        'sharedfolder', 'remove', $VmName, "--name=$ShareName", '--transient'
    ) -AllowFailure | Out-Null

    if (-not $Quiet) {
        Write-Host "Removed transient shared folder '$ShareName'."
    }

    return $true
}

function Test-QuarantineVMInboxNetworkAllowed {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    $settings = Get-QuarantineVMInboxSettings -Config $Config
    if (-not $settings.requireNetworkOff) {
        return $true
    }

    $mode = if ($Config.network -and $Config.network.mode) { $Config.network.mode } else { 'intnet' }
    return $mode -in @('none', 'offline', 'intnet')
}

function Write-QuarantineVMInboxTransferLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogDir,

        [Parameter(Mandatory)]
        [object[]]$Entries
    )

    Initialize-QuarantineVMInboxDirectory -HostPath $LogDir -LogDir $LogDir
    $logPath = Join-Path $LogDir 'transfers.jsonl'
    foreach ($entry in $Entries) {
        ($entry | ConvertTo-Json -Compress) | Add-Content -LiteralPath $logPath -Encoding UTF8
    }
}

function Push-QuarantineVMInbox {
    <#
    .SYNOPSIS
      Copy sample file(s) into the host inbox and record SHA256 hashes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path,

        [Parameter()]
        [string]$ConfigPath
    )

    begin {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
        $settings = Get-QuarantineVMInboxSettings
        Initialize-QuarantineVMInboxDirectory -HostPath $settings.hostPath -LogDir $settings.logDir
        $pushed = @()
    }

    process {
        foreach ($src in $Path) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($src)
            if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                throw "File not found: $src"
            }

            $item = Get-Item -LiteralPath $resolved
            $dest = Join-Path $settings.hostPath $item.Name
            Copy-Item -LiteralPath $item.FullName -Destination $dest -Force
            $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash

            $entry = [pscustomobject]@{
                timestamp = (Get-Date).ToString('o')
                fileName  = $item.Name
                bytes     = $item.Length
                sha256    = $hash
                hostPath  = $dest
            }
            $pushed += $entry
            Write-Host "Pushed $($item.Name) ($($item.Length) bytes)"
            Write-Host "  SHA256: $hash"
        }
    }

    end {
        if ($pushed.Count -gt 0) {
            Write-QuarantineVMInboxTransferLog -LogDir $settings.logDir -Entries $pushed
            Write-Host "Inbox: $($settings.hostPath)"
            Write-Host "Run: .\quarantine-vm.ps1 inbox open"
        }
    }
}

function Open-QuarantineVMInbox {
    <#
    .SYNOPSIS
      Mount the host inbox as a transient shared folder in the running guest.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$Writable
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $settings = Get-QuarantineVMInboxSettings

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -notin @('running', 'paused')) {
        throw "VM '$vmName' must be running to open the inbox (state: $state). Start it with: .\quarantine-vm.ps1 start"
    }

    if (-not (Test-QuarantineVMInboxNetworkAllowed)) {
        $mode = $script:Config.network.mode
        throw "Inbox open blocked: network mode '$mode' is not allowed while inbox.requireNetworkOff is true. Run: .\quarantine-vm.ps1 network none"
    }

    Initialize-QuarantineVMInboxDirectory -HostPath $settings.hostPath -LogDir $settings.logDir

    $files = @(Get-ChildItem -LiteralPath $settings.hostPath -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        Write-Warning "Inbox is empty. Push files first: .\quarantine-vm.ps1 inbox push <file>"
    }

    Remove-QuarantineVMInboxShare -VmName $vmName -ShareName $settings.shareName -Quiet

    $hostPath = Format-VBoxPath -Path $settings.hostPath
    $args = @(
        'sharedfolder', 'add', $vmName,
        "--name=$($settings.shareName)",
        "--hostpath=$hostPath",
        '--automount',
        '--transient'
    )
    if ($settings.readOnly -and -not $Writable) {
        $args += '--readonly'
    } elseif ($Writable) {
        Write-Host 'WARNING: Mounting inbox READ-WRITE (lab only). Close immediately after use.'
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Open inbox share '$($settings.shareName)'")) {
        try {
            Invoke-VBoxManage -Arguments $args | Out-Null
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                throw
            }
            Write-Verbose "Share '$($settings.shareName)' already mounted."
        }
        $guestPath = "\\VBOXSVR\$($settings.shareName)"
        $mountedReadOnly = $settings.readOnly -and -not $Writable
        Write-Host "Inbox mounted in guest (read-only: $mountedReadOnly)."
        Write-Host "  Host:  $($settings.hostPath)"
        Write-Host "  Guest: $guestPath"
        Write-Host 'Copy files in the guest, then run: .\quarantine-vm.ps1 inbox close'
    }
}

function Close-QuarantineVMInbox {
    <#
    .SYNOPSIS
      Remove the transient inbox shared folder from the running guest.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $settings = Get-QuarantineVMInboxSettings

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    if (Remove-QuarantineVMInboxShare -VmName $vmName -ShareName $settings.shareName) {
        return
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -notin @('running', 'paused')) {
        Write-Host "VM '$vmName' is not running; no transient share to remove."
        return
    }

    Write-Host "Inbox share '$($settings.shareName)' is not mounted."
}

function Get-QuarantineVMInbox {
    <#
    .SYNOPSIS
      Show inbox directory contents, mount state, and recent transfer log entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $settings = Get-QuarantineVMInboxSettings
    $mounted = $false

    if (Test-QuarantineVMExists -VmName $vmName) {
        $mounted = Test-QuarantineVMInboxShareOpen -VmName $vmName -ShareName $settings.shareName
    }

    $files = @()
    if (Test-Path -LiteralPath $settings.hostPath) {
        $files = Get-ChildItem -LiteralPath $settings.hostPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Name   = $_.Name
                Bytes  = $_.Length
                Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
    }

    $recentTransfers = @()
    $logPath = Join-Path $settings.logDir 'transfers.jsonl'
    if (Test-Path -LiteralPath $logPath) {
        $recentTransfers = Get-Content -LiteralPath $logPath -Tail 5 -ErrorAction SilentlyContinue | ForEach-Object {
            $_ | ConvertFrom-Json
        }
    }

    [pscustomobject]@{
        HostPath          = $settings.hostPath
        ShareName         = $settings.shareName
        ReadOnly          = $settings.readOnly
        RequireNetworkOff = $settings.requireNetworkOff
        Mounted           = $mounted
        GuestPath         = "\\VBOXSVR\$($settings.shareName)"
        Files             = $files
        RecentTransfers   = $recentTransfers
        LogPath           = $logPath
    }
}

function Clear-QuarantineVMInbox {
    <#
    .SYNOPSIS
      Delete all files from the host inbox directory (not the transfer log).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $settings = Get-QuarantineVMInboxSettings

    if (Test-QuarantineVMExists -VmName $vmName) {
        if (Test-QuarantineVMInboxShareOpen -VmName $vmName -ShareName $settings.shareName) {
            throw "Inbox is mounted in the guest. Close it first: .\quarantine-vm.ps1 inbox close"
        }
    }

    if (-not (Test-Path -LiteralPath $settings.hostPath)) {
        Write-Host 'Inbox directory does not exist; nothing to clear.'
        return
    }

    $files = @(Get-ChildItem -LiteralPath $settings.hostPath -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        Write-Host 'Inbox is already empty.'
        return
    }

    if ($PSCmdlet.ShouldProcess($settings.hostPath, "Delete $($files.Count) file(s)")) {
        $files | Remove-Item -Force
        Write-Host "Cleared $($files.Count) file(s) from inbox."
    }
}

function Get-QuarantineVMGuestSettings {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    $settings = [ordered]@{
        username      = ''
        password      = ''
        passwordFile  = ''
        domain        = ''
        defaultExe    = 'C:\Windows\System32\cmd.exe'
        copyTargetDir = 'C:\Users\Public\Quarantine'
        timeoutMs     = 60000
    }

    if ($Config.guest) {
        foreach ($key in @($settings.Keys)) {
            $value = $Config.guest.$key
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace("$value")) {
                $settings[$key] = $value
            }
        }
    }

    return [pscustomobject]$settings
}

function Get-QuarantineVMGuestPassword {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$ConfigPassword,

        [Parameter()]
        [string]$PasswordFile
    )

    if ($Password) {
        return $Password
    }

    $envPass = [Environment]::GetEnvironmentVariable('QUARANTINE_GUEST_PASSWORD')
    if ($envPass) {
        return $envPass
    }

    if ($ConfigPassword) {
        return $ConfigPassword
    }

    if ($PasswordFile -and (Test-Path -LiteralPath $PasswordFile)) {
        return (Get-Content -LiteralPath $PasswordFile -Raw).Trim()
    }

    if ([Environment]::UserInteractive) {
        $secure = Read-Host 'Guest password' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    throw @"
Guest password required. Provide one of:
  -GuestPassword parameter
  QUARANTINE_GUEST_PASSWORD environment variable
  guest.password in config
  guest.passwordFile in config (path to a file containing the password)
"@
}

function Resolve-QuarantineVMGuestCredential {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMGuestSettings

    $resolvedUser = if ($Username) { $Username } elseif ($settings.username) { $settings.username } else { $null }
    if (-not $resolvedUser) {
        throw @"
Guest username required. Set guest.username in config or pass -GuestUser.
Use a dedicated local account in the guest (not your personal credentials).
"@
    }

    $resolvedDomain = if ($Domain) { $Domain } elseif ($settings.domain) { $settings.domain } else { '' }
    if ($resolvedUser -match '^([^\\]+)\\(.+)$') {
        if (-not $resolvedDomain) {
            $resolvedDomain = $Matches[1]
        }
        $resolvedUser = $Matches[2]
    }
    $resolvedPassword = Get-QuarantineVMGuestPassword -Password $Password -ConfigPassword $settings.password -PasswordFile $settings.passwordFile

    [pscustomobject]@{
        Username = $resolvedUser
        Password = $resolvedPassword
        Domain   = $resolvedDomain
        Settings = $settings
    }
}

function Get-QuarantineVMPayloadSettings {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    $settings = [ordered]@{
        username      = ''
        password      = ''
        passwordFile  = ''
        domain        = ''
        defaultExe    = 'C:\Windows\System32\cmd.exe'
        copyTargetDir = 'C:\Users\Public\Quarantine'
        timeoutMs     = 120000
    }

    if ($Config.payload) {
        foreach ($key in @($settings.Keys)) {
            $value = $Config.payload.$key
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace("$value")) {
                $settings[$key] = $value
            }
        }
    }

    return [pscustomobject]$settings
}

function Resolve-QuarantineVMPayloadCredential {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $settings = Get-QuarantineVMPayloadSettings

    $resolvedUser = if ($Username) { $Username } elseif ($settings.username) { $settings.username } else { $null }
    if (-not $resolvedUser) {
        throw 'Payload username required. Set payload.username in config/quarantine-vm.json or pass -GuestUser.'
    }

    $resolvedDomain = if ($Domain) { $Domain } elseif ($settings.domain) { $settings.domain } else { '' }
    if ($resolvedUser -match '^([^\\]+)\\(.+)$') {
        if (-not $resolvedDomain) { $resolvedDomain = $Matches[1] }
        $resolvedUser = $Matches[2]
    }

    $resolvedPassword = Get-QuarantineVMGuestPassword -Password $Password -ConfigPassword $settings.password -PasswordFile $settings.passwordFile

    [pscustomobject]@{
        Username = $resolvedUser
        Password = $resolvedPassword
        Domain   = $resolvedDomain
        Settings = $settings
    }
}

function Restart-QuarantineVMGuestSession {
    <#
    .SYNOPSIS
      Recover from a broken guest-control session by power-cycling the VM and waiting for Guest Additions.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [int]$TimeoutSeconds = 180
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }

    $vmName = $script:Config.vmName
    $state = Get-QuarantineVMState -VmName $vmName
    Write-Warning "Recovering guest session (VM state: $state)..."

    if ($state -in @('running', 'paused', 'starting')) {
        Stop-QuarantineVM -ConfigPath $ConfigPath -Force
        Start-Sleep -Seconds 5
    } elseif ($state -in @('aborted', 'gurumeditation')) {
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 3
    }

    Start-QuarantineVM -ConfigPath $ConfigPath -Type headless -SkipProxy
    Start-Sleep -Seconds 15

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if (Test-QuarantineVMGuestControl -ConfigPath $ConfigPath) {
                Write-Host 'Guest control OK.'
                return
            }
        } catch {
            if ($_.Exception.Message -match 'not ready|poweroff|not running|E_ACCESSDENIED') {
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }

    throw 'Guest control did not become ready after VM restart.'
}

function Assert-QuarantineVMGuestRunning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    if (-not (Test-QuarantineVMExists -VmName $VmName)) {
        throw "VM '$VmName' not found."
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -notin @('running', 'paused')) {
        throw "VM '$VmName' must be running for guest control (state: $state). Start it with: .\quarantine-vm.ps1 start"
    }
}

function Invoke-QuarantineVMGuestControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [int]$TimeoutMs = 60000
    )

    $vmName = $script:Config.vmName
    Assert-QuarantineVMGuestRunning -VmName $vmName

    if ($Arguments.Count -lt 1) {
        throw 'Guest control subcommand is required (run, copyto, mkdir, ...).'
    }

    $subCommand = $Arguments[0]
    $subCommandArgs = @()
    if ($Arguments.Count -gt 1) {
        $subCommandArgs = $Arguments[1..($Arguments.Count - 1)]
    }

    $args = @('guestcontrol', $vmName, $subCommand)
    $args += "--username=$Username"
    $args += "--password=$Password"
    if ($Domain) {
        $args += "--domain=$Domain"
    }
    if ($subCommand -in @('run', 'start')) {
        $args += "--timeout=$TimeoutMs"
    }
    $args += $subCommandArgs

    $maxAttempts = if ($subCommand -in @('run', 'start')) { 3 } else { 1 }
    $lastError = $null

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return Invoke-VBoxManage -Arguments $args
        } catch {
            $lastError = $_
            $msg = $_.Exception.Message
            if ($attempt -lt $maxAttempts -and $msg -match 'RPC_S_SERVER_UNAVAILABLE|E_UNEXPECTED|session state|Unlocked|guest control|aborted|gurumeditation') {
                Write-Warning "Guest control attempt $attempt/$maxAttempts failed (transient VBox session). Restarting VM..."
                Start-Sleep -Seconds 5
                Restart-QuarantineVMGuestSession -ConfigPath $ConfigPath
                continue
            }
            if ($msg -match 'not able to logon|logon on guest|Authentication failure') {
                throw @"
$msg

Guest logon failed. Check:
  1. guest.username / guest.password in config (Microsoft accounts often fail - use a local account name)
  2. Run 'whoami' inside the guest to see the exact username
  3. Guest Additions installed and VM rebooted after install
  4. Account password is correct (typo in email domain? .ccom vs .com)
"@
            }
            throw
        }
    }

    throw $lastError
}

function Invoke-QuarantineVMGuestRun {
    <#
    .SYNOPSIS
      Run a program inside the guest via VirtualBox Guest Control (requires Guest Additions).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Command,

        [Parameter()]
        [string]$Exe,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [int]$TimeoutMs
    )

    if (-not $Command -or $Command.Count -eq 0) {
        throw 'Command arguments are required.'
    }

    $cred = Resolve-QuarantineVMGuestCredential -Username $Username -Password $Password -Domain $Domain -ConfigPath $ConfigPath
    $settings = $cred.Settings
    $timeout = if ($TimeoutMs) { $TimeoutMs } else { [int]$settings.timeoutMs }
    $exePath = if ($Exe) { $Exe } else { $settings.defaultExe }

    $args = @(
        'run',
        '--exe', $exePath,
        '--wait-stdout',
        '--wait-stderr',
        '--'
    )

    if ($exePath -match '(?i)(\\)?cmd\.exe$') {
        $args += '/c'
        $args += ($Command -join ' ')
    } else {
        $args += $Command
    }

    $output = Invoke-QuarantineVMGuestControl -Arguments $args -Username $cred.Username -Password $cred.Password -Domain $cred.Domain -ConfigPath $ConfigPath -TimeoutMs $timeout
    if ($output) {
        $output | ForEach-Object { Write-Output $_ }
    }
}

function Invoke-QuarantineGuestHostsEntry {
    <#
    .SYNOPSIS
      Add a harmless hosts-file entry in the guest via elevated scheduled task (lab admin account).
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [string]$IpAddress = '127.0.0.1',
        [string]$Hostname = 'smoke.lab.test',
        [int]$TimeoutMs = 120000
    )

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot 'config\quarantine-vm.json'
    }
    Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null

    $guestScript = Join-Path $PSScriptRoot 'guest\Add-QuarantineGuestHostsEntry.ps1'
    if (-not (Test-Path -LiteralPath $guestScript)) {
        throw "Guest script not found: $guestScript"
    }

    $settings = Get-QuarantineVMGuestSettings
    $guestDir = $settings.copyTargetDir
    if (-not $guestDir) { $guestDir = 'C:\Users\Public\Quarantine' }

    Copy-QuarantineVMGuestFile -Path $guestScript -ConfigPath $ConfigPath -TargetDirectory $guestDir
    $guestPath = Join-Path $guestDir (Split-Path -Leaf $guestScript)

    Invoke-QuarantineVMGuestRun -ConfigPath $ConfigPath -TimeoutMs $TimeoutMs `
        -Exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -Command @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $guestPath,
            '-IpAddress', $IpAddress,
            '-Hostname', $Hostname
        )
}

function Copy-QuarantineVMGuestFile {
    <#
    .SYNOPSIS
      Copy file(s) from the host into the guest via VirtualBox Guest Control.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path,

        [Parameter()]
        [string]$TargetDirectory,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath
    )

    begin {
        $cred = Resolve-QuarantineVMGuestCredential -Username $Username -Password $Password -Domain $Domain -ConfigPath $ConfigPath
        $settings = $cred.Settings
        $target = if ($TargetDirectory) { $TargetDirectory } else { $settings.copyTargetDir }
        $hostPaths = @()
    }

    process {
        foreach ($src in $Path) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($src)
            if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                throw "File not found: $src"
            }
            $hostPaths += $resolved
        }
    }

    end {
        if ($hostPaths.Count -eq 0) {
            throw 'At least one host file path is required.'
        }

        try {
            Invoke-QuarantineVMGuestControl -Arguments @(
                'mkdir', '--parents', $target
            ) -Username $cred.Username -Password $cred.Password -Domain $cred.Domain -TimeoutMs $settings.timeoutMs | Out-Null
        } catch {
            Write-Verbose "mkdir $target (may already exist): $($_.Exception.Message)"
        }

        foreach ($hostPath in $hostPaths) {
            $name = Split-Path -Leaf $hostPath
            $destFile = Join-Path $target $name
            $copyArgs = @('copyto', "--target-directory=$destFile", $hostPath)
            Invoke-QuarantineVMGuestControl -Arguments $copyArgs -Username $cred.Username -Password $cred.Password -Domain $cred.Domain -TimeoutMs $settings.timeoutMs | Out-Null
            Write-Host "Copied $name -> $destFile"
        }
    }
}

function Test-QuarantineVMGuestControl {
    <#
    .SYNOPSIS
      Verify Guest Additions guest control is reachable with the configured credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$ConfigPath
    )

    $output = Invoke-QuarantineVMGuestRun -Command @('echo quarantine-guest-ok') -Username $Username -Password $Password -Domain $Domain -ConfigPath $ConfigPath
    $text = ($output | Out-String).Trim()
    if ($text -match 'quarantine-guest-ok') {
        Write-Host 'Guest control OK.'
        return $true
    }

    Write-Warning "Guest control returned unexpected output: $text"
    return $false
}

function Set-QuarantineVMClipboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('disabled', 'hosttoguest', 'guesttohost', 'bidirectional')]
        [string]$Mode,

        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $ctx = Get-QuarantineVMModifyContext -VmName $vmName
    if ($ctx -eq 'live') {
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'clipboard', 'mode', $Mode) -AllowFailure | Out-Null
    } elseif ($ctx -eq 'saved') {
        throw @"
VM '$vmName' has saved state. Changing clipboard via modifyvm can corrupt that state and break the next boot.
Run: .\quarantine-vm.ps1 stop -Force
Then: .\quarantine-vm.ps1 clipboard $Mode
"@
    } else {
        Invoke-VBoxManage -Arguments @('modifyvm', $vmName, '--clipboard-mode', $Mode) | Out-Null
    }

    if (-not $script:Config.isolation) {
        $script:Config | Add-Member -NotePropertyName isolation -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    $script:Config.isolation.disableClipboard = ($Mode -eq 'disabled')
    $script:Config.isolation | Add-Member -NotePropertyName clipboardMode -NotePropertyValue $Mode -Force

    if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        if (-not $raw.isolation) {
            $raw | Add-Member -NotePropertyName isolation -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $raw.isolation.disableClipboard = ($Mode -eq 'disabled')
        $raw.isolation | Add-Member -NotePropertyName clipboardMode -NotePropertyValue $Mode -Force
        ($raw | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
    }

    if ($Mode -eq 'disabled') {
        Write-Host 'Clipboard sharing disabled.'
    } elseif ($Mode -eq 'hosttoguest') {
        Write-Host 'Clipboard set to host-to-guest. Install Guest Additions in the VM to paste from the host.'
    } elseif ($Mode -eq 'guesttohost') {
        Write-Host 'Clipboard set to guest-to-host. Guest Additions required.'
    } else {
        Write-Host 'Clipboard set to bidirectional. Guest Additions required.'
    }
}

function Set-QuarantineVMNetwork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        $Network = $script:Config.network
    )

    $mode = if ($Network.mode) { $Network.mode } else { 'intnet' }
    $mode = $mode.ToLowerInvariant()
    $intnetName = if ($Network.intnetName) { $Network.intnetName } else { 'quarantine-net' }
    $nicType = $mode
    $nicExtra = @()

    switch ($mode) {
        'hostonly' {
            $adapter = Get-QuarantineHostOnlyAdapter -PreferredName $Network.hostOnlyAdapter
            if ($adapter) {
                $nicExtra = @('--hostonlyadapter1', $adapter)
            } else {
                Write-Warning @'
Host-only networking unavailable (VirtualBox Host Interface Networking driver missing).
Falling back to intnet — VM is isolated with no host or internet access.
To repair host-only later: reinstall VirtualBox and run as Administrator:
  VBoxManage hostonlyif create
'@
                $nicType = 'intnet'
                $nicExtra = @('--intnet1', $intnetName)
            }
        }
        'intnet' {
            $nicExtra = @('--intnet1', $intnetName)
        }
        'none' {
            # no extra args
        }
        'nat' {
            Write-Warning 'NAT allows outbound internet. Use hostonly, intnet, none, or quarantine for controlled access.'
        }
        'quarantine' {
            $nicType = 'nat'
        }
        'gateway' {
            $nicType = 'intnet'
            $gwIntnet = if ($Network.gateway -and $Network.gateway.intnetName) {
                $Network.gateway.intnetName
            } elseif ($Network.intnetName) {
                $Network.intnetName
            } else {
                'quarantine-net'
            }
            $nicExtra = @('--intnet1', $gwIntnet)
        }
        default {
            throw "Unsupported network.mode '$mode'. Use hostonly, intnet, none, nat, quarantine, or gateway."
        }
    }

    $args = @('modifyvm', $VmName, '--nic1', $nicType) + $nicExtra + @('--cableconnected1', 'on')
    Invoke-VBoxManage -Arguments $args | Out-Null
}

function Set-QuarantineVMNetworkMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('nat', 'intnet', 'none', 'hostonly', 'quarantine', 'offline', 'gateway')]
        [string]$Mode,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$SkipProxy,

        [Parameter()]
        [switch]$SkipCapture
    )

    if ($Mode -eq 'offline') {
        $Mode = 'intnet'
    }

    if ($Mode -eq 'quarantine') {
        $networkModule = Join-Path $PSScriptRoot 'QuarantineNetwork.psm1'
        if (-not (Test-Path -LiteralPath $networkModule)) {
            throw "QuarantineNetwork.psm1 not found at $networkModule"
        }
        Import-Module $networkModule -Force
        Enable-QuarantineVMNetwork -ConfigPath $ConfigPath -SkipProxy:$SkipProxy -SkipCapture:$SkipCapture
        Update-QuarantineVMNetworkConfig -ConfigPath $ConfigPath -Mode 'quarantine'
        return
    }

    if ($Mode -eq 'gateway') {
        $networkModule = Join-Path $PSScriptRoot 'QuarantineNetwork.psm1'
        if (-not (Test-Path -LiteralPath $networkModule)) {
            throw "QuarantineNetwork.psm1 not found at $networkModule"
        }
        Import-Module $networkModule -Force
        Enable-QuarantineGatewayNetwork -ConfigPath $ConfigPath -SkipCapture:$SkipCapture
        Update-QuarantineVMNetworkConfig -ConfigPath $ConfigPath -Mode 'gateway'
        return
    }

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    Initialize-QuarantineVMMutable -ConfigPath $ConfigPath -VmName $vmName -Reason "set network mode to $Mode"

    $network = [pscustomobject]@{
        mode              = $Mode
        hostOnlyAdapter   = $script:Config.network.hostOnlyAdapter
        intnetName        = $script:Config.network.intnetName
        gateway           = $script:Config.network.gateway
    }

    Set-QuarantineVMNetwork -VmName $vmName -Network $network

    if ($Mode -eq 'intnet') {
        Update-QuarantineVMNetworkConfig -ConfigPath $ConfigPath -Mode 'intnet'
    }

    if ($Mode -eq 'nat') {
        Write-Warning 'NAT is enabled — VM has internet. Switch back after setup: .\quarantine-vm.ps1 network quarantine'
        Write-Warning 'Guest firewall/proxy still block Windows Update. In the guest run Open-QuarantineGuestForUpdates.ps1 as Admin.'
    } else {
        Write-Host "Network mode set to: $Mode"
    }
}

function Update-QuarantineVMNetworkConfig {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$Mode
    )

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot 'config\quarantine-vm.json'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return }

    $raw = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if (-not $raw.network) { return }
    $raw.network.mode = $Mode
    ($raw | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
}

function Format-VBoxPath {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -replace '\\', '/')
}

function Remove-QuarantineDiskMedium {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    foreach ($target in @($Path, (Format-VBoxPath -Path $Path))) {
        Invoke-VBoxManage -Arguments @('closemedium', 'disk', $target, '--delete') -AllowFailure | Out-Null
    }

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function New-VBoxDiskMedium {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [int]$SizeMb
    )

    Remove-QuarantineDiskMedium -Path $Path

    $nativePath = Format-VBoxPath -Path $Path
    $sizeBytes = [int64]$SizeMb * 1MB

    Invoke-VBoxManage -Arguments @(
        'createmedium', 'disk',
        "--filename=$nativePath",
        "--sizebyte=$sizeBytes",
        '--format=VDI',
        '--variant=Standard'
    ) | Out-Null
}

function New-QuarantineVM {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$Force
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if ((Test-QuarantineVMExists -VmName $vmName) -and -not $Force) {
        throw "VM '$vmName' already exists. Use -Force to recreate (destroys existing VM)."
    }

    if ($Force -and (Test-QuarantineVMExists -VmName $vmName)) {
        if ($PSCmdlet.ShouldProcess($vmName, 'Remove existing VM')) {
            $state = Get-QuarantineVMState -VmName $vmName
            if ($state -in @('running', 'paused')) {
                Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
                Start-Sleep -Seconds 2
            }
            Invoke-VBoxManage -Arguments @('unregistervm', $vmName, '--delete') | Out-Null
        }
    }

    $diskPath = Get-QuarantineVMDiskPath -Config $script:Config

    $diskDir = Split-Path -Parent $diskPath
    if (-not (Test-Path -LiteralPath $diskDir)) {
        New-Item -ItemType Directory -Path $diskDir -Force | Out-Null
    }

    $isoPath = Resolve-WindowsIsoPath `
        -ConfiguredPath $script:Config.windowsIsoPath `
        -GuestOsType $script:Config.guestOsType `
        -ProjectRoot $PSScriptRoot

    if ($PSCmdlet.ShouldProcess($vmName, 'Create quarantine VM')) {
        $vmBaseFolder = Get-QuarantineVMDataDir -Config $script:Config
        $vmFolder = Get-QuarantineVMFolder -Config $script:Config

        if (-not (Test-Path -LiteralPath $vmBaseFolder)) {
            New-Item -ItemType Directory -Path $vmBaseFolder -Force | Out-Null
        }

        Write-Host "Creating VM '$vmName' in $vmFolder..."
        Invoke-VBoxManage -Arguments @(
            'createvm', '--name', $vmName,
            '--ostype', $script:Config.guestOsType,
            '--basefolder', $vmBaseFolder,
            '--register'
        ) | Out-Null

        Invoke-VBoxManage -Arguments @(
            'modifyvm', $vmName,
            '--memory', [string]$script:Config.memoryMb,
            '--cpus', [string]$script:Config.cpuCount,
            '--vram', '128',
            '--graphicscontroller', 'vboxsvga',
            '--ioapic', 'on',
            '--pae', 'on',
            '--longmode', 'on',
            '--nested-hw-virt', 'off',
            '--boot1', 'dvd',
            '--boot2', 'disk',
            '--boot3', 'none',
            '--boot4', 'none'
        ) | Out-Null

        $firmware = if ($script:Config.firmware) { $script:Config.firmware } else { 'efi' }
        if ($firmware.ToLowerInvariant() -eq 'efi') {
            Invoke-VBoxManage -Arguments @('modifyvm', $vmName, '--firmware', 'efi') | Out-Null
        }

        Set-QuarantineVMInstallNat -VmName $vmName -ConfigPath $ConfigPath
        Set-QuarantineVMIsolation -VmName $vmName | Out-Null

        $diskSizeMb = [int]$script:Config.diskSizeGb * 1024
        if ($diskSizeMb -le 0) {
            throw 'diskSizeGb must be a positive number in config.'
        }

        New-VBoxDiskMedium -Path $diskPath -SizeMb $diskSizeMb

        Invoke-VBoxManage -Arguments @(
            'storagectl', $vmName,
            '--name', 'SATA',
            '--add', 'sata',
            '--controller', 'IntelAhci',
            '--portcount', '3',
            '--hostiocache', 'on'
        ) | Out-Null

        Invoke-VBoxManage -Arguments @(
            'storageattach', $vmName,
            '--storagectl', 'SATA',
            '--port', '0',
            '--device', '0',
            '--type', 'hdd',
            '--medium', $diskPath
        ) | Out-Null

        Invoke-VBoxManage -Arguments @(
            'storageattach', $vmName,
            '--storagectl', 'SATA',
            '--port', '1',
            '--device', '0',
            '--type', 'dvddrive',
            '--medium', $isoPath
        ) | Out-Null

        Invoke-VBoxManage -Arguments @('modifyvm', $vmName, '--tpm-type', 'x2') -AllowFailure | Out-Null

        Mount-QuarantineUnattendMedia -VmName $vmName -ConfigPath $ConfigPath

        Write-Host "VM '$vmName' created with isolation defaults (NAT for Setup; switch to gateway after)."
        Write-Host "Next: run '.\quarantine-vm.ps1 install' to start Windows setup, then '.\quarantine-vm.ps1 snapshot' after hardening."
    }
}

function Get-QuarantineUnattendFloppyPath {
    <#
    .SYNOPSIS
      Path to the 1.44MB unattend floppy built by setup secrets ({vmDataDir}\unattend\unattend.img).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }
    $dataDir = Get-QuarantineVMDataDir -Config $script:Config
    return (Join-Path $dataDir 'unattend\unattend.img')
}

function Get-QuarantineWindowsSetupIsoPath {
    <#
    .SYNOPSIS
      Bootable remastered Win11 ISO with autounattend.xml in the root ({vmDataDir}\unattend\Win11-setup.iso).
    #>
    [CmdletBinding()]
    param([string]$ConfigPath)
    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }
    $dataDir = Get-QuarantineVMDataDir -Config $script:Config
    return (Join-Path $dataDir 'unattend\Win11-setup.iso')
}

function Get-QuarantineUnattendIsoPath {
    <#
    .SYNOPSIS
      Sidecar answer-file ISO (fallback). Prefer Win11-setup.iso as the install DVD.
    #>
    [CmdletBinding()]
    param([string]$ConfigPath)
    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }
    $dataDir = Get-QuarantineVMDataDir -Config $script:Config
    return (Join-Path $dataDir 'unattend\unattend.iso')
}

function Mount-QuarantineUnattendMedia {
    <#
    .SYNOPSIS
      Attach unattend.img floppy (+ optional sidecar ISO) for answer file / FirstLogon helpers.
      Prefer booting from Win11-setup.iso (Set-QuarantineVMInstallMedia) so Setup sees autounattend.xml.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [string]$ConfigPath
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -in @('running', 'paused', 'starting')) {
        throw "VM '$VmName' must be powered off to attach unattend media (state: $state)."
    }

    $setupIso = Get-QuarantineWindowsSetupIsoPath -ConfigPath $ConfigPath
    $iso = Get-QuarantineUnattendIsoPath -ConfigPath $ConfigPath
    # Only attach sidecar on port 2 when the remastered boot ISO is missing.
    if (-not (Test-Path -LiteralPath $setupIso) -and (Test-Path -LiteralPath $iso)) {
        Invoke-VBoxManage -Arguments @(
            'storagectl', $VmName,
            '--name', 'SATA',
            '--portcount', '3'
        ) -AllowFailure | Out-Null

        Invoke-VBoxManage -Arguments @(
            'storageattach', $VmName,
            '--storagectl', 'SATA',
            '--port', '2',
            '--device', '0',
            '--type', 'dvddrive',
            '--medium', (Format-VBoxPath -Path $iso)
        ) | Out-Null
        Write-Host "Attached unattend sidecar ISO (SATA port 2): $iso"
    } elseif (-not (Test-Path -LiteralPath $setupIso)) {
        Write-Warning "Win11-setup.iso not found: $setupIso (run setup secrets). Unattended EFI install will fail."
    }

    Mount-QuarantineUnattendFloppy -VmName $VmName -ConfigPath $ConfigPath
}

function Mount-QuarantineUnattendFloppy {
    <#
    .SYNOPSIS
      Attach {vmDataDir}\unattend\unattend.img as the VM floppy (Windows Setup + FirstLogon).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [string]$ConfigPath
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }

    $floppy = Get-QuarantineUnattendFloppyPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $floppy)) {
        Write-Warning "Unattend floppy not found: $floppy - run .\quarantine-vm.ps1 setup secrets"
        return
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -in @('running', 'paused', 'starting')) {
        throw "VM '$VmName' must be powered off to attach the unattend floppy (state: $state)."
    }

    Invoke-VBoxManage -Arguments @(
        'storagectl', $VmName,
        '--name', 'Floppy',
        '--add', 'floppy',
        '--controller', 'I82078',
        '--portcount', '1'
    ) -AllowFailure | Out-Null

    Invoke-VBoxManage -Arguments @(
        'storageattach', $VmName,
        '--storagectl', 'Floppy',
        '--port', '0',
        '--device', '0',
        '--type', 'fdd',
        '--medium', (Format-VBoxPath -Path $floppy)
    ) | Out-Null

    Write-Host "Attached unattend floppy: $floppy"
}

function Set-QuarantineVMInstallNat {
    <#
    .SYNOPSIS
      Attach NIC1 to the Linux gateway intnet for Windows Setup/OOBE (82540EM inbox driver).
      Unattend FirstLogon configures 10.66.0.15; WAN is FakeNet or permissive via the gateway.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VmName,
        [string]$ConfigPath
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }
    $intnet = 'quarantine-net'
    if ($script:Config -and $script:Config.network) {
        if ($script:Config.network.gateway -and $script:Config.network.gateway.intnetName) {
            $intnet = [string]$script:Config.network.gateway.intnetName
        } elseif ($script:Config.network.intnetName) {
            $intnet = [string]$script:Config.network.intnetName
        }
    }

    Invoke-VBoxManage -Arguments @(
        'modifyvm', $VmName,
        '--nic1', 'intnet',
        '--intnet1', $intnet,
        '--cableconnected1', 'on',
        '--nictype1', '82540EM',
        '--nic2', 'none'
    ) | Out-Null
    Write-Host "Install network: gateway intnet '$intnet' (82540EM). Start the Linux gateway before Windows Setup."
}

function Set-QuarantineVMInstallMedia {
    <#
    .SYNOPSIS
      Attach the Windows ISO to SATA and set EFI boot order for installation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [string]$ConfigPath
    )

    if ($ConfigPath) {
        $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    }

    # Prefer remastered ISO with autounattend.xml in the boot volume root (required for EFI).
    $setupIso = Get-QuarantineWindowsSetupIsoPath -ConfigPath $ConfigPath
    if (Test-Path -LiteralPath $setupIso) {
        $isoPath = (Resolve-Path -LiteralPath $setupIso).Path
        Write-Host "Using remastered setup ISO (answer file baked in): $isoPath"
    } else {
        $isoPath = Resolve-WindowsIsoPath `
            -ConfiguredPath $script:Config.windowsIsoPath `
            -GuestOsType $script:Config.guestOsType `
            -ProjectRoot $PSScriptRoot
        Write-Warning "Win11-setup.iso missing ($setupIso). Falling back to stock ISO; Setup will likely prompt."
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM before remounting install media...'
        Invoke-VBoxManage -Arguments @('controlvm', $VmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 2
    }

    Invoke-VBoxManage -Arguments @(
        'storageattach', $VmName,
        '--storagectl', 'IDE',
        '--port', '0', '--device', '0',
        '--medium', 'none'
    ) -AllowFailure | Out-Null

    Invoke-VBoxManage -Arguments @(
        'storageattach', $VmName,
        '--storagectl', 'SATA',
        '--port', '1', '--device', '0',
        '--type', 'dvddrive',
        '--medium', (Format-VBoxPath -Path $isoPath)
    ) | Out-Null

    Invoke-VBoxManage -Arguments @(
        'modifyvm', $VmName,
        '--firmware', 'efi',
        '--boot1', 'dvd',
        '--boot2', 'disk',
        '--boot3', 'none',
        '--boot4', 'none'
    ) | Out-Null

    Invoke-VBoxManage -Arguments @('modifyvm', $VmName, '--tpm-type', 'x2') -AllowFailure | Out-Null

    Set-QuarantineVMInstallNat -VmName $VmName -ConfigPath $ConfigPath
    Mount-QuarantineUnattendMedia -VmName $VmName -ConfigPath $ConfigPath

    Write-Host "Install media mounted: $isoPath"
}

function Start-QuarantineVM {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [ValidateSet('gui', 'headless', 'separate')]
        [string]$Type = 'gui',

        [Parameter()]
        [switch]$Fresh,

        [Parameter()]
        [switch]$SkipProxy,

        [Parameter()]
        [switch]$KeepInstallMedia
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found. Run '.\quarantine-vm.ps1 create' first."
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host "VM '$vmName' is already $state."
        if (-not $SkipProxy) {
            $networkModule = Join-Path $PSScriptRoot 'QuarantineNetwork.psm1'
            if (Test-Path -LiteralPath $networkModule) {
                Import-Module $networkModule -Force
                Initialize-QuarantineNetworkServices -ConfigPath $ConfigPath -SkipProxy:$SkipProxy
            }
        }
        return
    }

    if ($Fresh -and $state -in @('saved', 'aborted')) {
        Write-Host "Discarding saved/aborted state for a clean boot..."
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
        $state = Get-QuarantineVMState -VmName $vmName
    }

    if ($state -eq 'saved') {
        if ($PSCmdlet.ShouldProcess($vmName, 'Resume saved session')) {
            Write-Host "Resuming saved session for '$vmName'..."
            Invoke-VBoxManage -Arguments @('startvm', $vmName, '--type', $Type) | Out-Null
            Write-Host "VM resumed. Treat all guest activity as hostile."
            if (-not $SkipProxy) {
                $networkModule = Join-Path $PSScriptRoot 'QuarantineNetwork.psm1'
                if (Test-Path -LiteralPath $networkModule) {
                    Import-Module $networkModule -Force
                    Initialize-QuarantineNetworkServices -ConfigPath $ConfigPath -SkipProxy:$SkipProxy
                }
            }
        }
        return
    }

    if ($state -in @('aborted', 'stuck')) {
        Write-Host "Discarding unusable VM state ($state)..."
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    }

    if ($KeepInstallMedia) {
        # First-time Windows Setup: keep ISO attached and prefer DVD boot.
        # (NormalBoot ejects the ISO - that was breaking build-windows / install.)
        Write-Host 'Keeping install ISO attached (DVD boot for Windows Setup).'
        # Ensure host CPU profile - stealth Skylake profile causes EFI Win11 triple-fault.
        Invoke-VBoxManage -Arguments @('modifyvm', $vmName, '--cpu-profile', 'host') -AllowFailure | Out-Null
        Set-QuarantineVMIsolation -VmName $vmName | Out-Null
    } else {
        Set-QuarantineVMNormalBoot -VmName $vmName | Out-Null
        Set-QuarantineVMIsolation -VmName $vmName | Out-Null
    }
    $networkMode = if ($script:Config.network.mode) { $script:Config.network.mode.ToLowerInvariant() } else { '' }
    if ($networkMode -eq 'quarantine' -and -not $SkipProxy) {
        $networkModule = Join-Path $PSScriptRoot 'QuarantineNetwork.psm1'
        if (Test-Path -LiteralPath $networkModule) {
            Import-Module $networkModule -Force
            if ($script:Config.network.proxy.enabled) {
                Start-QuarantineProxy -ConfigPath $ConfigPath
            }
            if ($script:Config.network.capture.enabled) {
                Start-QuarantineCapture -ConfigPath $ConfigPath
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Start ($Type)")) {
        Write-Host "Starting '$vmName' ($Type)..."
        Invoke-VBoxManage -Arguments @('startvm', $vmName, '--type', $Type) | Out-Null
        Write-Host "VM started. Treat all guest activity as hostile."
    }
}

function Stop-QuarantineVM {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$Force
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $state = Get-QuarantineVMState -VmName $vmName

    if ($state -notin @('running', 'paused', 'stuck', 'teleporting')) {
        Write-Host "VM '$vmName' is not running (state: $state)."
        return
    }

    $action = if ($Force) { @('poweroff') } else { @('acpipowerbutton') }

    Close-QuarantineVMInbox -ConfigPath $ConfigPath

    if ($PSCmdlet.ShouldProcess($vmName, ($action -join ' '))) {
        Invoke-VBoxManage -Arguments (@('controlvm', $vmName) + $action) | Out-Null
        Write-Host "Stop signal sent to '$vmName'."
    }
}

function Clear-QuarantineVMSnapshots {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $lines = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable') -AllowFailure
    $uuids = @()
    if ($LASTEXITCODE -eq 0) {
        foreach ($line in $lines) {
            if ($line -match '^SnapshotUUID((?:-[0-9]+)*)="([^"]+)"$') {
                $uuids += $Matches[2]
            }
        }
    }

    if ($uuids.Count -eq 0) {
        Write-Host 'No snapshots to delete.'
        return
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM before deleting snapshots...'
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 3
    }
    if ((Get-QuarantineVMState -VmName $vmName) -eq 'saved') {
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Delete $($uuids.Count) snapshot(s) and merge to disk")) {
        [array]::Reverse($uuids)
        foreach ($uuid in $uuids) {
            Write-Host "Deleting snapshot $uuid..."
            Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'delete', $uuid) | Out-Null
        }
        Write-Host 'All snapshots removed; disk flattened to current state.'
    }
}

function Remove-QuarantineVMSnapshotsByUuid {
    <#
    .SYNOPSIS
      Delete specific snapshots by UUID (deepest in tree first). Pass descendant UUIDs as
      well when replacing a branch — VirtualBox cannot delete a snapshot with more than
      one child, or the current snapshot while it still has children.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string[]]$Uuid,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$SkipUuid,

        [Parameter()]
        [switch]$RemoveManifests
    )

    $wanted = @($Uuid | Where-Object { $_ -and $_ -ne $SkipUuid } | Select-Object -Unique)
    if ($wanted.Count -eq 0) {
        return
    }

    $tree = @(Get-QuarantineVMSnapshotTreeEntries -ConfigPath $ConfigPath)
    $wantedSet = @{}
    foreach ($id in $wanted) { $wantedSet[$id] = $true }

    $sorted = @(
        $tree |
            Where-Object { $wantedSet.ContainsKey($_.UUID) } |
            Sort-Object { $_.Suffix.Length } -Descending
    )
    foreach ($id in $wanted) {
        if (-not ($sorted | Where-Object { $_.UUID -eq $id })) {
            $sorted += [pscustomobject]@{ Suffix = ''; Name = $id; UUID = $id }
        }
    }

    $manifestModule = Join-Path $PSScriptRoot 'manifest\QuarantineManifest.psm1'
    foreach ($entry in $sorted) {
        if ($SkipUuid -and $entry.UUID -eq $SkipUuid) { continue }
        if ($PSCmdlet.ShouldProcess($VmName, "Delete snapshot '$($entry.Name)' ($($entry.UUID))")) {
            Write-Host "Deleting snapshot '$($entry.Name)' ($($entry.UUID))..."
            try {
                Invoke-VBoxManage -Arguments @('snapshot', $VmName, 'delete', $entry.UUID) | Out-Null
            } catch {
                throw "Failed to delete snapshot '$($entry.Name)' ($($entry.UUID)). $($_.Exception.Message)"
            }
            if ($RemoveManifests) {
                try {
                    if (Test-Path -LiteralPath $manifestModule) {
                        Import-Module $manifestModule -Force -ErrorAction Stop
                        $removed = @(Remove-QuarantineSnapshotManifestArtifacts -ConfigPath $ConfigPath -SnapshotName $entry.Name)
                        foreach ($path in $removed) {
                            Write-Host "  Removed manifest artifact: $path"
                        }
                    }
                } catch {
                    Write-Warning "Manifest cleanup failed for '$($entry.Name)': $($_.Exception.Message)"
                }
            }
        }
    }
}

function New-QuarantineVMBaseline {
    <#
    .SYNOPSIS
      Delete all snapshots, merge current disk state, and save a fresh Clean baseline.
      Flattening requires the VM off, so this Clean is disk-only. For a logged-in
      resume point, start the VM, log in, then run snapshot while it is running.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string]$Description
    )

    Clear-QuarantineVMSnapshots -ConfigPath $ConfigPath
    Save-QuarantineVMSnapshot -ConfigPath $ConfigPath -Name $Name -Description $Description -Offline
    Write-Host 'Baseline is disk-only (flatten requires power-off). For reset-to-desktop: start, log in, then:'
    Write-Host '  .\quarantine-vm.ps1 snapshot'
    Write-Host '  (creates live CleanSession — then use reset -Clean to resume it)'
}

function Save-QuarantineVMSnapshot {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$Offline
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $snapshotName = if (-not [string]::IsNullOrWhiteSpace($Name)) { $Name } else { $null }
    $description = $Description

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -eq 'starting') {
        Write-Host 'Waiting for VM to finish starting before snapshot...'
        $deadline = (Get-Date).AddSeconds(60)
        do {
            Start-Sleep -Seconds 2
            $state = Get-QuarantineVMState -VmName $vmName
        } while ($state -eq 'starting' -and (Get-Date) -lt $deadline)
    }

    $liveStates = @('running', 'paused', 'saved')
    if ($Offline -and $state -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM for a disk-only snapshot (restore will cold-boot)...'
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 3
        $state = Get-QuarantineVMState -VmName $vmName
    }
    if ($Offline -and $state -eq 'saved') {
        Write-Host 'Discarding saved RAM so this snapshot is disk-only...'
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
        $state = Get-QuarantineVMState -VmName $vmName
    }

    $includesRam = (-not $Offline) -and ($state -in $liveStates)

    $sessionName = if ($script:Config.manifest -and $script:Config.manifest.sessionBaselineSnapshot) {
        [string]$script:Config.manifest.sessionBaselineSnapshot
    } else {
        'CleanSession'
    }
    $diskName = if ($script:Config.cleanSnapshotName) {
        [string]$script:Config.cleanSnapshotName
    } else {
        'Clean'
    }
    # Live → CleanSession (daily desktop). Disk-only → Clean (golden image).
    if ([string]::IsNullOrWhiteSpace($snapshotName)) {
        $snapshotName = if ($includesRam) { $sessionName } else { $diskName }
    }
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = if ($includesRam) {
            'Live clean desktop (resume with reset -Clean).'
        } else {
            'Disk-only clean baseline.'
        }
    }

    $existing = @(Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath | Where-Object {
        $_.Name -eq $snapshotName
    })
    $replaceUuids = @()
    if ($existing.Count -gt 0) {
        $details = ($existing | ForEach-Object {
            $when = if ($_.TakenAt -ne [datetime]::MinValue) {
                $_.TakenAt.ToString('yyyy-MM-dd HH:mm')
            } else {
                'unknown time'
            }
            $kind = if ($_.HasSavedState) { 'live' } else { 'disk' }
            "  $($_.Name)  $when  $kind  $($_.UUID)"
        }) -join [Environment]::NewLine

        $tree = @(Get-QuarantineVMSnapshotTreeEntries -ConfigPath $ConfigPath)
        $replaceUuidSet = @{}
        $childNames = [System.Collections.Generic.List[string]]::new()
        foreach ($snap in $existing) {
            $replaceUuidSet[$snap.UUID] = $true
            foreach ($descUuid in @(Get-QuarantineVMSnapshotDescendantUuids -TargetUuid $snap.UUID -TreeEntries $tree)) {
                $replaceUuidSet[$descUuid] = $true
            }
        }
        foreach ($entry in $tree) {
            if (-not $replaceUuidSet.ContainsKey($entry.UUID)) { continue }
            if ($entry.Name -ne $snapshotName -and $childNames -notcontains $entry.Name) {
                $childNames.Add($entry.Name) | Out-Null
            }
        }
        $replaceUuids = @($replaceUuidSet.Keys)

        if (-not $Force) {
            Write-Host "Snapshot '$snapshotName' already exists ($($existing.Count)):"
            Write-Host $details
            if ($childNames.Count -gt 0) {
                Write-Host 'Child snapshots will be deleted:'
                foreach ($childName in $childNames) {
                    Write-Host "  $childName"
                }
            }
            $newKind = if ($includesRam) { 'live (RAM + disk)' } else { 'disk-only' }
            $reply = Read-Host "Replace with a new $newKind snapshot? [y/N]"
            if ($reply -notmatch '^[yY](es)?$') {
                Write-Host 'Cancelled — snapshot not saved.'
                return
            }
        } else {
            Write-Host "Replacing $($existing.Count) existing snapshot(s) named '$snapshotName' (-Force)..."
            if ($childNames.Count -gt 0) {
                Write-Host ('Deleting child snapshot(s): ' + ($childNames -join ', '))
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Snapshot '$snapshotName'")) {
        if ($replaceUuids.Count -gt 0) {
            Write-Host "Deleting previous '$snapshotName' branch ($($replaceUuids.Count) snapshot(s))..."
            Remove-QuarantineVMSnapshotsByUuid -ConfigPath $ConfigPath -VmName $vmName `
                -Uuid $replaceUuids -RemoveManifests
            $state = Get-QuarantineVMState -VmName $vmName
            if (-not $Offline) {
                $includesRam = $state -in $liveStates
            }
        }

        if ($includesRam) {
            if ($state -in @('running', 'paused')) {
                Write-Host "Taking live snapshot (RAM + disk). VM pauses briefly, then keeps running..."
            } else {
                Write-Host "Taking snapshot of saved session (RAM + disk)..."
            }
        } else {
            Write-Host "Taking disk-only snapshot. Restore will cold-boot (firmware POST + login)."
        }

        $snapArgs = @(
            'snapshot', $vmName, 'take', $snapshotName,
            '--description', $description
        )
        Invoke-VBoxManage -Arguments $snapArgs | Out-Null
        $uuid = $null
        foreach ($line in (Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable'))) {
            if ($line -match '^CurrentSnapshotUUID="([^"]+)"$') {
                $uuid = $Matches[1]
                break
            }
        }
        Write-Host "Snapshot '$snapshotName' saved."
        if ($uuid) {
            Write-Host "  UUID: $uuid"
        }
        if ($includesRam) {
            Write-Host '  Kind: live (restore resumes this logged-in session, no POST)'
        } else {
            Write-Host '  Kind: disk-only (restore cold-boots Windows)'
        }
        Write-Host "  Folder: $(Join-Path (Get-QuarantineVMFolder -Config $script:Config) 'Snapshots')"

        if ($includesRam) {
            try {
                $manifestModule = Join-Path $PSScriptRoot 'manifest\QuarantineManifest.psm1'
                Import-Module $manifestModule -Force -ErrorAction Stop
                $markConfig = if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
                    $ConfigPath
                } else {
                    Join-Path $PSScriptRoot 'config\quarantine-vm.json'
                }
                Invoke-QuarantineLiveSnapshotManifestMark -ConfigPath $markConfig -SnapshotName $snapshotName `
                    -SkipGuestReadyWait -TimeoutMs 900000
            } catch {
                Write-Warning "Live snapshot USN/registry mark failed: $($_.Exception.Message)"
                Write-Host 'Retry: .\quarantine-vm.ps1 manifest mark -SnapshotName' $snapshotName
            }
        }
    }
}

function Save-QuarantineVMEvidence {
    <#
    .SYNOPSIS
      Save the current (possibly compromised) VM state under a timestamped snapshot for later analysis.
      Does not modify the Clean baseline. Running VMs are snapshotted live (RAM included).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Label,

        [Parameter()]
        [switch]$Offline
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $suffix = if (-not [string]::IsNullOrWhiteSpace($Label)) {
        ($Label -replace '[^\w\-]', '-')
    } else {
        $timestamp
    }
    $name = "Evidence-$suffix"
    $description = "Preserved session state ($timestamp). Possibly compromised - for analysis only."

    Save-QuarantineVMSnapshot -ConfigPath $ConfigPath -Name $name -Description $description -Offline:$Offline
    Write-Host "Evidence snapshot: $name"
    Write-Host "Return to Clean baseline: .\quarantine-vm.ps1 reset -Clean"
    Write-Host "Re-open this evidence:   .\quarantine-vm.ps1 reset"
}

function ConvertTo-QuarantineVMSnapshotLocalTime {
    param([string]$Timestamp)

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        return $null
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    try {
        $utc = [datetime]::Parse($Timestamp, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
        return $utc.ToLocalTime()
    } catch {
        return $null
    }
}

function Get-QuarantineVMSnapshotXmlMeta {
    <#
    .SYNOPSIS
      Map snapshot UUID -> taken-at and whether the snapshot includes saved RAM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    $map = @{}
    $cfgFile = Get-QuarantineVMCfgFile -VmName $VmName
    if (-not $cfgFile -or -not (Test-Path -LiteralPath $cfgFile)) {
        return $map
    }

    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($cfgFile)
    foreach ($node in $xml.SelectNodes('//*[local-name()="Snapshot"]')) {
        $uuid = ($node.GetAttribute('uuid') -replace '[{}]', '')
        if (-not $uuid) { continue }
        $ts = $node.GetAttribute('timeStamp')
        $stateFile = $node.GetAttribute('stateFile')
        $local = if ($ts) { ConvertTo-QuarantineVMSnapshotLocalTime -Timestamp $ts } else { $null }
        $map[$uuid] = @{
            TakenAt       = $local
            HasSavedState = -not [string]::IsNullOrWhiteSpace($stateFile)
        }
    }

    return $map
}

function Format-QuarantineVMSnapshotWhen {
    param($Snapshot)

    if ($Snapshot.TakenAt -and $Snapshot.TakenAt -ne [datetime]::MinValue) {
        return $Snapshot.TakenAt.ToString('yyyy-MM-dd HH:mm')
    }
    return 'unknown time'
}

function Get-QuarantineVMSnapshotList {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $lines = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable') -AllowFailure
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $currentUuid = $null
    $orderedSuffixes = [System.Collections.Generic.List[string]]::new()
    $entries = @{}

    foreach ($line in $lines) {
        if ($line -match '^CurrentSnapshotUUID="([^"]+)"$') {
            $currentUuid = $Matches[1]
        }
        if ($line -match '^(SnapshotName|SnapshotUUID|SnapshotDescription)((?:-[0-9]+)*)="(.*)"$') {
            $field = $Matches[1]
            $suffix = $Matches[2]
            $value = $Matches[3]

            if (-not $entries.ContainsKey($suffix)) {
                $entries[$suffix] = @{}
                $orderedSuffixes.Add($suffix) | Out-Null
            }
            $entries[$suffix][$field] = $value
        }
    }

    $xmlMeta = Get-QuarantineVMSnapshotXmlMeta -VmName $vmName
    $nameCounts = @{}
    foreach ($suffix in $orderedSuffixes) {
        $n = $entries[$suffix]['SnapshotName']
        if ($n) {
            if (-not $nameCounts.ContainsKey($n)) { $nameCounts[$n] = 0 }
            $nameCounts[$n]++
        }
    }

    $results = @()
    foreach ($suffix in $orderedSuffixes) {
        $entry = $entries[$suffix]
        $name = $entry['SnapshotName']
        $uuid = $entry['SnapshotUUID']
        $description = $entry['SnapshotDescription']

        $takenAt = $null
        $hasSavedState = $false
        if ($uuid -and $xmlMeta.ContainsKey($uuid)) {
            $meta = $xmlMeta[$uuid]
            $takenAt = $meta.TakenAt
            $hasSavedState = [bool]$meta.HasSavedState
        }
        if (-not $takenAt -and $name -match 'Evidence-(\d{8})-(\d{6})') {
            $takenAt = [datetime]::ParseExact(
                "$($Matches[1])$($Matches[2])", 'yyyyMMddHHmmss', $null)
        }
        if (-not $takenAt -and $uuid) {
            $snapDir = Join-Path (Get-QuarantineVMFolder -Config $script:Config) 'Snapshots'
            $vdi = Get-ChildItem -LiteralPath $snapDir -Filter "*$uuid*" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($vdi) { $takenAt = $vdi.LastWriteTime }
        }

        $results += [pscustomobject]@{
            Name          = $name
            UUID          = $uuid
            Description   = $description
            TakenAt       = if ($takenAt) { $takenAt } else { [datetime]::MinValue }
            IsCurrent     = ($uuid -eq $currentUuid)
            NameIsDup     = ($name -and $nameCounts[$name] -gt 1)
            HasSavedState = $hasSavedState
        }
    }

    return $results
}

function Format-QuarantineVMSnapshotDupList {
    param([object[]]$Snapshots)

    return (
        $Snapshots | ForEach-Object {
            $mark = if ($_.IsCurrent) { '  [current]' } else { '' }
            "  $($_.Name)  $(Format-QuarantineVMSnapshotWhen $_)  $($_.UUID)$mark"
        }
    ) -join [Environment]::NewLine
}

function Resolve-QuarantineVMSnapshot {
    <#
    .SYNOPSIS
      Resolve a snapshot to a unique object (exact, Evidence- prefix, or unique partial match).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$Clean
    )

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot 'config\quarantine-vm.json'
    }

    Initialize-QuarantineVMContext -ConfigPath $ConfigPath | Out-Null
    $snapshots = @(Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath)
    if ($snapshots.Count -eq 0) {
        throw @'
No snapshots found. The VM disk is still intact (powered off with no restore point).

Create a Clean baseline now:
  .\quarantine-vm.ps1 snapshot -SnapshotName Clean

Or after setup:
  .\quarantine-vm.ps1 baseline
'@
    }

    if ($Clean) {
        $sessionName = if ($script:Config.manifest -and $script:Config.manifest.sessionBaselineSnapshot) {
            [string]$script:Config.manifest.sessionBaselineSnapshot
        } else {
            'CleanSession'
        }
        $diskName = if ($script:Config.cleanSnapshotName) { [string]$script:Config.cleanSnapshotName } else { 'Clean' }
        $matches = @($snapshots | Where-Object { $_.Name -eq $sessionName })
        if ($matches.Count -eq 0) {
            $matches = @($snapshots | Where-Object { $_.Name -eq $diskName })
        }
        if ($matches.Count -eq 0) {
            throw "No clean snapshot found (tried '$sessionName' then '$diskName'). Take CleanSession while logged in, or run baseline."
        }
        if ($matches.Count -eq 1) {
            return $matches[0]
        }

        $current = @($matches | Where-Object { $_.IsCurrent })
        $pick = if ($current.Count -eq 1) {
            $current[0]
        } else {
            $matches | Sort-Object TakenAt | Select-Object -Last 1
        }
        Write-Warning "Multiple snapshots named '$($pick.Name)'. Restoring $($pick.UUID) taken $(Format-QuarantineVMSnapshotWhen $pick)."
        return $pick
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'Snapshot name is required.'
    }

    $exact = @($snapshots | Where-Object { $_.Name -eq $Name })
    if ($exact.Count -eq 1) {
        return $exact[0]
    }
    if ($exact.Count -gt 1) {
        throw @"
Snapshot '$Name' is ambiguous ($($exact.Count) snapshots share that name). Use .\quarantine-vm.ps1 reset and pick by number.

$(Format-QuarantineVMSnapshotDupList -Snapshots $exact)
"@
    }

    $withEvidence = "Evidence-$Name"
    $evidence = @($snapshots | Where-Object { $_.Name -eq $withEvidence })
    if ($evidence.Count -eq 1) {
        Write-Host "Resolved snapshot '$Name' -> '$withEvidence'"
        return $evidence[0]
    }
    if ($evidence.Count -gt 1) {
        throw @"
Snapshot '$withEvidence' is ambiguous.

$(Format-QuarantineVMSnapshotDupList -Snapshots $evidence)
"@
    }

    $partial = @($snapshots | Where-Object { $_.Name -like "*$Name*" })
    if ($partial.Count -eq 1) {
        Write-Host "Resolved snapshot '$Name' -> '$($partial[0].Name)'"
        return $partial[0]
    }

    $list = Format-QuarantineVMSnapshotDupList -Snapshots $snapshots
    if ($partial.Count -gt 1) {
        throw @"
Snapshot '$Name' is ambiguous. Matches:
$(Format-QuarantineVMSnapshotDupList -Snapshots $partial)
Use the exact snapshot name from: .\quarantine-vm.ps1 snapshots
"@
    }

    throw @"
Snapshot '$Name' not found.

Available snapshots:
$list

Tip: preserve creates 'Evidence-<label>' — use that full name or just the label (e.g. testdiff -> Evidence-testdiff).
"@
}

function Resolve-QuarantineVMSnapshotName {
    <#
    .SYNOPSIS
      Resolve a snapshot name (exact, Evidence- prefix, or unique partial match).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$ConfigPath
    )

    $snap = Resolve-QuarantineVMSnapshot -Name $Name -ConfigPath $ConfigPath
    return $snap.Name
}

function Get-QuarantineVMSnapshotTreeEntries {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $lines = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable') -AllowFailure
    if ($LASTEXITCODE -ne 0) { return @() }

    $orderedSuffixes = [System.Collections.Generic.List[string]]::new()
    $entries = @{}
    foreach ($line in $lines) {
        if ($line -match '^(SnapshotName|SnapshotUUID)((?:-[0-9]+)*)="(.*)"$') {
            $field = $Matches[1]
            $suffix = $Matches[2]
            $value = $Matches[3]
            if (-not $entries.ContainsKey($suffix)) {
                $entries[$suffix] = @{}
                $orderedSuffixes.Add($suffix) | Out-Null
            }
            $entries[$suffix][$field] = $value
        }
    }

    $results = @()
    foreach ($suffix in $orderedSuffixes) {
        $entry = $entries[$suffix]
        $results += [pscustomobject]@{
            Suffix = $suffix
            Name   = $entry['SnapshotName']
            UUID   = $entry['SnapshotUUID']
        }
    }
    return $results
}

function Get-QuarantineVMSnapshotDescendantUuids {
    param(
        [Parameter(Mandatory)][string]$TargetUuid,
        [Parameter(Mandatory)][array]$TreeEntries
    )

    $target = @($TreeEntries | Where-Object { $_.UUID -eq $TargetUuid } | Select-Object -First 1)
    if (-not $target) { return @() }

    $parentSuffix = [string]$target.Suffix
    $descendants = @($TreeEntries | Where-Object {
        $_.Suffix -ne $parentSuffix -and $_.Suffix -like "$parentSuffix-*"
    })
    return @($descendants | ForEach-Object { $_.UUID })
}

function Remove-QuarantineVMSnapshot {
    <#
    .SYNOPSIS
      Delete one snapshot (and optional descendants) plus host manifest sidecars.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$SnapshotName,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$KeepManifests
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    if ([string]::IsNullOrWhiteSpace($SnapshotName)) {
        $picked = Select-QuarantineVMSnapshot -ConfigPath $ConfigPath `
            -Prompt 'Select snapshot to delete:' -CancelMessage 'Delete cancelled.'
        $SnapshotName = $picked.Name
    } else {
        $SnapshotName = Resolve-QuarantineVMSnapshotName -Name $SnapshotName -ConfigPath $ConfigPath
    }

    $snapshots = @(Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath)
    $target = $snapshots | Where-Object { $_.Name -eq $SnapshotName } | Select-Object -First 1
    if (-not $target) {
        throw "Snapshot '$SnapshotName' not found."
    }

    $protected = @()
    if ($script:Config.cleanSnapshotName) { $protected += [string]$script:Config.cleanSnapshotName }
    if ($script:Config.manifest -and $script:Config.manifest.sessionBaselineSnapshot) {
        $protected += [string]$script:Config.manifest.sessionBaselineSnapshot
    }
    $protected = @($protected | Select-Object -Unique)
    if ($protected -contains $SnapshotName -and -not $Force) {
        throw "Refusing to delete protected baseline '$SnapshotName'. Pass -Force if you really mean it."
    }

    $tree = @(Get-QuarantineVMSnapshotTreeEntries -ConfigPath $ConfigPath)
    $childUuids = @(Get-QuarantineVMSnapshotDescendantUuids -TargetUuid $target.UUID -TreeEntries $tree)
    $childNames = @($tree | Where-Object { $_.UUID -in $childUuids } | ForEach-Object { $_.Name })

    if ($childNames.Count -gt 0 -and -not $Force) {
        $childList = ($childNames | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
        throw @"
Cannot delete '$SnapshotName' while child snapshots exist. Delete children first or pass -Force to delete the whole branch:

$childList
"@
    }

    $deleteUuids = @{ $target.UUID = $true }
    foreach ($uuid in $childUuids) { $deleteUuids[$uuid] = $true }
    $sortedDeletes = @(
        $tree |
            Where-Object { $deleteUuids.ContainsKey($_.UUID) } |
            Sort-Object { $_.Suffix.Length } -Descending
    )

    if ($childNames.Count -gt 0) {
        Write-Host "Deleting snapshot branch ($($sortedDeletes.Count) snapshot(s))..."
    } else {
        Write-Host "Deleting snapshot '$SnapshotName'..."
    }

    if (-not $Force) {
        $reply = Read-Host 'Continue? [y/N]'
        if ($reply -notmatch '^[yY](es)?$') {
            Write-Host 'Cancelled.'
            return
        }
    }

    foreach ($entry in $sortedDeletes) {
        $snapName = $entry.Name
        $snapUuid = $entry.UUID
        if ($PSCmdlet.ShouldProcess($vmName, "Delete snapshot '$snapName' ($snapUuid)")) {
            Write-Host "Deleting '$snapName' ($snapUuid)..."
            try {
                Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'delete', $snapUuid) | Out-Null
            } catch {
                throw "Failed to delete snapshot '$snapName': $($_.Exception.Message)"
            }
            if (-not $KeepManifests) {
                try {
                    $manifestModule = Join-Path $PSScriptRoot 'manifest\QuarantineManifest.psm1'
                    if (Test-Path -LiteralPath $manifestModule) {
                        Import-Module $manifestModule -Force -ErrorAction Stop
                        $removed = @(Remove-QuarantineSnapshotManifestArtifacts -ConfigPath $ConfigPath -SnapshotName $snapName)
                        foreach ($path in $removed) {
                            Write-Host "  Removed manifest artifact: $path"
                        }
                    }
                } catch {
                    Write-Warning "Manifest cleanup failed for '$snapName': $($_.Exception.Message)"
                }
            }
        }
    }

    Write-Host "Snapshot delete complete."
}

function Select-QuarantineVMSnapshot {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Prompt = 'Select snapshot to restore:',

        [Parameter()]
        [string]$CancelMessage = 'Restore cancelled.'
    )

    $snapshots = Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath
    if ($snapshots.Count -eq 0) {
        throw @'
No snapshots found. The VM disk is still intact (powered off with no restore point).

Create a Clean baseline now:
  .\quarantine-vm.ps1 snapshot -SnapshotName Clean

Or wipe and recreate in one step (only if no snapshots exist):
  .\quarantine-vm.ps1 baseline
'@
    }

    Write-Host ''
    Write-Host $Prompt
    Write-Host ''

    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        $s = $snapshots[$i]
        $when = if ($s.TakenAt -ne [datetime]::MinValue) {
            $s.TakenAt.ToString('yyyy-MM-dd HH:mm')
        } else {
            'unknown time'
        }
        $current = if ($s.IsCurrent) { '  [current]' } else { '' }
        $shortUuid = if ($s.UUID) { $s.UUID.Substring(0, [Math]::Min(8, $s.UUID.Length)) } else { '' }
        Write-Host ("  [{0}] {1}  ({2})  {3}{4}" -f ($i + 1), $s.Name, $when, $shortUuid, $current)
        if ($s.Description) {
            Write-Host "       $($s.Description)"
        }
    }

    Write-Host ''
    Write-Host '  [0] Cancel'
    Write-Host ''

    do {
        $choice = Read-Host 'Enter number'
        if ($choice -eq '0') {
            throw $CancelMessage
        }
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $snapshots.Count) {
            return $snapshots[[int]$choice - 1]
        }
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
    } while ($true)
}

function Get-QuarantineVMSnapshots {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    Write-Host "Snapshots for '$vmName':"
    Write-Host "  $(Join-Path (Get-QuarantineVMFolder -Config $script:Config) 'Snapshots')"
    Write-Host ''

    $listed = @(Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath)
    foreach ($s in $listed) {
        $when = if ($s.TakenAt -ne [datetime]::MinValue) {
            $s.TakenAt.ToString('yyyy-MM-dd HH:mm')
        } else {
            'unknown'
        }
        $current = if ($s.IsCurrent) { ' *' } else { '' }
        $kind = if ($s.HasSavedState) { 'live' } else { 'disk' }
        $shortUuid = if ($s.UUID) { $s.UUID.Substring(0, [Math]::Min(8, $s.UUID.Length)) } else { '' }
        Write-Host "  $($s.Name)  ($when)  $kind  $shortUuid$current"
        if ($s.Description) {
            Write-Host "    $($s.Description)"
        }
    }

    if ($listed.Count -eq 0) {
        Write-Host '  (none)'
        Write-Host ''
        Write-Host 'Create a baseline:  .\quarantine-vm.ps1 snapshot -SnapshotName Clean'
        Write-Host 'Or after setup:       .\quarantine-vm.ps1 baseline'
    }
}

function Reset-QuarantineVM {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$SnapshotName,

        [Parameter()]
        [switch]$Clean
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if ($Clean) {
        $snap = Resolve-QuarantineVMSnapshot -ConfigPath $ConfigPath -Clean
    } elseif (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {
        $snap = Resolve-QuarantineVMSnapshot -Name $SnapshotName -ConfigPath $ConfigPath
    } else {
        $snap = Select-QuarantineVMSnapshot -ConfigPath $ConfigPath
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused')) {
        Close-QuarantineVMInbox -ConfigPath $ConfigPath
        Stop-QuarantineVM -ConfigPath $ConfigPath -Force
        Start-Sleep -Seconds 3
    }

    $label = "$($snap.Name) ($($snap.UUID))"
    if ($PSCmdlet.ShouldProcess($vmName, "Restore snapshot $label")) {
        Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'restore', $snap.UUID) | Out-Null
        $kind = if ($snap.HasSavedState) { 'live (saved RAM — start resumes the session, no POST)' } else { 'disk-only (start cold-boots Windows)' }
        Write-Host "Restored '$vmName' to snapshot '$($snap.Name)'."
        Write-Host "  UUID: $($snap.UUID)  taken $(Format-QuarantineVMSnapshotWhen $snap)"
        Write-Host "  Kind: $kind"
    }
    return $snap
}

function Get-QuarantineVMStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $state = Get-QuarantineVMState -VmName $vmName

    [pscustomobject]@{
        VmName        = $vmName
        State         = $state
        NetworkMode   = $script:Config.network.mode
        CleanSnapshot = $script:Config.cleanSnapshotName
        VmDataDir     = Get-QuarantineVMDataDir -Config $script:Config
        VmFolder      = Get-QuarantineVMFolder -Config $script:Config
        DiskPath      = Get-QuarantineVMDiskPath -Config $script:Config
        ConfigFile    = if (Test-QuarantineVMExists -VmName $vmName) { Get-QuarantineVMCfgFile -VmName $vmName } else { $null }
        Exists        = ($state -ne 'notfound')
    }
}

function Wait-QuarantineVMGuestControlReady {
    <#
    .SYNOPSIS
      Poll guestcontrol until credentials work or timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [int]$TimeoutMinutes = 90,

        [Parameter()]
        [int]$PollSeconds = 20
    )

    if ($TimeoutMinutes -le 0) {
        throw 'TimeoutMinutes must be > 0'
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $cfg = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $cfg.vmName
    Write-Host "Waiting up to $TimeoutMinutes min for guest control on '$vmName' (FirstLogon + Guest Additions)..."
    Write-Host 'When the desktop appears, in a second host terminal run:'
    Write-Host '  .\quarantine-vm.ps1 guest-additions'
    Write-Host 'Then in the guest install from the DVD and reboot.'
    while ((Get-Date) -lt $deadline) {
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -eq 'notfound') {
            throw "VM '$vmName' disappeared while waiting."
        }
        if ($state -notin @('running', 'paused', 'starting')) {
            Write-Host "  state=$state - start the VM if it powered off after setup."
            Start-Sleep -Seconds $PollSeconds
            continue
        }
        try {
            if (Test-QuarantineVMGuestControl -ConfigPath $ConfigPath) {
                Write-Host 'Guest control is ready.'
                return
            }
        } catch {
            Write-Host ("  not ready: " + $_.Exception.Message)
        }
        Start-Sleep -Seconds $PollSeconds
    }
    throw (
        "Timed out after $TimeoutMinutes minutes waiting for guest control.`n`n" +
        "Complete in the VM GUI:`n" +
        "  1. Press a key when prompted to boot from the Windows ISO.`n" +
        "  2. Wait for unattend + FirstLogon (accounts + elevated provision).`n" +
        "  3. .\quarantine-vm.ps1 guest-additions  then install from the DVD and reboot.`n" +
        "  4. Re-run: .\quarantine-vm.ps1 build-windows -Continue"
    )
}

function Invoke-QuarantineWindowsBuild {
    <#
    .SYNOPSIS
      One-shot host bootstrap: secrets, create Windows VM, start unattended install,
      optionally wait for guest control and stage post-GA provision files.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$ProjectRoot,

        [Parameter()]
        [string]$CliExe,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [int]$WaitMinutes = 90,

        [Parameter()]
        [switch]$NoWait,

        [Parameter()]
        [switch]$Continue
    )

    if (-not $ProjectRoot) { $ProjectRoot = $PSScriptRoot }
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $ProjectRoot 'config\quarantine-vm.json'
    }

    $example = Join-Path $ProjectRoot 'config\quarantine-vm.example.json'
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        if (-not (Test-Path -LiteralPath $example)) {
            throw "Missing config and example: $ConfigPath"
        }
        $cfgDir = Split-Path -Parent $ConfigPath
        if (-not (Test-Path -LiteralPath $cfgDir)) {
            New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $example -Destination $ConfigPath
        Write-Host "Created $ConfigPath from example."
    }

    $sysmonExe = Join-Path $ProjectRoot 'tools\Sysmon64.exe'
    if (-not (Test-Path -LiteralPath $sysmonExe)) {
        $getSysmon = Join-Path $ProjectRoot 'scripts\Get-Sysmon.ps1'
        if (Test-Path -LiteralPath $getSysmon) {
            Write-Host 'Downloading Sysmon...'
            & $getSysmon -ProjectRoot $ProjectRoot
        } else {
            Write-Warning 'Sysmon64.exe missing and scripts\Get-Sysmon.ps1 not found.'
        }
    }

    if ($CliExe -and (Test-Path -LiteralPath $CliExe)) {
        Write-Host 'Generating secrets + unattend floppy...'
        & (Get-Item -LiteralPath $CliExe).FullName --config $ConfigPath setup secrets
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "setup secrets failed (exit $LASTEXITCODE)"
        }
    } else {
        Write-Warning 'CLI binary not available; run: .\quarantine-vm.ps1 setup secrets'
    }

    $cfg = Initialize-QuarantineVMContext -ConfigPath $ConfigPath
    $vmName = $cfg.vmName
    $floppy = Get-QuarantineUnattendFloppyPath -ConfigPath $ConfigPath
    $setupIso = Get-QuarantineWindowsSetupIsoPath -ConfigPath $ConfigPath
    $sidecarIso = Get-QuarantineUnattendIsoPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $setupIso) -and -not (Test-Path -LiteralPath $floppy) -and -not (Test-Path -LiteralPath $sidecarIso)) {
        throw "Unattend media missing under $(Split-Path -Parent $floppy) - run setup secrets first."
    }
    if (-not (Test-Path -LiteralPath $setupIso)) {
        Write-Warning "Win11-setup.iso not found ($setupIso). Run setup secrets again so install can be fully unattended."
    }

    if ($Continue) {
        Write-Host "Continue mode: stage post-GA provision for '$vmName'..."
        if (-not (Test-QuarantineVMExists -VmName $vmName)) {
            throw "VM '$vmName' not found. Run build-windows without -Continue first."
        }
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -notin @('running', 'paused')) {
            Start-QuarantineVM -ConfigPath $ConfigPath -Type gui
            Start-Sleep -Seconds 5
        }
        Wait-QuarantineVMGuestControlReady -ConfigPath $ConfigPath -TimeoutMinutes ([Math]::Max(5, $WaitMinutes))
    } else {
        if ((Test-QuarantineVMExists -VmName $vmName) -and -not $Force) {
            throw (
                "VM '$vmName' already exists.`n" +
                "  - Keep it and finish provisioning: .\quarantine-vm.ps1 build-windows -Continue`n" +
                "  - Recreate from scratch (destroys that VM only): .\quarantine-vm.ps1 build-windows -Force`n" +
                "  - Renamed VMs in VirtualBox are left alone if their name differs from config vmName."
            )
        }

        Write-Host "=== build-windows: create '$vmName' ==="
        New-QuarantineVM -ConfigPath $ConfigPath -Force:$Force

        Write-Host '=== build-windows: start Linux gateway (lab NIC is already intnet) ==='
        if ($CliExe -and (Test-Path -LiteralPath $CliExe)) {
            & (Get-Item -LiteralPath $CliExe).FullName --config $ConfigPath gateway start
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                Write-Warning "gateway start exited $LASTEXITCODE — Windows Setup will have no WAN until the gateway is up"
            }
            & (Get-Item -LiteralPath $CliExe).FullName --config $ConfigPath network gateway
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                Write-Warning "network gateway exited $LASTEXITCODE"
            }
        }

        Write-Host '=== build-windows: start Windows Setup (GUI) ==='
        if (Test-Path -LiteralPath $setupIso) {
            Write-Host 'Booting remastered Win11-setup.iso (efisys_noprompt when available; no key press expected).'
        } else {
            Write-Host 'When you see "Press any key to boot from CD or DVD", press a key.'
        }
        Install-QuarantineVM -ConfigPath $ConfigPath

        if ($NoWait -or $WaitMinutes -le 0) {
            Write-Host @'

Host bootstrap started (NoWait).
After Windows FirstLogon finishes:
  1. .\quarantine-vm.ps1 guest-additions   # install from DVD in guest, reboot
  2. .\quarantine-vm.ps1 build-windows -Continue

'@
            return
        }

        Write-Host @'

Windows is installing. In the VM window:
  - Press a key at the DVD boot prompt if shown (efisys_noprompt skips this)
  - Leave it alone through OOBE / FirstLogon (elevated provision from the setup ISO)

FirstLogon installs the agent and sets gateway networking. Guest Additions are
only needed for host guestcontrol (paste / later staging), not agent health.

'@
        Wait-QuarantineVMGuestControlReady -ConfigPath $ConfigPath -TimeoutMinutes $WaitMinutes
    }

    Write-Host '=== Mount Guest Additions ISO ==='
    try {
        Mount-QuarantineVMGuestAdditions -ConfigPath $ConfigPath
    } catch {
        Write-Warning "Guest Additions mount: $($_.Exception.Message)"
    }

    Write-Host '=== Network: gateway ==='
    try {
        Set-QuarantineVMNetworkMode -ConfigPath $ConfigPath -Mode gateway
    } catch {
        Write-Warning "network gateway: $($_.Exception.Message)"
    }

    if ($CliExe -and (Test-Path -LiteralPath $CliExe)) {
        Write-Host '=== Stage guest provision (agent/Sysmon/scripts) ==='
        & (Get-Item -LiteralPath $CliExe).FullName --config $ConfigPath guest provision
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Warning "guest provision staging exited $LASTEXITCODE"
        }
    }

    $pub = if ($cfg.guest.copyTargetDir) { [string]$cfg.guest.copyTargetDir } else { 'C:\Users\Public\Quarantine' }
    Write-Host @"

=== build-windows: almost done ===
Unattend FirstLogon should already have installed the agent on the gateway LAN.
On the host:
  .\quarantine-vm.ps1 agent health
  .\quarantine-vm.ps1 baseline

If provision skipped the agent (binary missing from the setup ISO), re-run
setup secrets after building quarantine-agent.exe, then in the guest:
  Public Desktop: Finish-QuarantineProvision.cmd
  or:  & '$pub\Invoke-QuarantineGuestProvision.ps1'

"@
}

function Set-QuarantineVMPostPeBootOrder {
    <#
    .SYNOPSIS
      After Windows PE has started from DVD, prefer disk for later Setup reboots.
      Leaving DVD first makes Setup re-enter the installer and show
      "The computer restarted unexpectedly...".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [int]$DelaySeconds = 45
    )

    if ($DelaySeconds -gt 0) {
        Write-Host "Waiting ${DelaySeconds}s for Windows PE to start from DVD, then setting disk-first boot..."
        Start-Sleep -Seconds $DelaySeconds
    }

    $state = Get-QuarantineVMState -VmName $VmName
    if ($state -notin @('running', 'paused')) {
        Write-Warning "Skip boot-order flip; VM state is '$state'."
        return
    }

    Invoke-VBoxManage -Arguments @(
        'modifyvm', $VmName,
        '--boot1', 'disk',
        '--boot2', 'dvd',
        '--boot3', 'none',
        '--boot4', 'none'
    ) -AllowFailure | Out-Null

    $boot1 = (& (Get-VBoxManagePath) showvminfo $VmName --machinereadable 2>$null | Select-String '^boot1=').ToString()
    if ($boot1 -match 'boot1="disk"') {
        Write-Host 'Boot order set to disk then DVD (ISO stays attached; next Setup reboot hits the hard disk).'
    } else {
        Write-Warning @"
Could not change boot order while the VM is running (VirtualBox locked it).
After Windows finishes copying files and reboots, if you see the 'restarted unexpectedly' dialog:
  1. Power off the VM
  2. VBoxManage modifyvm $VmName --boot1 disk --boot2 dvd
  3. Start the VM again (boots into the installed Windows / specialize)
"@
    }
}

function Install-QuarantineVM {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    Write-Host @'

Windows install workflow:
  1. VM boots from remastered ISO + unattend floppy (GUI window opens).
  2. Host flips boot order to disk-first after PE starts (avoids re-entering Setup).
  3. Autounattend creates accounts; FirstLogon runs from floppy A:.
  4. Install Guest Additions, then: .\quarantine-vm.ps1 build-windows -Continue
  5. Install analysis tools, then: .\quarantine-vm.ps1 baseline / snapshot

'@

    $vmName = (Get-QuarantineVMConfig -ConfigPath $ConfigPath).vmName
    Set-QuarantineVMInstallMedia -VmName $vmName -ConfigPath $ConfigPath
    Start-QuarantineVM -ConfigPath $ConfigPath -Type gui -KeepInstallMedia -SkipProxy
    Set-QuarantineVMPostPeBootOrder -VmName $vmName -DelaySeconds 45
}

function Move-QuarantineVMDisk {
    <#
    .SYNOPSIS
      Move the VM disk to vmDataDir (C:\QuarantineLab by default) and reattach it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $newPath = Get-QuarantineVMDiskPath -Config $script:Config
    $newDir = Split-Path -Parent $newPath

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $currentPath = $null
    $info = Invoke-VBoxManage -Arguments @('showvminfo', $vmName)
    for ($i = 0; $i -lt $info.Count; $i++) {
        if ($info[$i] -match 'Port 0, Unit 0:' -and $info[$i] -notmatch 'UUID') {
            for ($j = $i + 1; $j -lt [Math]::Min($i + 4, $info.Count); $j++) {
                if ($info[$j] -match 'Location:\s+"(.+\.vdi)"') {
                    $currentPath = $Matches[1]
                    break
                }
            }
            break
        }
    }

    if (-not $currentPath) {
        throw 'Could not determine current VM disk path.'
    }

    if ((Format-VBoxPath -Path $currentPath) -eq (Format-VBoxPath -Path $newPath)) {
        Write-Host "Disk already at target location: $newPath"
        return
    }

    if (-not (Test-Path -LiteralPath $currentPath)) {
        throw "Current disk not found: $currentPath"
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Move disk to $newPath")) {
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -in @('running', 'paused', 'starting')) {
            Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
            Start-Sleep -Seconds 2
        }

        if (-not (Test-Path -LiteralPath $newDir)) {
            New-Item -ItemType Directory -Path $newDir -Force | Out-Null
        }

        Write-Host "Moving disk..."
        Write-Host "  From: $currentPath"
        Write-Host "  To:   $newPath"

        Invoke-VBoxManage -Arguments @(
            'modifymedium', 'disk', $currentPath, "--move=$newPath"
        ) | Out-Null

        $oldDir = Split-Path -Parent $currentPath
        if ((Test-Path -LiteralPath $oldDir) -and -not (Get-ChildItem -LiteralPath $oldDir -Force | Where-Object { $_.Name -notin @('.', '..') })) {
            Remove-Item -LiteralPath $oldDir -Force -ErrorAction SilentlyContinue
        }

        Write-Host 'Disk relocated successfully.'
    }
}

function Get-QuarantineVMCfgFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VmName
    )

    $info = Invoke-VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable')
    foreach ($line in $info) {
        if ($line -match '^CfgFile="(.+)"$') {
            return $Matches[1]
        }
    }

    return $null
}

function Move-QuarantineVMHome {
    <#
    .SYNOPSIS
      Move VM config, snapshots, and logs into vmDataDir\{vmName}\ (alongside the disk).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $targetFolder = Get-QuarantineVMFolder -Config $script:Config
    $vboxFile = Join-Path $targetFolder "$vmName.vbox"

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $cfgFile = Get-QuarantineVMCfgFile -VmName $vmName
    if (-not $cfgFile) {
        throw 'Could not determine VM config file path.'
    }

    $currentFolder = Split-Path -Parent $cfgFile
    if ((Format-VBoxPath -Path $currentFolder) -eq (Format-VBoxPath -Path $targetFolder)) {
        Write-Host "VM home already consolidated: $targetFolder"
        return
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Consolidate VM home to $targetFolder")) {
        $state = Get-QuarantineVMState -VmName $vmName
        if ($state -in @('running', 'paused', 'starting')) {
            Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
            Start-Sleep -Seconds 2
        }
        if ((Get-QuarantineVMState -VmName $vmName) -eq 'saved') {
            Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
            Start-Sleep -Seconds 1
        }

        Write-Host "Moving VM config and snapshots..."
        Write-Host "  From: $currentFolder"
        Write-Host "  To:   $targetFolder"

        Invoke-VBoxManage -Arguments @('unregistervm', $vmName) | Out-Null

        if (-not (Test-Path -LiteralPath $targetFolder)) {
            New-Item -ItemType Directory -Path $targetFolder -Force | Out-Null
        }

        Get-ChildItem -LiteralPath $currentFolder -Force | ForEach-Object {
            $dest = Join-Path $targetFolder $_.Name
            if ($_.PSIsContainer -and (Test-Path -LiteralPath $dest)) {
                Get-ChildItem -LiteralPath $_.FullName -Force | ForEach-Object {
                    Move-Item -LiteralPath $_.FullName -Destination $dest -Force
                }
            } elseif (-not (Test-Path -LiteralPath $dest)) {
                Move-Item -LiteralPath $_.FullName -Destination $targetFolder -Force
            } elseif ($_.Extension -ne '.vdi') {
                Move-Item -LiteralPath $_.FullName -Destination $dest -Force
            }
        }

        if (-not (Test-Path -LiteralPath $vboxFile)) {
            throw "Expected config file not found after move: $vboxFile"
        }

        Invoke-VBoxManage -Arguments @('registervm', $vboxFile) | Out-Null

        if ((Test-Path -LiteralPath $currentFolder) -and
            -not (Get-ChildItem -LiteralPath $currentFolder -Force | Where-Object { $_.Name -notin @('.', '..') })) {
            Remove-Item -LiteralPath $currentFolder -Force -ErrorAction SilentlyContinue
        }

        Write-Host "VM consolidated to: $targetFolder"
    }
}

function Move-QuarantineVMStorage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $targetDisk = Get-QuarantineVMDiskPath -Config $script:Config
    if (Test-Path -LiteralPath $targetDisk) {
        Move-QuarantineVMHome -ConfigPath $ConfigPath
    } else {
        Move-QuarantineVMDisk -ConfigPath $ConfigPath
        Move-QuarantineVMHome -ConfigPath $ConfigPath
    }
}

Export-ModuleMember -Function @(
    'Get-QuarantineVMConfig',
    'Initialize-QuarantineVMContext',
    'Get-QuarantineVMDataDir',
    'Get-QuarantineVMFolder',
    'Get-QuarantineVMDiskPath',
    'Resolve-WindowsIsoPath',
    'New-QuarantineVM',
    'Start-QuarantineVM',
    'Stop-QuarantineVM',
    'Save-QuarantineVMEvidence',
    'Clear-QuarantineVMSnapshots',
    'New-QuarantineVMBaseline',
    'Save-QuarantineVMSnapshot',
    'Remove-QuarantineVMSnapshot',
    'Get-QuarantineVMSnapshotList',
    'Resolve-QuarantineVMSnapshot',
    'Resolve-QuarantineVMSnapshotName',
    'Select-QuarantineVMSnapshot',
    'Get-QuarantineVMSnapshots',
    'Reset-QuarantineVM',
    'Get-QuarantineVMStatus',
    'Install-QuarantineVM',
    'Set-QuarantineVMInstallMedia',
    'Set-QuarantineVMPostPeBootOrder',
    'Get-QuarantineUnattendFloppyPath',
    'Get-QuarantineUnattendIsoPath',
    'Get-QuarantineWindowsSetupIsoPath',
    'Mount-QuarantineUnattendFloppy',
    'Mount-QuarantineUnattendMedia',
    'Set-QuarantineVMInstallNat',
    'Wait-QuarantineVMGuestControlReady',
    'Invoke-QuarantineWindowsBuild',
    'Set-QuarantineVMNormalBoot',
    'Mount-QuarantineVMGuestAdditions',
    'Set-QuarantineVMNetworkMode',
    'Set-QuarantineVMClipboard',
    'Set-QuarantineVMStealth',
    'Push-QuarantineVMInbox',
    'Open-QuarantineVMInbox',
    'Close-QuarantineVMInbox',
    'Get-QuarantineVMInbox',
    'Clear-QuarantineVMInbox',
    'Get-QuarantineVMGuestSettings',
    'Invoke-QuarantineVMGuestRun',
    'Restart-QuarantineVMGuestSession',
    'Invoke-QuarantineGuestHostsEntry',
    'Copy-QuarantineVMGuestFile',
    'Test-QuarantineVMGuestControl',
    'Resolve-QuarantineVMGuestCredential',
    'Resolve-QuarantineVMPayloadCredential',
    'Get-QuarantineVMPayloadSettings',
    'Invoke-QuarantineVMGuestControl',
    'Update-QuarantineVMNetworkConfig',
    'Move-QuarantineVMDisk',
    'Move-QuarantineVMHome',
    'Move-QuarantineVMStorage',
    'Get-QuarantineVMState',
    'Initialize-QuarantineVMMutable'
)
