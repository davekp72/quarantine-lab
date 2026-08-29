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

function Get-QuarantineVMDataDir {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Config = $script:Config
    )

    if ($Config.vmDataDir -and -not [string]::IsNullOrWhiteSpace($Config.vmDataDir)) {
        return $Config.vmDataDir
    }

    return 'D:\Vbox\LabVM'
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
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe",
        'D:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
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
        if ($line -match '^VMState="(?<state>[^"]+)"$') {
            return $Matches['state']
        }
    }

    return 'unknown'
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
        Ensure-QuarantineVMDvdDrive -VmName $VmName -Empty | Out-Null
    } else {
        Ensure-QuarantineVMDvdDrive -VmName $VmName | Out-Null
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
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox",
        'D:\Program Files\Oracle\VirtualBox'
    )

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not $root) { continue }
        $iso = Join-Path $root 'VBoxGuestAdditions.iso'
        if (Test-Path -LiteralPath $iso) { return $iso }
    }

    return $null
}

function Ensure-QuarantineVMDvdDrive {
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

    Ensure-QuarantineVMDvdDrive -VmName $vmName | Out-Null

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
        Ensure-QuarantineVMDvdDrive -VmName $vmName | Out-Null
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
        $Isolation = $script:Config.isolation
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
            Invoke-VBoxManage -Arguments @('controlvm', $VmName, 'sharedfolder', 'remove', '--name=quarantine-in', '--transient') -AllowFailure | Out-Null
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
        Invoke-VBoxManage -Arguments @('controlvm', $VmName, 'sharedfolder', 'remove', '--name=quarantine-in', '--transient') -AllowFailure | Out-Null
    }
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
        default {
            throw "Unsupported network.mode '$mode'. Use hostonly, intnet, none, nat, or quarantine."
        }
    }

    $args = @('modifyvm', $VmName, '--nic1', $nicType) + $nicExtra + @('--cableconnected1', 'on')
    Invoke-VBoxManage -Arguments $args | Out-Null
}

function Set-QuarantineVMNetworkMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('nat', 'intnet', 'none', 'hostonly', 'quarantine', 'offline')]
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

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found."
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM before changing network...'
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 2
    }

    $network = [pscustomobject]@{
        mode              = $Mode
        hostOnlyAdapter   = $script:Config.network.hostOnlyAdapter
        intnetName        = $script:Config.network.intnetName
    }

    Set-QuarantineVMNetwork -VmName $vmName -Network $network

    if ($Mode -eq 'intnet') {
        Update-QuarantineVMNetworkConfig -ConfigPath $ConfigPath -Mode 'intnet'
    }

    if ($Mode -eq 'nat') {
        Write-Warning 'NAT is enabled — VM has internet. Switch back after setup: .\quarantine-vm.ps1 network offline'
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

        Set-QuarantineVMNetwork -VmName $vmName | Out-Null
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
            '--portcount', '2',
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

        if ($script:Config.autounattendPath -and (Test-Path -LiteralPath $script:Config.autounattendPath)) {
            Write-Verbose 'autounattend.xml is configured; attach manually after creating a floppy image (see README).'
        }

        Write-Host "VM '$vmName' created with isolation defaults."
        Write-Host "Next: run '.\quarantine-vm.ps1 install' to start Windows setup, then '.\quarantine-vm.ps1 snapshot' after hardening."
    }
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

    $isoPath = Resolve-WindowsIsoPath `
        -ConfiguredPath $script:Config.windowsIsoPath `
        -GuestOsType $script:Config.guestOsType `
        -ProjectRoot $PSScriptRoot

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
        '--medium', $isoPath
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
        [switch]$SkipProxy
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName

    if (-not (Test-QuarantineVMExists -VmName $vmName)) {
        throw "VM '$vmName' not found. Run '.\quarantine-vm.ps1 create' first."
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host "VM '$vmName' is already $state."
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
        }
        return
    }

    if ($state -in @('aborted', 'stuck')) {
        Write-Host "Discarding unusable VM state ($state)..."
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    }

    Set-QuarantineVMNormalBoot -VmName $vmName | Out-Null
    Set-QuarantineVMIsolation -VmName $vmName | Out-Null

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

    $lines = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable')
    $uuids = @()
    foreach ($line in $lines) {
        if ($line -match '^SnapshotUUID(-[0-9]+)*="([^"]+)"$') {
            $uuids += $Matches[2]
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

function New-QuarantineVMBaseline {
    <#
    .SYNOPSIS
      Delete all snapshots, merge current disk state, and save a fresh Clean baseline.
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
    Save-QuarantineVMSnapshot -ConfigPath $ConfigPath -Name $Name -Description $Description
}

function Save-QuarantineVMSnapshot {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Name,

        [Parameter()]
        [string]$Description = 'Known-good baseline for quarantine reset.'
    )

    $script:Config = Get-QuarantineVMConfig -ConfigPath $ConfigPath
    $vmName = $script:Config.vmName
    $snapshotName = if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $Name
    } elseif ($script:Config.cleanSnapshotName) {
        $script:Config.cleanSnapshotName
    } else {
        'Clean'
    }

    $description = if (-not [string]::IsNullOrWhiteSpace($Description)) {
        $Description
    } else {
        'Known-good baseline for quarantine reset.'
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused', 'starting')) {
        Write-Host 'Stopping VM before snapshot (required for a consistent snapshot)...'
        Invoke-VBoxManage -Arguments @('controlvm', $vmName, 'poweroff') -AllowFailure | Out-Null
        Start-Sleep -Seconds 3
    }
    if ((Get-QuarantineVMState -VmName $vmName) -eq 'saved') {
        Invoke-VBoxManage -Arguments @('discardstate', $vmName) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Snapshot '$snapshotName'")) {
        $snapArgs = @(
            'snapshot', $vmName, 'take', $snapshotName,
            '--description', $description,
            '--pause'
        )
        Invoke-VBoxManage -Arguments $snapArgs | Out-Null
        Write-Host "Snapshot '$snapshotName' saved."
        Write-Host "  Folder: $(Join-Path (Get-QuarantineVMFolder -Config $script:Config) 'Snapshots')"
    }
}

function Save-QuarantineVMEvidence {
    <#
    .SYNOPSIS
      Save the current (possibly compromised) VM state under a timestamped snapshot for later analysis.
      Does not modify the Clean baseline.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$Label
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $suffix = if (-not [string]::IsNullOrWhiteSpace($Label)) {
        ($Label -replace '[^\w\-]', '-')
    } else {
        $timestamp
    }
    $name = "Evidence-$suffix"
    $description = "Preserved session state ($timestamp). Possibly compromised - for analysis only."

    Save-QuarantineVMSnapshot -ConfigPath $ConfigPath -Name $name -Description $description
    Write-Host "Evidence snapshot: $name"
    Write-Host "Return to Clean baseline: .\quarantine-vm.ps1 reset -Clean"
    Write-Host "Re-open this evidence:   .\quarantine-vm.ps1 reset"
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

    $lines = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'list', '--machinereadable')
    $currentUuid = $null
    $orderedSuffixes = [System.Collections.Generic.List[string]]::new()
    $entries = @{}

    foreach ($line in $lines) {
        if ($line -match '^CurrentSnapshotUUID="([^"]+)"$') {
            $currentUuid = $Matches[1]
        }
        if ($line -match '^(SnapshotName|SnapshotUUID|SnapshotDescription)(-[0-9]+)*="(.*)"$') {
            $field = $Matches[1]
            $suffix = if ($Matches[2]) { $Matches[2] } else { '' }
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
        $name = $entry['SnapshotName']
        $uuid = $entry['SnapshotUUID']
        $description = $entry['SnapshotDescription']

        $takenAt = $null
        if ($name -match 'Evidence-(\d{8})-(\d{6})') {
            $takenAt = [datetime]::ParseExact(
                "$($Matches[1])$($Matches[2])", 'yyyyMMddHHmmss', $null)
        }

        $info = Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'showvminfo', $name) -AllowFailure
        foreach ($infoLine in $info) {
            if ($infoLine -match 'since (\d{4}-\d{2}-\d{2}T[0-9:\.]+)') {
                $parsed = [datetime]::Parse($Matches[1], [System.Globalization.CultureInfo]::InvariantCulture)
                if (-not $takenAt -or $parsed -gt $takenAt) {
                    $takenAt = $parsed
                }
            }
        }

        if (-not $takenAt) {
            $snapDir = Join-Path (Get-QuarantineVMFolder -Config $script:Config) 'Snapshots'
            $vdi = Get-ChildItem -LiteralPath $snapDir -Filter "*$uuid*" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($vdi) { $takenAt = $vdi.LastWriteTime }
        }

        $results += [pscustomobject]@{
            Name        = $name
            UUID        = $uuid
            Description = $description
            TakenAt     = if ($takenAt) { $takenAt } else { [datetime]::MinValue }
            IsCurrent   = ($uuid -eq $currentUuid)
        }
    }

    return $results
}

function Select-QuarantineVMSnapshot {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    $snapshots = Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath
    if ($snapshots.Count -eq 0) {
        throw 'No snapshots found.'
    }

    Write-Host ''
    Write-Host 'Select snapshot to restore:'
    Write-Host ''

    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        $s = $snapshots[$i]
        $when = if ($s.TakenAt -ne [datetime]::MinValue) {
            $s.TakenAt.ToString('yyyy-MM-dd HH:mm')
        } else {
            'unknown time'
        }
        $current = if ($s.IsCurrent) { '  [current]' } else { '' }
        Write-Host ("  [{0}] {1}  ({2}){3}" -f ($i + 1), $s.Name, $when, $current)
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
            throw 'Restore cancelled.'
        }
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $snapshots.Count) {
            return $snapshots[[int]$choice - 1].Name
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

    foreach ($s in (Get-QuarantineVMSnapshotList -ConfigPath $ConfigPath)) {
        $when = if ($s.TakenAt -ne [datetime]::MinValue) {
            $s.TakenAt.ToString('yyyy-MM-dd HH:mm')
        } else {
            'unknown'
        }
        $current = if ($s.IsCurrent) { ' *' } else { '' }
        Write-Host "  $($s.Name)  ($when)$current"
        if ($s.Description) {
            Write-Host "    $($s.Description)"
        }
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
        $target = if ($script:Config.cleanSnapshotName) { $script:Config.cleanSnapshotName } else { 'Clean' }
    } elseif (-not [string]::IsNullOrWhiteSpace($SnapshotName)) {
        $target = $SnapshotName
    } else {
        $target = Select-QuarantineVMSnapshot -ConfigPath $ConfigPath
    }

    $state = Get-QuarantineVMState -VmName $vmName
    if ($state -in @('running', 'paused')) {
        Stop-QuarantineVM -ConfigPath $ConfigPath -Force
        Start-Sleep -Seconds 3
    }

    if ($PSCmdlet.ShouldProcess($vmName, "Restore snapshot '$target'")) {
        Invoke-VBoxManage -Arguments @('snapshot', $vmName, 'restore', $target) | Out-Null
        Write-Host "Restored '$vmName' to snapshot '$target'."
    }
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

function Install-QuarantineVM {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath
    )

    Write-Host @'

Windows install workflow:
  1. VM boots from ISO (GUI window opens).
  2. When you see "Press any key to boot from CD or DVD", press a key immediately.
  3. Complete setup or use templates\autounattend.xml for unattended install.
  4. Disable Windows Update, Defender cloud sample submission, and OneDrive sync.
  5. Install your analysis tools (browser, mail client, debugger, etc.).
  6. Run: .\quarantine-vm.ps1 snapshot

'@

    Set-QuarantineVMInstallMedia -VmName (Get-QuarantineVMConfig -ConfigPath $ConfigPath).vmName -ConfigPath $ConfigPath
    Start-QuarantineVM -ConfigPath $ConfigPath -Type gui
}

function Move-QuarantineVMDisk {
    <#
    .SYNOPSIS
      Move the VM disk to vmDataDir (D:\Vbox\LabVM by default) and reattach it.
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
    'Get-QuarantineVMSnapshotList',
    'Select-QuarantineVMSnapshot',
    'Get-QuarantineVMSnapshots',
    'Reset-QuarantineVM',
    'Get-QuarantineVMStatus',
    'Install-QuarantineVM',
    'Set-QuarantineVMInstallMedia',
    'Set-QuarantineVMNormalBoot',
    'Mount-QuarantineVMGuestAdditions',
    'Set-QuarantineVMNetworkMode',
    'Set-QuarantineVMClipboard',
    'Update-QuarantineVMNetworkConfig',
    'Move-QuarantineVMDisk',
    'Move-QuarantineVMHome',
    'Move-QuarantineVMStorage',
    'Get-QuarantineVMState'
)
