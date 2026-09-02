#Requires -Version 5.1
<#
.SYNOPSIS
  Capture filesystem + registry inventory for snapshot diff analysis (run inside guest).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutFile,

    [string]$SnapshotLabel = '',
    [ValidateSet('events', 'full')]
    [string]$ScanMode = 'events',
    [ValidateSet('regshot', 'legacy')]
    [string]$RegistryEngine = 'regshot',
    [int]$HashMaxMb = 50,
    [int]$ContentMaxKb = 51200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:QuarantineBackupPrivilegesEnabled = $false

$hashMaxBytes = [int64]$HashMaxMb * 1MB
$contentMaxBytes = [int64]$ContentMaxKb * 1KB
$files = New-Object System.Collections.Generic.List[object]
$registry = New-Object System.Collections.Generic.List[object]
$tasks = New-Object System.Collections.Generic.List[object]

function Get-StringHash([string]$Text) {
    if ($null -eq $Text) { return '' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash) -replace '-', '')
}

function Get-FileContentPayload {
    param(
        [System.IO.FileInfo]$Item,
        [int64]$MaxBytes
    )

    if ($Item.Length -gt $MaxBytes) {
        return @{ c = 'too_large' }
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($Item.FullName)
        $hasNull = $false
        foreach ($b in $bytes) {
            if ($b -eq 0) { $hasNull = $true; break }
        }

        if (-not $hasNull) {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            $bad = 0
            foreach ($ch in $text.ToCharArray()) {
                $code = [int][char]$ch
                if ($code -lt 9 -or ($code -gt 13 -and $code -lt 32)) { $bad++ }
            }
            if ($text.Length -eq 0 -or ($bad / $text.Length) -lt 0.05) {
                return @{ c = 'text'; d = $text }
            }
        }

        return @{ c = 'base64'; d = [Convert]::ToBase64String($bytes) }
    } catch {
        return @{ c = 'access_denied' }
    }
}

function Add-FileEntry {
    param([System.IO.FileInfo]$Item)
    if (-not $Item) { return }
    $entry = [ordered]@{
        p = $Item.FullName
        s = $Item.Length
        m = $Item.LastWriteTimeUtc.ToString('o')
    }
    if ($Item.Length -le $hashMaxBytes) {
        try {
            $entry.h = (Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            $entry.h = 'ACCESS_DENIED'
        }
    } else {
        $entry.h = 'SKIPPED_LARGE'
    }

    if ($Item.Length -le $contentMaxBytes) {
        $shouldContent = ($files.Count -lt 2500) -and ($Item.FullName -notmatch '\\Program Files\\|\\Program Files \(x86\)\\|\\WinSxS\\')
        if ($shouldContent) {
            $payload = Get-FileContentPayload -Item $Item -MaxBytes $contentMaxBytes
            $entry.c = $payload.c
            if ($payload.d) { $entry.d = $payload.d }
        } else {
            $entry.c = 'scan_only'
        }
    } else {
        $entry.c = 'too_large'
    }

    $files.Add([pscustomobject]$entry) | Out-Null
}

function Scan-RootFilesOnly {
    param([string]$Root)
    try {
        if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) { return }
    } catch {
        return
    }
    try {
        Get-ChildItem -LiteralPath $Root -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Add-FileEntry -Item $_
        }
    } catch { }
}

function Scan-Root {
    param([string]$Root, [string[]]$ExcludeDirNames = @())
    try {
        if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) { return }
    } catch {
        return
    }
    try {
        Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            $skip = $false
            foreach ($part in $ExcludeDirNames) {
                if ($_.FullName -match [regex]::Escape($part)) { $skip = $true; break }
            }
            if (-not $skip) { Add-FileEntry -Item $_ }
        }
    } catch { }
}

$excludeHeavy = @('\WinSxS\', '\Windows\SoftwareDistribution\Download\', '\$Recycle.Bin\')

if ($ScanMode -eq 'full') {
    foreach ($root in @(
        "$env:ProgramData",
        "$env:Public",
        "$env:TEMP",
        'C:\Windows\Temp'
    )) {
        Scan-Root -Root $root -ExcludeDirNames $excludeHeavy
    }

    Scan-RootFilesOnly -Root 'C:\'
    Scan-RootFilesOnly -Root 'C:\Windows'
    Scan-RootFilesOnly -Root 'C:\Windows\System32'

    foreach ($watchFile in @(
        'C:\Windows\System32\drivers\etc\hosts'
    )) {
        try {
            if (Test-Path -LiteralPath $watchFile -ErrorAction Stop) {
                Add-FileEntry -Item (Get-Item -LiteralPath $watchFile -Force)
            }
        } catch { }
    }

    foreach ($root in @(
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\Windows\System32\drivers',
        'C:\Windows\System32\Tasks',
        'C:\Windows\System32\spool\drivers',
        'C:\Windows\System32\GroupPolicy',
        'C:\Windows\SysWOW64',
        'C:\Windows\System32\Tasks\Microsoft\Windows'
    )) {
        Scan-Root -Root $root -ExcludeDirNames $excludeHeavy
    }

    Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($sub in @('Desktop', 'Downloads', 'Documents', 'AppData\Roaming', 'AppData\Local\Temp', 'AppData\Local\Microsoft\Windows\Start Menu')) {
            Scan-Root -Root (Join-Path $_.FullName $sub) -ExcludeDirNames $excludeHeavy
        }
    }

    foreach ($startup in @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )) {
        Scan-Root -Root $startup
    }
}

function Normalize-RegKeyPath {
    param([string]$Path)
    $normalized = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $normalized = $normalized -replace '^HKEY_CURRENT_USER\\', 'HKCU:\'
    $normalized = $normalized -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\'
    $normalized = $normalized -replace '^HKEY_USERS\\', 'HKU:\'
    if ($normalized -match '^HKCU:\\') { return $normalized }
    if ($normalized -match '^HKLM:\\') { return $normalized }
    if ($normalized -match '^HKU:\\') { return $normalized }
    return $Path
}

function Export-RegKey {
    param([string]$Path)
    $keyPath = Normalize-RegKeyPath -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Get-ItemProperty -LiteralPath $Path -ErrorAction Stop | ForEach-Object {
            $item = $_
            $item.PSObject.Properties | Where-Object {
                $_.Name -notmatch '^PS' -and $null -ne $_.Value
            } | ForEach-Object {
                $val = [string]$_.Value
                $typeName = $_.TypeNames[0]
                if ($typeName -match '^System\.') { $typeName = $typeName -replace '^System\.', '' }
                $registry.Add([pscustomobject][ordered]@{
                    k = $keyPath
                    n = $_.Name
                    t = $typeName
                    v = if ($val.Length -le 512) { $val } else { $val.Substring(0, 512) }
                    h = (Get-StringHash $val)
                }) | Out-Null
            }
        }
    } catch { }
}

function Export-RegTree {
    param(
        [string]$Path,
        [int]$MaxDepth = 12,
        [int]$Depth = 0
    )

    Export-RegKey -Path $Path
    if ($Depth -ge $MaxDepth) { return }

    try {
        Get-ChildItem -LiteralPath $Path -ErrorAction Stop | ForEach-Object {
            Export-RegTree -Path $_.PSPath -MaxDepth $MaxDepth -Depth ($Depth + 1)
        }
    } catch { }
}

function Enable-QuarantineBackupPrivileges {
    if ($script:QuarantineBackupPrivilegesEnabled -eq $true) { return $true }
    try {
        if (-not ('QuarantineTokenPriv' -as [type])) {
            Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class QuarantineTokenPriv {
    const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const int TOKEN_QUERY = 0x0008;
    const int SE_PRIVILEGE_ENABLED = 0x00000002;
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public LUID_AND_ATTRIBUTES[] Privileges;
    }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TOKEN_PRIVILEGES tp, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    static bool Enable(string name) {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) return false;
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return false;
        var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new[] { new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED } } };
        return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
    public static bool EnableBackupAndRestore() {
        return Enable("SeBackupPrivilege") & Enable("SeRestorePrivilege");
    }
}
'@
        }
        $script:QuarantineBackupPrivilegesEnabled = [QuarantineTokenPriv]::EnableBackupAndRestore()
        return [bool]$script:QuarantineBackupPrivilegesEnabled
    } catch {
        return $false
    }
}

function Copy-NtUserDatForOfflineLoad {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestPath
    )

    Enable-QuarantineBackupPrivileges | Out-Null
    try {
        [System.IO.File]::Copy($SourcePath, $DestPath, $true)
        return $true
    } catch { }

    $robocopy = Join-Path $env:SystemRoot 'System32\robocopy.exe'
    if (Test-Path -LiteralPath $robocopy) {
        $srcDir = Split-Path -Parent $SourcePath
        $dstDir = Split-Path -Parent $DestPath
        $name = Split-Path -Leaf $SourcePath
        & $robocopy $srcDir $dstDir $name /B /R:0 /W:0 /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
        if (Test-Path -LiteralPath $DestPath) { return $true }
    }

    return $false
}

function Get-LoadedUserRegistrySids {
    $sids = New-Object System.Collections.Generic.List[string]
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object {
            $sid = $_.PSChildName
            if ($sid -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
                [void]$sids.Add($sid)
            }
        }
    } catch { }
    return @($sids)
}

function Get-UserSidForProfilePath {
    param([string]$ProfilePath)
    $target = $ProfilePath.TrimEnd('\')
    try {
        Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop |
            ForEach-Object {
                $image = (Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
                if ($image -and $image.TrimEnd('\') -eq $target) {
                    return $_.PSChildName
                }
            }
    } catch { }
    return $null
}

function Get-UserProfileRecords {
    $records = New-Object System.Collections.Generic.List[object]
    $seenSids = @{}

    try {
        Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop |
            ForEach-Object {
                $sid = $_.PSChildName
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { return }
                $image = (Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
                if ([string]::IsNullOrWhiteSpace($image)) { return }
                $userName = Split-Path -Leaf $image.TrimEnd('\')
                if ($userName -in @('Public', 'Default', 'Default User', 'All Users')) { return }
                $seenSids[$sid] = $true
                $records.Add([pscustomobject]@{
                    UserName    = $userName
                    ProfilePath = $image.TrimEnd('\')
                    Sid         = $sid
                }) | Out-Null
            }
    } catch { }

    try {
        Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $userName = $_.Name
            if ($userName -in @('Public', 'Default', 'Default User', 'All Users')) { return }
            $profilePath = $_.FullName
            $sid = Get-UserSidForProfilePath -ProfilePath $profilePath
            if ($sid -and $seenSids.ContainsKey($sid)) { return }
            $records.Add([pscustomobject]@{
                UserName    = $userName
                ProfilePath = $profilePath
                Sid         = if ($sid) { $sid } else { $null }
            }) | Out-Null
        }
    } catch { }

    return $records.ToArray()
}

function Get-CurrentUserSid {
    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    } catch {
        return $null
    }
}

function Export-CurrentUserRegistryViaHkcu {
    param([int]$MaxDepth = 12)

    $sid = Get-CurrentUserSid
    if ([string]::IsNullOrWhiteSpace($sid)) { return 0 }

    $hkcuSoftware = 'Registry::HKEY_CURRENT_USER\Software'
    if (-not (Test-Path -LiteralPath $hkcuSoftware)) { return 0 }

    $before = $registry.Count
    Export-RegTree -Path $hkcuSoftware -MaxDepth $MaxDepth

    $hkcuPrefix = 'HKCU:\Software'
    $hkuPrefix = "HKU:\$sid\Software"
    for ($i = $before; $i -lt $registry.Count; $i++) {
        $entry = $registry[$i]
        if ($entry.k -like "$hkcuPrefix*") {
            $entry.k = $entry.k -replace '^HKCU:\\Software', $hkuPrefix
        }
    }

    return (Get-ExportedRegistryCountForSid -Sid $sid)
}

function Get-ExportedRegistryCountForSid {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return 0 }
    $prefix = "HKU:\$Sid\"
    $count = 0
    foreach ($entry in $registry) {
        if ($entry.k -like "$prefix*") { $count++ }
    }
    return $count
}

function Export-LoadedUserRegistry {
    param(
        [string]$Sid,
        [int]$MaxDepth = 12
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) { return 0 }
    $before = Get-ExportedRegistryCountForSid -Sid $Sid
    $software = "Registry::HKEY_USERS\$Sid\Software"
    if (Test-Path -LiteralPath $software) {
        Export-RegTree -Path $software -MaxDepth $MaxDepth
    }
    return (Get-ExportedRegistryCountForSid -Sid $Sid) - $before
}

function Mount-OfflineUserRegistryHive {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$NtUserPath,
        [System.Collections.Generic.List[string]]$MountedKeys,
        [System.Collections.Generic.List[string]]$Warnings,
        [string]$UserName
    )

    $mountKey = "QuarantineManifest_$Sid"
    $hiveToLoad = $NtUserPath
    $tempHive = Join-Path $env:TEMP "$mountKey.dat"
    $usedTempCopy = $false

    Enable-QuarantineBackupPrivileges | Out-Null

    $load = reg.exe load "HKU\$mountKey" $hiveToLoad 2>&1
    if ($LASTEXITCODE -ne 0) {
        if (Copy-NtUserDatForOfflineLoad -SourcePath $NtUserPath -DestPath $tempHive) {
            $hiveToLoad = $tempHive
            $usedTempCopy = $true
            $load = reg.exe load "HKU\$mountKey" $hiveToLoad 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            [void]$Warnings.Add("Could not load NTUSER.DAT for ${UserName}: $load")
            if ($usedTempCopy) { Remove-Item -LiteralPath $tempHive -Force -ErrorAction SilentlyContinue }
            return $false
        }
    }

    [void]$MountedKeys.Add($mountKey)
    return $true
}

function Test-PathAccessible {
    param([string]$Path)
    try {
        return Test-Path -LiteralPath $Path -ErrorAction Stop
    } catch {
        return $false
    }
}

function Export-OfflineUserRegistryForProfile {
    param(
        [Parameter(Mandatory)]$Profile,
        [int]$MaxDepth = 12,
        [System.Collections.Generic.List[string]]$MountedKeys,
        [System.Collections.Generic.List[string]]$Warnings
    )

    $userName = [string]$Profile.UserName
    $profilePath = [string]$Profile.ProfilePath
    $sid = [string]$Profile.Sid
    $ntUser = Join-Path $profilePath 'NTUSER.DAT'

    if (-not (Test-PathAccessible -Path $ntUser)) {
        [void]$Warnings.Add("NTUSER.DAT not accessible for $userName (use payload HKCU export)")
        return
    }

    if ([string]::IsNullOrWhiteSpace($sid)) {
        $sid = Get-UserSidForProfilePath -ProfilePath $profilePath
    }
    if ([string]::IsNullOrWhiteSpace($sid)) {
        [void]$Warnings.Add("No ProfileList SID for $userName")
        return
    }

    $currentSid = Get-CurrentUserSid
    if ($currentSid -and $sid -eq $currentSid) {
        return
    }

    if (-not (Mount-OfflineUserRegistryHive -Sid $sid -NtUserPath $ntUser -MountedKeys $MountedKeys -Warnings $Warnings -UserName $userName)) {
        return
    }

    $mountKey = "QuarantineManifest_$sid"
    $before = $registry.Count
    $software = "Registry::HKEY_USERS\$mountKey\Software"
    if (Test-Path -LiteralPath $software) {
        Export-RegTree -Path $software -MaxDepth $MaxDepth
        for ($i = $before; $i -lt $registry.Count; $i++) {
            $entry = $registry[$i]
            if ($entry.k -match "^HKU:\\QuarantineManifest_$([regex]::Escape($sid))\\") {
                $entry.k = $entry.k -replace "^HKU:\\QuarantineManifest_$([regex]::Escape($sid))\\", "HKU:\$sid\"
            }
        }
    } else {
        [void]$Warnings.Add("Software hive missing after load for $userName")
    }
}

function Export-OfflineUserRegistry {
    param([int]$MaxDepth = 12)

    $mountedKeys = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    try {
        foreach ($profile in (Get-UserProfileRecords)) {
            Export-OfflineUserRegistryForProfile -Profile $profile -MaxDepth $MaxDepth -MountedKeys $mountedKeys -Warnings $warnings
        }
    } finally {
        foreach ($mountKey in $mountedKeys) {
            reg.exe unload "HKU\$mountKey" 2>$null | Out-Null
            Remove-Item -LiteralPath (Join-Path $env:TEMP "$mountKey.dat") -Force -ErrorAction SilentlyContinue
        }
    }

    return @($warnings)
}

function Export-EventsModeUserRegistry {
    param([int]$MaxDepth = 8)

    Enable-QuarantineBackupPrivileges | Out-Null
    $warnings = New-Object System.Collections.Generic.List[string]
    Export-CurrentUserRegistryViaHkcu -MaxDepth $MaxDepth | Out-Null

    foreach ($sid in (Get-LoadedUserRegistrySids)) {
        Export-LoadedUserRegistry -Sid $sid -MaxDepth $MaxDepth | Out-Null
    }

    $defaultNtUser = 'C:\Users\Default\NTUSER.DAT'
    if (Test-PathAccessible -Path $defaultNtUser) {
        $defaultSid = Get-UserSidForProfilePath -ProfilePath 'C:\Users\Default'
        if ([string]::IsNullOrWhiteSpace($defaultSid)) {
            $defaultSid = '.DEFAULT'
        }
        $mountedKeys = New-Object System.Collections.Generic.List[string]
        try {
            $fakeProfile = [pscustomobject]@{ UserName = 'Default'; ProfilePath = 'C:\Users\Default'; Sid = $defaultSid }
            Export-OfflineUserRegistryForProfile -Profile $fakeProfile -MaxDepth $MaxDepth -MountedKeys $mountedKeys -Warnings $warnings
        } finally {
            foreach ($mountKey in $mountedKeys) {
                reg.exe unload "HKU\$mountKey" 2>$null | Out-Null
                Remove-Item -LiteralPath (Join-Path $env:TEMP "$mountKey.dat") -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        [void]$warnings.Add('Default user NTUSER.DAT not accessible.')
    }

    [void]$warnings.Add('events mode: loaded Default + current-user HKU; jkcooper HKCU merged post-capture.')
    return @($warnings)
}

function Export-AllUserRegistry {
    param([int]$MaxDepth = 12)

    Enable-QuarantineBackupPrivileges | Out-Null
    $warnings = New-Object System.Collections.Generic.List[string]
    $profiles = Get-UserProfileRecords

    Export-CurrentUserRegistryViaHkcu -MaxDepth $MaxDepth | Out-Null

    foreach ($sid in (Get-LoadedUserRegistrySids)) {
        Export-LoadedUserRegistry -Sid $sid -MaxDepth $MaxDepth | Out-Null
    }

    foreach ($profile in $profiles) {
        $sid = [string]$profile.Sid
        if ([string]::IsNullOrWhiteSpace($sid)) {
            $sid = Get-UserSidForProfilePath -ProfilePath $profile.ProfilePath
        }
        if (-not [string]::IsNullOrWhiteSpace($sid) -and (Get-ExportedRegistryCountForSid -Sid $sid) -gt 0) {
            continue
        }

        $mountedKeys = New-Object System.Collections.Generic.List[string]
        try {
            Export-OfflineUserRegistryForProfile -Profile $profile -MaxDepth $MaxDepth -MountedKeys $mountedKeys -Warnings $warnings
        } finally {
            foreach ($mountKey in $mountedKeys) {
                reg.exe unload "HKU\$mountKey" 2>$null | Out-Null
                Remove-Item -LiteralPath (Join-Path $env:TEMP "$mountKey.dat") -Force -ErrorAction SilentlyContinue
            }
        }
    }

    foreach ($profile in $profiles) {
        $sid = [string]$profile.Sid
        if ([string]::IsNullOrWhiteSpace($sid)) {
            $sid = Get-UserSidForProfilePath -ProfilePath $profile.ProfilePath
        }
        if ([string]::IsNullOrWhiteSpace($sid)) { continue }
        if ((Get-ExportedRegistryCountForSid -Sid $sid) -eq 0) {
            [void]$warnings.Add("No HKU registry exported for $($profile.UserName) ($sid)")
        }
    }

    return @($warnings)
}

$regTrees = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
    'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions'
)
$userRegistryWarnings = @()
$userRegistryCount = 0
if ($RegistryEngine -eq 'legacy') {
    foreach ($tree in $regTrees) { Export-RegTree -Path $tree }
    if ($ScanMode -eq 'full') {
        $userRegistryWarnings = Export-AllUserRegistry
    } else {
        $userRegistryWarnings = Export-EventsModeUserRegistry -MaxDepth 8
    }
    $userRegistryCount = 0
    foreach ($entry in $registry) {
        if ($entry.k -match '^HKU:\\') { $userRegistryCount++ }
    }

    try {
        Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue |
            Select-Object -First 400 | ForEach-Object {
                $p = $_.PSPath
                try {
                    $ip = (Get-ItemProperty -LiteralPath $p -ErrorAction Stop).ImagePath
                    if ($ip) {
                        $regKey = Normalize-RegKeyPath -Path ($p -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                        $registry.Add([pscustomobject][ordered]@{
                            k = $regKey
                            n = 'ImagePath'
                            t = 'REG_SZ'
                            v = [string]$ip
                            h = (Get-StringHash ([string]$ip))
                        }) | Out-Null
                    }
                } catch { }
            }
    } catch { }
} elseif ($RegistryEngine -eq 'regshot') {
    [void]$userRegistryWarnings.Add('registryEngine=regshot: HKLM/HKU captured via Regshot compare at manifest diff time.')
} else {
    [void]$userRegistryWarnings.Add('registryEngine=cli: payload HKU captured live via reg.exe at snapshot/preserve; HKLM captured via SYSTEM reg.exe export at snapshot/preserve.')
}

try {
    schtasks.exe /query /fo CSV /v 2>$null | Select-Object -Skip 1 | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return }
        $tasks.Add([pscustomobject][ordered]@{ line = $_ }) | Out-Null
    }
} catch { }

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$usnOut = Join-Path $scriptDir 'usn-delta-export.json'
$sysmonOut = Join-Path $scriptDir 'sysmon-events-export.json'
$serviceInstallOut = Join-Path $scriptDir 'service-install-events-export.json'

$privModule = Join-Path $scriptDir 'QuarantineGuestPriv.psm1'
if (Test-Path -LiteralPath $privModule) {
    Import-Module $privModule -Force -ErrorAction SilentlyContinue | Out-Null
}

function Read-QuarantineGuestJsonExport {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    if (Get-Command Read-QuarantineGuestJsonFile -ErrorAction SilentlyContinue) {
        return Read-QuarantineGuestJsonFile -Path $Path
    }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

$usnDelta = Read-QuarantineGuestJsonExport -Path $usnOut
$sysmonEvents = Read-QuarantineGuestJsonExport -Path $sysmonOut
$serviceInstallEvents = Read-QuarantineGuestJsonExport -Path $serviceInstallOut

if (-not $usnDelta) {
    $usnDelta = [pscustomobject]@{ available = $false; eventCount = 0; message = 'USN export missing (host privileged export failed).'; events = @() }
}
if (-not $sysmonEvents) {
    $sysmonEvents = [pscustomobject]@{ available = $false; eventCount = 0; message = 'Sysmon export missing (host privileged export failed).'; events = @() }
}
if (-not $serviceInstallEvents) {
    $serviceInstallEvents = [pscustomobject]@{ available = $false; eventCount = 0; message = 'Service install export missing (host privileged export failed).'; events = @() }
}

$manifest = [ordered]@{
    version      = 2
    guestScriptVersion = 5
    scanMode     = $ScanMode
    registryEngine = $RegistryEngine
    capturedAt   = (Get-Date).ToUniversalTime().ToString('o')
    computerName = $env:COMPUTERNAME
    snapshot     = $SnapshotLabel
    contentMaxKb = $ContentMaxKb
    fileCount    = $files.Count
    registryCount = $registry.Count
    userRegistryCount = $userRegistryCount
    taskCount    = $tasks.Count
    userRegistryWarnings = @($userRegistryWarnings)
    usn          = $usnDelta
    sysmon       = $sysmonEvents
    serviceInstalls = $serviceInstallEvents
    files        = $files
    registry     = $registry
    tasks        = $tasks
}

function Write-QuarantineManifestJson {
    param(
        [object]$Manifest,
        [string]$Path
    )

    function Remove-FileContentPayload {
        param([object]$ManifestObj)
        if (-not $ManifestObj.files) { return }
        for ($i = 0; $i -lt $ManifestObj.files.Count; $i++) {
            $f = $ManifestObj.files[$i]
            if ($null -eq $f) { continue }
            if ($f.PSObject.Properties['d']) {
                $null = $f.PSObject.Properties.Remove('d')
            }
            if ($f.c -in @('text', 'base64')) {
                $f.c = 'omitted_serialize'
            }
        }
        $ManifestObj | Add-Member -NotePropertyName contentOmitted -NotePropertyValue $true -Force
    }

    foreach ($depth in @(6, 5, 4)) {
        try {
            $json = $Manifest | ConvertTo-Json -Depth $depth -Compress
            $json | Set-Content -LiteralPath $Path -Encoding UTF8
            return
        } catch {
            if ($depth -eq 6) { Remove-FileContentPayload -ManifestObj $Manifest }
        }
    }

    throw 'Manifest JSON serialization failed even after omitting embedded file content.'
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

Write-QuarantineManifestJson -Manifest ([pscustomobject]$manifest) -Path $OutFile
$sysmonCount = if ($sysmonEvents -and $sysmonEvents.PSObject.Properties['eventCount']) { $sysmonEvents.eventCount } else { 0 }
Write-Output "MANIFEST_WRITTEN $OutFile scanMode=$ScanMode files=$($files.Count) registry=$($registry.Count) tasks=$($tasks.Count) sysmon=$sysmonCount"
