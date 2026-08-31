#Requires -Version 5.1
<#
.SYNOPSIS
  Shared token privilege helpers for guest manifest scripts.
#>
function Enable-QuarantineTokenPrivilege {
    param([Parameter(Mandatory)][string[]]$Names)

    if (-not ('QuarantineTokenPrivUtil' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class QuarantineTokenPrivUtil {
    const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const int TOKEN_QUERY = 0x0008;
    const int SE_PRIVILEGE_ENABLED = 0x00000002;
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public LUID_AND_ATTRIBUTES[] Privileges;
    }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TOKEN_PRIVILEGES tp, uint len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    public static bool Enable(string name) {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) return false;
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return false;
        var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new LUID_AND_ATTRIBUTES[4] };
        tp.Privileges[0] = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
        return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
    }

    $enabled = @()
    foreach ($name in $Names) {
        if ([QuarantineTokenPrivUtil]::Enable($name)) { $enabled += $name }
    }
    return $enabled
}

function Enable-QuarantineManifestReadPrivileges {
    Enable-QuarantineTokenPrivilege -Names @('SeBackupPrivilege', 'SeSecurityPrivilege', 'SeRestorePrivilege') | Out-Null
}

function Get-QuarantineGuestJsonText {
    param([Parameter(Mandatory)][string]$Text)

    $trimmed = $Text.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'Empty JSON content.'
    }

    try {
        $null = $trimmed | ConvertFrom-Json
        return $trimmed
    } catch { }

    foreach ($line in ($trimmed -split "`r?`n")) {
        $candidate = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try {
            $null = $candidate | ConvertFrom-Json
            return $candidate
        } catch { }
    }

    $start = $trimmed.IndexOf('{')
    if ($start -lt 0) { throw 'No JSON object found.' }

    $depth = 0
    $inString = $false
    $escape = $false
    for ($i = $start; $i -lt $trimmed.Length; $i++) {
        $c = $trimmed[$i]
        if ($inString) {
            if ($escape) { $escape = $false; continue }
            if ($c -eq '\') { $escape = $true; continue }
            if ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '"') { $inString = $true; continue }
        if ($c -eq '{') { $depth++ }
        elseif ($c -eq '}') {
            $depth--
            if ($depth -eq 0) {
                $json = $trimmed.Substring($start, $i - $start + 1)
                $null = $json | ConvertFrom-Json
                return $json
            }
        }
    }

    throw 'Could not extract a complete JSON object.'
}

function Write-QuarantineGuestJsonFile {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $json = $Object | ConvertTo-Json -Depth $Depth -Compress
    $tmp = Join-Path $dir ("{0}.{1}.tmp" -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString('n'))
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($tmp, $json, $utf8)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Read-QuarantineGuestJsonFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = [System.IO.File]::ReadAllText($Path)
    $json = Get-QuarantineGuestJsonText -Text $raw
    if ($json -ne $raw.Trim()) {
        [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding $false))
    }
    return ($json | ConvertFrom-Json)
}

Export-ModuleMember -Function @(
    'Enable-QuarantineManifestReadPrivileges',
    'Enable-QuarantineTokenPrivilege',
    'Get-QuarantineGuestJsonText',
    'Write-QuarantineGuestJsonFile',
    'Read-QuarantineGuestJsonFile'
)
