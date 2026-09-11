#Requires -Version 5.1
<#
.SYNOPSIS
  One-time guest hardening: Event Log Readers + USN read privileges for the lab admin account.
  Also removes the legacy SYSTEM privileged-export polling task if present.
  Run once from an elevated PowerShell session inside the guest (GUI).
#>
[CmdletBinding()]
param(
    [string]$LogName = 'Microsoft-Windows-Sysmon/Operational',
    [string]$LabAdmin = 'quarantine'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session in the guest.'
    }
}

function Resolve-LocalGroupName {
    param([Parameter(Mandatory)][string]$WellKnownSid)

    $group = Get-LocalGroup -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $WellKnownSid } | Select-Object -First 1
    if ($group) { return $group.Name }

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($WellKnownSid)
        $account = $sid.Translate([System.Security.Principal.NTAccount])
        $name = [string]$account
        if ($name -match '\\') { $name = ($name -split '\\', 2)[1] }
        if ($name) {
            $byName = Get-LocalGroup -Name $name -ErrorAction SilentlyContinue
            if ($byName) { return $byName.Name }
        }
    } catch { }

    return $null
}

function Add-LabAdminToWellKnownGroup {
    param(
        [Parameter(Mandatory)][string]$WellKnownSid,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Member
    )

    $groupName = Resolve-LocalGroupName -WellKnownSid $WellKnownSid
    if (-not $groupName) {
        Write-Warning "$Label group (SID $WellKnownSid) not present on this Windows image - skipping."
        return $false
    }

    try {
        Add-LocalGroupMember -Group $groupName -Member $Member -ErrorAction Stop
        Write-Host "Added $Member to $Label ($groupName)."
    } catch {
        if ($_.Exception.Message -match 'already a member|Already exists') {
            Write-Host "$Member already in $Label ($groupName)."
            return $true
        }
        throw
    }
    return $true
}

function Grant-UserPrivilegeToAccount {
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string[]]$PrivilegeIds
    )

    if (-not ('QuarantineLsaUtil' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class QuarantineLsaUtil {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);
    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern uint LsaAddAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, LSA_UNICODE_STRING[] UserRights, int CountOfRights);
    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern uint LsaClose(IntPtr ObjectHandle);
    [DllImport("advapi32.dll")]
    public static extern uint LsaNtStatusToWinError(uint status);
    public static LSA_UNICODE_STRING InitString(string value) {
        var item = new LSA_UNICODE_STRING();
        item.Buffer = Marshal.StringToHGlobalUni(value);
        item.Length = (ushort)(value.Length * 2);
        item.MaximumLength = (ushort)(item.Length + 2);
        return item;
    }
    public const uint PolicyAccess = 0x00000010u | 0x00000800u | 0x00000200u;
}
'@
    }

    $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier])
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)
    $sidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidPtr, $sidBytes.Length)

    $attrs = New-Object QuarantineLsaUtil+LSA_OBJECT_ATTRIBUTES
    $attrs.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($attrs)
    $policy = [IntPtr]::Zero
    $status = [QuarantineLsaUtil]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attrs, [QuarantineLsaUtil]::PolicyAccess, [ref]$policy)
    if ($status -ne 0) {
        $winErr = [QuarantineLsaUtil]::LsaNtStatusToWinError($status)
        throw "LsaOpenPolicy failed (NTSTATUS 0x$("{0:X}" -f $status), Win32 $winErr)."
    }

    try {
        $rights = New-Object QuarantineLsaUtil+LSA_UNICODE_STRING[] $PrivilegeIds.Count
        for ($i = 0; $i -lt $PrivilegeIds.Count; $i++) {
            $rights[$i] = [QuarantineLsaUtil]::InitString($PrivilegeIds[$i])
        }
        $status = [QuarantineLsaUtil]::LsaAddAccountRights($policy, $sidPtr, $rights, $PrivilegeIds.Count)
        if ($status -ne 0) {
            $winErr = [QuarantineLsaUtil]::LsaNtStatusToWinError($status)
            throw "LsaAddAccountRights failed (NTSTATUS 0x$("{0:X}" -f $status), Win32 $winErr)."
        }
        foreach ($priv in $PrivilegeIds) {
            Write-Host "Granted $priv to $AccountName via LSA."
        }
    } finally {
        [QuarantineLsaUtil]::LsaClose($policy) | Out-Null
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidPtr)
    }
}

Assert-Admin

Add-LabAdminToWellKnownGroup -WellKnownSid 'S-1-5-32-573' -Label 'Event Log Readers' -Member $LabAdmin | Out-Null

$backupGroupOk = Add-LabAdminToWellKnownGroup -WellKnownSid 'S-1-5-32-552' -Label 'Backup Operators' -Member $LabAdmin
if (-not $backupGroupOk) {
    Write-Host 'Assigning SeBackupPrivilege / SeRestorePrivilege directly (USN journal read)...'
    Grant-UserPrivilegeToAccount -AccountName $LabAdmin -PrivilegeIds @('SeBackupPrivilege', 'SeRestorePrivilege', 'SeManageVolumePrivilege')
}

function Remove-QuarantinePrivilegedExportTask {
    <#
    .SYNOPSIS
      Removes the legacy SYSTEM polling task QuarantineLabPrivilegedExport if present.
      Collection now uses the authenticated agent (or guestcontrol as lab admin after grant).
    #>
    $guestDir = 'C:\Users\Public\Quarantine'
    $taskName = 'QuarantineLabPrivilegedExport'
    $marker = Join-Path $guestDir 'privileged-export-task.ok'
    $worker = Join-Path $guestDir 'Invoke-QuarantinePrivilegedExportWorker.ps1'

    $removed = $false
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            schtasks.exe /Delete /TN $taskName /F 2>&1 | Out-Null
            $removed = $true
            Write-Host "Removed legacy scheduled task '$taskName' (SYSTEM polling job runner)."
        }
    } catch {
        Write-Warning "Could not remove legacy task '$taskName': $($_.Exception.Message)"
    }

    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    # Leave worker file if present but unused; delete to shrink attack surface under Public.
    Remove-Item -LiteralPath $worker -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $guestDir -Filter 'privileged-job*.json' -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $guestDir 'privileged-job.done') -Force -ErrorAction SilentlyContinue

    if (-not $removed) {
        Write-Host "Legacy SYSTEM task '$taskName' not present (OK)."
    }
    return $true
}

$null = Remove-QuarantinePrivilegedExportTask
$guestDir = 'C:\Users\Public\Quarantine'

try {
    $null = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    Write-Host "Sysmon log readable: $LogName"
} catch {
    $evtx = Join-Path $env:SystemRoot 'System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
    if (Test-Path -LiteralPath $evtx) {
        Write-Host 'Sysmon operational log API blocked; evtx file present (manifest capture uses evtx fallback).'
    } else {
        Write-Warning "Sysmon log not readable yet: $($_.Exception.Message)"
    }
}

function Get-NativeExitCode {
    if (Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue) {
        return [int]$LASTEXITCODE
    }
    return 0
}

function Invoke-UsnReadJournal {
    param([string]$StartUsn)
    $out = & fsutil.exe usn readjournal C: csv "startusn=$StartUsn" 2>&1
    return [pscustomobject]@{ ExitCode = (Get-NativeExitCode); Output = @($out) }
}

$queryOut = & fsutil.exe usn queryjournal C: 2>&1
$queryCode = Get-NativeExitCode
$queryText = @($queryOut) -join ' '
if ($queryCode -ne 0 -or $queryText -match 'Access is denied|Error:\s*5\b') {
    Write-Warning "USN queryjournal failed (exit $queryCode): $queryText"
    Write-Warning 'Reboot the guest so SeBackupPrivilege applies, then run this script again.'
} else {
    Write-Host 'USN journal query OK (privileges work).'
    $baseline = 'C:\Users\Public\Quarantine\usn-baseline.json'
    if (Test-Path -LiteralPath $baseline) {
        $b = Get-Content -LiteralPath $baseline -Raw | ConvertFrom-Json
        $start = [string]$b.startUsn
        $read = Invoke-UsnReadJournal -StartUsn $start
        $readText = $read.Output -join ' '
        if ($read.ExitCode -eq 0) {
            Write-Host 'USN readjournal from baseline OK.'
        } elseif ($readText -match '1181|deleted from the journal') {
            Write-Host 'USN baseline start USN is stale (journal wrapped / Error 1181). Privileges are fine; host reset -Clean will refresh usn-baseline.json.'
        } elseif ($readText -match 'Access is denied|Error:\s*5\b') {
            Write-Warning "USN readjournal access denied: $readText"
            Write-Warning 'Reboot the guest so SeBackupPrivilege applies, then run this script again.'
        } else {
            Write-Warning "USN readjournal failed (exit $($read.ExitCode)): $readText"
        }
    } else {
        Write-Host 'No usn-baseline.json yet - read check skipped (run reset -Clean on the host after grant).'
    }
}

Write-Output 'GRANT_OK'
cmd /c exit 0
