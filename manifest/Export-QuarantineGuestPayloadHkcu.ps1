#Requires -Version 5.1
<#
.SYNOPSIS
  Export HKCU\Software for the current (payload) user as HKU-prefixed registry entries.
  Run via guest control as the standard test user (e.g. jkcooper), not the lab admin.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutFile,
    [int]$MaxDepth = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Normalize-RegKeyPath {
    param([string]$Path)
    $normalized = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $normalized = $normalized -replace '^HKEY_CURRENT_USER\\', 'HKCU:\'
    $normalized = $normalized -replace '^HKEY_USERS\\', 'HKU:\'
    return $normalized
}

$registry = New-Object System.Collections.Generic.List[object]
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$userName = $env:USERNAME

function Export-RegKey {
    param([string]$Path, [string]$KeyPrefix)
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
                    k = $KeyPrefix
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
        [string]$KeyPrefix,
        [int]$MaxDepth = 12,
        [int]$Depth = 0
    )

    Export-RegKey -Path $Path -KeyPrefix $KeyPrefix
    if ($Depth -ge $MaxDepth) { return }

    try {
        Get-ChildItem -LiteralPath $Path -ErrorAction Stop | ForEach-Object {
            $subKey = Normalize-RegKeyPath -Path $_.PSPath
            $hkuKey = $subKey -replace '^HKCU:\\', "HKU:\$sid\"
            Export-RegTree -Path $_.PSPath -KeyPrefix $hkuKey -MaxDepth $MaxDepth -Depth ($Depth + 1)
        }
    } catch { }
}

$hkcuSoftware = 'Registry::HKEY_CURRENT_USER\Software'
if (Test-Path -LiteralPath $hkcuSoftware) {
    Export-RegTree -Path $hkcuSoftware -KeyPrefix "HKU:\$sid\Software" -MaxDepth $MaxDepth
}

$payload = [ordered]@{
    userName       = $userName
    sid            = $sid
    entryCount     = $registry.Count
    registry       = $registry.ToArray()
}

$payload | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "Payload HKCU export: $userName ($sid) -> $($registry.Count) entries"
