# Host tools (not redistributed)

## Sysmon

Do **not** commit `Sysmon64.exe`. Microsoft does not permit third parties to redistribute Sysinternals utilities. Download them from Microsoft instead.

- License FAQ: https://learn.microsoft.com/en-us/sysinternals/license-faq
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

From the repo root:

```powershell
.\scripts\Get-Sysmon.ps1
# or
.\Setup-Dependencies.ps1
.\quarantine-vm.ps1 sysmon fetch
```

The script:

1. Downloads `Sysmon.zip` from `download.sysinternals.com`.
2. Verifies the Microsoft Authenticode signature on `Sysmon64.exe`.
3. Optionally checks SHA-256 against `tools\Sysmon64.sha256` if that pin file exists.
4. Records the installed version in `tools\Sysmon.version` (local only).

To pin a reviewed build, put a SHA-256 hex digest in `tools\Sysmon64.sha256` (comments starting with `#` are ignored). Update the pin only after checking a new Microsoft release.
