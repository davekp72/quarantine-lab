# Regshot binaries (not bundled)

## Required for automated manifest registry diff

**`Regshot-x64-ANSI.exe` from [GitHub Seabreg/Regshot](https://github.com/Seabreg/Regshot) is the GUI only — it cannot run headless under guestcontrol.**

Download **RegShot CMD** from [SourceForge regcmd](https://sourceforge.net/projects/regshot/files/regcmd/) and place in this folder:

- `Regshot_cmd-x64-ANSI.exe` (recommended)

## Optional (manual use in guest GUI)

- `Regshot-x64-ANSI.exe` or `Regshot-x64-Unicode.exe` from GitHub

## Deploy

```powershell
.\quarantine-vm.ps1 regshot copy
```

## Workflow (live session baseline)

```powershell
# 1. Restore clean session
.\quarantine-vm.ps1 reset                    # pick CleanSession
#    OR: .\quarantine-vm.ps1 reset -SnapshotName CleanSession -Mark

# 2. Mark baseline BEFORE any test changes (required if step 1 had no -Mark)
.\quarantine-vm.ps1 manifest mark -SnapshotName CleanSession

# 3. Make changes, then preserve
.\quarantine-vm.ps1 preserve -SnapshotName LiveEvi

# 4. Diff (use your actual snapshot names)
.\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-LiveEvi -Refresh -StopAfter
```

`reset -Clean` still auto-marks the configured `cleanSnapshotName` snapshot (default `Clean`).

Baselines are saved as:

- `D:\Vbox\LabVM\logs\manifests\<SnapshotName>-baseline.json` (USN)
- `D:\Vbox\LabVM\logs\manifests\<SnapshotName>-regshot.hivu` (Regshot)
