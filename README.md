# Quarantine VM Utility

PowerShell utility to create and manage an **isolated VirtualBox Windows guest** for opening suspicious email, malware samples, and other quarantine work.

> **Go rewrite:** A Go + Wails implementation lives in [`go/`](go/README.md). Launch with `.\quarantine-go.ps1` (builds `go/quarantine.exe` on first run). Same config and sidecar layout; Wails UI replaces static `session.html` for dynamic diff browsing and on-demand snapshot disk reads.

The VM is configured with conservative defaults: host→guest clipboard (one-way paste), no drag-drop, USB disabled, recording off, and **internal networking (`intnet`)** so the guest has no host or internet access unless you change that.

## Prerequisites

- [VirtualBox](https://www.oracle.com/virtualization/virtualbox/) 7.x (detected at `D:\Program Files\Oracle\VirtualBox\` on this machine)
- A Windows 10/11 x64 ISO
- Enough disk/RAM for a 4 GB / 80 GB VM (configurable)

## Quick start

```powershell
# 0. Verify/install dependencies and config
.\Setup-Dependencies.ps1

# If ISO is missing, download from the page that opens into isos\ (any Windows *.iso name works), then:
.\Setup-Dependencies.ps1

# 1. Create VM
.\quarantine-vm.ps1 create

# 3. Install Windows (opens VirtualBox GUI)
.\quarantine-vm.ps1 install

# 4. After guest is hardened: log in as the payload user, then save a *live* baseline
.\quarantine-vm.ps1 snapshot

# 5. Daily workflow
.\quarantine-vm.ps1 start    # analyze samples (or skip — live reset already resumes)
.\quarantine-vm.ps1 preserve # keep evidence (live if VM is running)
.\quarantine-vm.ps1 reset -Clean    # resume the logged-in Clean session (no POST)
```

## Commands

| Command | Purpose |
|---------|---------|
| `create` | Register VM, disk, ISO, isolation settings |
| `install` | Start VM for first-time Windows setup |
| `start` | Boot quarantine VM |
| `stop` | ACPI shutdown (`-Force` power off) |
| `snapshot` | Live snapshot if VM is running. Existing name prompts to replace (child snapshots are deleted); `-Force` replaces without prompt. `-Offline` for disk-only. |
| `snapshots` | List snapshots (`live` = resume session, `disk` = cold boot) |
| `reset` | Restore and start; live snapshots skip POST/login. `-Clean` / `-SnapshotName` |
| `status` | Show VM name and power state |
| `network quarantine` | Internet-only via host mitmproxy (NAT + logging) |
| `network offline` | Fully isolated (`intnet`) |
| `proxy start\|stop\|status` | Manage mitmproxy on the host |
| `capture start\|stop` | Manage tshark PCAP capture on the host |

## Snapshots (manual only)

Nothing is snapshotted automatically — you save a baseline only when you run `snapshot`.

**Live vs disk-only**

| Kind | When | Restore |
|------|------|---------|
| **live** | VM is **running** (or saved) when you snapshot | Resumes the exact RAM state: logged-in desktop, no firmware POST, no Windows boot, no login |
| **disk-only** | VM is powered off, or you pass `-Offline` | Cold boot from firmware. You have to log in again |

VirtualBox calls this an *online snapshot*: pause briefly, write disk + RAM (`.sav`), then continue. `reset` restores that `.sav` and starts the VM — you land in the same Windows session.

`baseline` still **powers off** to flatten the snapshot tree, so that Clean is disk-only. For a resume-to-desktop Clean, snapshot while logged in (see below).

### Save a live baseline (logged-in session)

1. Start the VM and log in as the account you run samples under (`payload.username`, e.g. `jkcooper`).
2. Arrange the desktop how you want it. Turn off lock screen, screensaver, and sleep so restore does not sit at a lock prompt.
3. Leave the VM **running**. Do not shut down.
4. Save the snapshot (replaces existing `CleanSession` after confirmation):
   ```powershell
   .\quarantine-vm.ps1 snapshot
   ```
   Default name: **`CleanSession`** (from `cleanSnapshotName` in config). Custom name:
   ```powershell
   .\quarantine-vm.ps1 snapshot -SnapshotName "Before-Outlook" -SnapshotDescription "Baseline with Outlook installed"
   ```
   If that name already exists, you are prompted to replace it. Child snapshots such as `Evidence-*` under that name are deleted first (VirtualBox cannot replace a snapshot that still has children). Use `-Force` to replace without prompting:
   ```powershell
   .\quarantine-vm.ps1 snapshot -SnapshotName CleanSession -Force
   ```

Disk-only snapshot (old behavior — restore will POST and boot):
```powershell
.\quarantine-vm.ps1 snapshot -Offline
```

Stored under: `D:\Vbox\LabVM\Quarantine-Win11\Snapshots\` (live snapshots also store a RAM dump, roughly `memoryMb` in size).

### List snapshots

```powershell
.\quarantine-vm.ps1 snapshots
```

Each line shows `live` or `disk`. Current snapshot is marked `*`.

### Restore a snapshot

**Interactive** (lists name + date/time, you pick):

```powershell
.\quarantine-vm.ps1 reset
```

**Quick restore to Clean** (no prompt). Live Clean resumes the desktop; disk-only Clean cold-boots:

```powershell
.\quarantine-vm.ps1 reset -Clean
```

**Direct restore by name:**

```powershell
.\quarantine-vm.ps1 reset -SnapshotName "Evidence-phishing-sample-1"
```

`reset` starts the VM after restore. Do **not** use `start -Fresh` after a live restore — that discards the saved RAM and forces a cold boot.

### After testing (possibly compromised)

**`reset -Clean`** returns to your known-good session.

To **keep the compromised state** (including RAM / running processes) before wiping:

```powershell
# VM still running — live evidence snapshot (RAM + disk)
.\quarantine-vm.ps1 preserve
# or with a label:
.\quarantine-vm.ps1 preserve -SnapshotName "phishing-email-1"

.\quarantine-vm.ps1 reset -Clean
```

Re-open saved evidence later (resumes that session if it was live):

```powershell
.\quarantine-vm.ps1 reset -SnapshotName "Evidence-phishing-email-1"
```

List all snapshots (Clean + evidence): `.\quarantine-vm.ps1 snapshots`

Evidence snapshots live under `D:\Vbox\LabVM\Quarantine-Win11\Snapshots\` alongside `Clean`. Delete old evidence manually in VirtualBox when no longer needed.

### Replace all snapshots with a fresh disk baseline

Wipes the entire snapshot tree, merges the **current disk state** into the base `.vdi`, then saves one new **disk-only** snapshot (default **`Clean`**). The VM is powered off — restore will cold-boot:

```powershell
.\quarantine-vm.ps1 baseline
```

Then start, log in, and take a live snapshot if you want reset-to-desktop.

**VirtualBox GUI:** with the VM running → **Snapshots** tab → **Take**. That is the same live snapshot. Powered off → **Take** is disk-only.

## Network isolation

Default: **intnet** (offline) — guest NIC on an isolated internal network (no host, no internet). Works without the VirtualBox host-only driver.

| Mode / command | Behavior |
|----------------|----------|
| `network offline` / `intnet` | No internet, no LAN (recommended for offline analysis) |
| `network quarantine` | NAT + host mitmproxy — internet only, RFC1918 blocked, HTTP(S) logged |
| `hostonly` | Host ↔ guest only (requires VirtualBox host networking driver) |
| `none` | No NIC |
| `nat` | Raw internet (use only during Windows setup) |

### Quarantine networking (internet-only + logging)

Use when you need the guest to reach the **public internet** but **not** your LAN or host services.

**Architecture:** guest → `10.0.2.2:8080` (mitmproxy on host) → internet. DNS via VirtualBox NAT (`10.0.2.3`). Enforcement is two-layer: guest Windows Firewall (only proxy + DNS outbound) and mitmproxy ACL (blocks RFC1918 even if guest rules are bypassed).

**Host prerequisites:**

```powershell
.\Setup-Dependencies.ps1       # creates .venv and installs mitmproxy from requirements.txt
# Optional PCAP capture:
# Install Wireshark (includes Npcap + tshark): https://www.wireshark.org/download.html
.\Setup-Dependencies.ps1       # verifies tools and creates log dirs
```

**One-time guest setup** (run inside VM as Administrator, then baseline on host):

```powershell
# In guest:
powershell -ExecutionPolicy Bypass -File \\path\to\network\guest\Configure-QuarantineGuestNetwork.ps1

# On host after guest is configured:
.\quarantine-vm.ps1 stop
.\quarantine-vm.ps1 baseline
```

**Enable quarantine network for a session:**

```powershell
.\quarantine-vm.ps1 network quarantine   # NAT + start proxy/capture
.\quarantine-vm.ps1 start                  # auto-starts proxy/capture when config mode is quarantine
.\quarantine-vm.ps1 start -SkipProxy     # start VM without touching proxy (debugging)
```

**Return to offline analysis:**

```powershell
.\quarantine-vm.ps1 network offline
```

**Log locations** (sensitive — treat as evidence):

| Path | Contents |
|------|----------|
| `D:\Vbox\LabVM\logs\proxy\{session}\flows.mitm` | mitmproxy flow dump (replayable) |
| `D:\Vbox\LabVM\logs\proxy\{session}\access.log` | URL / method / timestamp |
| `D:\Vbox\LabVM\logs\proxy\{session}\errors.log` | Blocked private-IP attempts |
| `D:\Vbox\LabVM\logs\pcap\quarantine-*.pcap` | Wireshark capture (NAT guest traffic) |

Review flows: `.venv\Scripts\mitmproxy.exe -r D:\Vbox\LabVM\logs\proxy\{session}\flows.mitm`  
Review PCAPs: open in Wireshark.

**Proxy / capture commands** (host, independent of VM start):

```powershell
.\quarantine-vm.ps1 proxy start
.\quarantine-vm.ps1 proxy status
.\quarantine-vm.ps1 proxy stop
.\quarantine-vm.ps1 capture start
.\quarantine-vm.ps1 capture stop
```

### Phase 2 — HTTPS inspection (deferred)

TLS decryption requires installing the mitmproxy CA in the guest **Trusted Root Certification Authorities** store:

1. Start proxy once so mitmproxy generates its CA under `logs\proxy\certs\`
2. `.\quarantine-vm.ps1 proxy export-ca`
3. Install `mitmproxy-ca-cert.cer` in the guest

**Limits:** certificate pinning, HSTS preload, Windows Update, and many non-browser apps will **not** be decryptable even with the CA installed.

## Windows setup: "Let's connect you to a network"

The quarantine VM uses **`intnet`** (no internet) by design. Windows 11 setup requires a network unless you bypass it. **Do not click "Install driver"** — the adapter works; there is simply no network on `intnet`.

### Option A — Bypass (recommended for quarantine)

On the "Let's connect you to a network" screen:

1. Press **Shift + F10** (opens Command Prompt)
2. Run:
   ```
   oobe\bypassnro
   ```
3. PC reboots — continue setup with a **local account** (no Microsoft account)

### Option B — Temporary internet for setup

From PowerShell on the host:

```powershell
.\quarantine-vm.ps1 stop -Force
.\quarantine-vm.ps1 network nat
.\quarantine-vm.ps1 start
```

Complete Windows setup, then isolate again:

```powershell
.\quarantine-vm.ps1 stop
.\quarantine-vm.ps1 network offline
```

### Guest Additions (required for clipboard paste)

Host→guest paste needs **VirtualBox Guest Additions** installed in the guest.

**Mount the ISO from the host** (creates a DVD drive if missing — fixes VirtualBox “Can't mount image”):

```powershell
.\quarantine-vm.ps1 guest-additions
```

Then in the guest:

1. Open **File Explorer → DVD drive** (VirtualBox Guest Additions)
2. Run **VBoxWindowsAdditions.exe** (or `VBoxWindowsAdditions-amd64.exe`)
3. Reboot when prompted

Or use the GUI: **Devices → Insert Guest Additions CD image** (only works if a DVD drive is present; use `guest-additions` if you see “Can't mount image”).

Clipboard mode is **host→guest only** by default:

```powershell
.\quarantine-vm.ps1 clipboard hosttoguest   # default
.\quarantine-vm.ps1 clipboard disabled      # lock down after a session
```

## Guest hardening checklist

After Windows installs, before taking the `Clean` snapshot:

- Turn off Windows Update (or pause indefinitely)
- Disable Defender **cloud-delivered protection** and automatic sample submission
- Disable OneDrive, Store auto-updates, and sign-in nags
- For live snapshots: disable lock screen, screensaver, and sleep on the payload account so restore does not sit at a lock prompt
- Install VirtualBox Guest Additions if you need host→guest paste (see above)
- Install only the tools you need (mail client, browser, hex editor, etc.)

Optional unattended install: customize `templates\autounattend.xml` (change passwords), then set `autounattendPath` in config and follow VirtualBox floppy/VISO docs to attach it at first boot.

## Transferring samples to the guest

Use the **inbox** workflow for one-way host→guest transfer with a transient read-only share:

```powershell
.\quarantine-vm.ps1 inbox push .\sample.exe
.\quarantine-vm.ps1 start
.\quarantine-vm.ps1 inbox open
# In guest: copy from \\VBOXSVR\quarantine-in (requires Guest Additions)
.\quarantine-vm.ps1 inbox close
```

- Files land in `D:\Vbox\LabVM\quarantine-inbox` (configurable via `inbox.hostPath`)
- Each push is logged with SHA256 to `logs\inbox\transfers.jsonl`
- The share is transient and removed on `inbox close`, `stop`, `reset`, or isolation apply
- Set `inbox.requireNetworkOff`: `true` to block `inbox open` unless network is `none`, `offline`, or `intnet`

Alternatives for maximum isolation:

1. Detach network (`.\quarantine-vm.ps1 network none`) before opening the inbox, or
2. Use a dedicated USB drive passed only when needed

Never map host folders that contain sensitive data.

### Guest control (run commands from host)

With **Guest Additions** installed, the host can run commands or copy files into the guest via `VBoxManage guestcontrol` — no shared folder needed.

**Setup:**

1. Create a dedicated local account in the guest (e.g. `quarantine`) with a known password.
2. Store the password in `D:\Vbox\LabVM\secrets\guest-password.txt` (or set `QUARANTINE_GUEST_PASSWORD`).
3. Set `guest.username` in `config/quarantine-vm.json`.
4. VM must be **running**.

```powershell
.\quarantine-vm.ps1 guest test
.\quarantine-vm.ps1 guest run whoami
.\quarantine-vm.ps1 guest ps "Get-Process | Select-Object -First 3"
.\quarantine-vm.ps1 guest copy .\sample.exe
```

Files copied with `guest copy` land in `C:\Users\Public\Quarantine` by default (`guest.copyTargetDir`).

**Security:** guest credentials live on the host — use a disposable guest account, not your personal password. Guest control is host→guest only; malware cannot invoke it from inside the VM without a separate escape.

## Safety notes

- Run analysis on a machine you can afford to rebuild; VM escape is rare but not impossible.
- Never sign into personal Microsoft/Google accounts inside the guest.
- Always `reset` after a session so persistence and lateral movement artifacts are discarded.
- Treat the host OS as semi-trusted: keep VirtualBox updated.

| `mount-iso` | Re-attach Windows ISO for install |
| `relocate` | Move VM disk to `vmDataDir` (local D: drive) |

## Storage layout

VM disks, config, and snapshots are stored together under **`D:\Vbox\LabVM`** (not in `%USERPROFILE%\VirtualBox VMs`):

```
D:\Vbox\LabVM\Quarantine-Win11\
  Quarantine-Win11.vbox      # VM settings
  Quarantine-Win11.vdi       # disk
  Quarantine-Win11.nvram       # UEFI state
  Snapshots\                   # Clean snapshot and diffs
  Logs\
```

| Path | Contents |
|------|----------|
| `D:\Vbox\LabVM\{vmName}\` | Everything for the VM |
| `isos\` (project folder) | Windows ISO only |

Set `vmDataDir` in config to change the base path. New VMs are created with `--basefolder` pointing here automatically.

If an older VM still has files under `%USERPROFILE%\VirtualBox VMs\`, consolidate:

```powershell
.\quarantine-vm.ps1 consolidate
```

## Configuration reference

See `config/quarantine-vm.example.json` for