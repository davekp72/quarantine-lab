# Quarantine Lab

### Warning: This has been built by an amateur using AI tools. It will have bugs. Use at your own risk

An isolated **VirtualBox Windows lab** for opening suspicious email, malware
samples, and other quarantine work. This reduces risk; it **cannot guarantee
containment**. VirtualBox is the primary escape boundary.

**License:** [Apache-2.0](LICENSE) · **Security:** [SECURITY.md](SECURITY.md) ·
**Threat model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) ·
**Third-party:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

**Main command:** `.\quarantine-vm.ps1`  
**Desktop UI:** `.\quarantine-vm.ps1 ui`

---

## Quick start

A new public clone should get to a first analysis session with this path.

### 1. Install VirtualBox

Install [VirtualBox 7.x](https://www.oracle.com/virtualization/virtualbox/).
You need a Windows 10/11 x64 ISO (any `*.iso` in `isos\` is detected).

### 2. Clone the repository

```powershell
git clone https://github.com/davekp72/quarantine-lab.git
cd quarantine-lab
```

### 3. Run the prerequisites check

```powershell
.\Setup-Dependencies.ps1
```

That verifies VirtualBox, the ISO, Python/mitmproxy, and **downloads Sysmon
from Microsoft** (Authenticode-verified). Sysmon is not shipped in git.

```powershell
copy config\quarantine-vm.example.json config\quarantine-vm.json
# Edit vmDataDir, payload.username (default: analyst), and ui.homeIspPatterns
.\quarantine-vm.ps1 setup secrets
```

`setup secrets` writes unique passwords and gateway SSH keys under
`{vmDataDir}\secrets\` (never commit that directory). It also renders
`{vmDataDir}\unattend\autounattend.xml` and packs
`{vmDataDir}\unattend\unattend.img` (floppy with FirstLogon scripts).

### 4. Create the gateway

```powershell
.\quarantine-vm.ps1 gateway create
# Install Ubuntu on that VM (OpenSSH + Guest Additions), then:
.\quarantine-vm.ps1 gateway provision
.\quarantine-vm.ps1 gateway export-ca
```

Default traffic mode is **FakeNet** (no real WAN). Details:
[`gateway/README.md`](gateway/README.md).

### 5. Create the Windows VM

One command (secrets + create + unattend install). The lab NIC is on the
**gateway intnet from create**. FirstLogon (from the remastered setup ISO)
installs the agent and static `10.66.0.15` addressing:

```powershell
.\quarantine-vm.ps1 build-windows
```

The Linux gateway must already exist (`gateway create` / `gateway provision`).
`build-windows` starts it before Windows Setup and waits for **agent /health**
(`127.0.0.1:9443` via the gateway), not Guest Additions.

Useful flags:
- `-Force` — destroy/recreate the VM named in config (renamed VMs are untouched)
- `-NoWait` — return after starting Setup; later: `.\quarantine-vm.ps1 build-windows -Continue`
- `-WaitMinutes 120` — custom agent-health wait
- `-GuestAdditions` — fallback: wait for guestcontrol, mount Additions ISO, enable clipboard

Manual equivalent: `setup secrets` → `create` → `install` (same NIC/unattend).

### 6. Install and harden the guest

1. FirstLogon already put the guest on the gateway LAN (`10.66.0.15` → `10.66.0.1`)
   and installed the agent from the setup ISO. Confirm on the host:

   ```powershell
   .\quarantine-vm.ps1 agent health
   ```

2. Accounts from config (also created by unattend):
   - **`Administrator`** — built-in admin (lab tooling, Sysmon); password from `guest.password`
   - **`analyst`** (or `payload.username`) — standard user for samples

3. Guest Additions are **optional** (clipboard paste, auto-resize, `\\VBOXSVR`).
   Default copy/run/inbox uses the agent. To enable paste/resize:

   ```powershell
   .\quarantine-vm.ps1 guest-additions
   ```

   In the guest: run the installer from the DVD, then reboot. Pass
   `-GuestAdditions` on later `guest` / `inbox` / `payload` commands to use
   guestcontrol instead of the agent.

   If health fails after a Force rebuild, re-run `setup secrets` (needs
   `go\quarantine-agent.exe`) so the remastered ISO contains the binary.

4. Optional fingerprint softening (VM powered off):

   ```powershell
   .\quarantine-vm.ps1 stealth
   ```

### 7. Run the containment self-test

```powershell
.\scripts\Test-QuarantineContainment.ps1
.\Invoke-QuarantineLabSmokeTest.ps1
```

The containment script checks isolation flags, gateway mode, and residual-risk
reminders. The smoke test writes harmless guest markers you can diff later.

### 8. Create CleanSession

Shut down after the guest looks right, then:

```powershell
.\quarantine-vm.ps1 baseline          # disk-only Clean (golden image)
.\quarantine-vm.ps1 start
# Log in as the payload user, arrange the desktop, leave the VM running:
.\quarantine-vm.ps1 snapshot          # live CleanSession
```

### 9. Launch the first analysis

```powershell
.\quarantine-vm.ps1 reset -Clean
.\quarantine-vm.ps1 inbox push .\sample.bin
.\quarantine-vm.ps1 inbox open
# In guest: C:\Users\Public\Quarantine\inbox
.\quarantine-vm.ps1 inbox close
.\quarantine-vm.ps1 capture start
# ... work in the guest ...
.\quarantine-vm.ps1 capture stop
.\quarantine-vm.ps1 preserve -SnapshotName "first-run"
.\quarantine-vm.ps1 reset -Clean
.\quarantine-vm.ps1 ui    # or: manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-first-run
```

Daily loop after that: restore CleanSession → work → preserve → reset → compare.

---

## The daily workflow (operational reference)

```
  Set up VM  →  Baseline  →  CleanSession  →  Do stuff  →  Evidence  →  Compare
     once         once          once/refresh     each run      save         review
```

| Step | What it means | Command |
|------|----------------|---------|
| **1. Set up VM** | Create the guest, install Windows, harden it, gateway | [Quick start](#quick-start) |
| **2. Baseline** | Freeze a clean **disk** image named `Clean` | `.\quarantine-vm.ps1 baseline` |
| **3. CleanSession** | Freeze a **logged-in desktop** you can jump back to | `.\quarantine-vm.ps1 snapshot` (VM running) |
| **4. Do stuff** | Open samples, browse, click the phishing link | Work inside the guest |
| **5. Evidence** | Save that session before you wipe it | `.\quarantine-vm.ps1 preserve` |
| **6. Compare** | Diff files / registry / network vs the clean session | `.\quarantine-vm.ps1 manifest view ...` or **UI** |

```powershell
.\quarantine-vm.ps1 reset -Clean
```

That restores **CleanSession** (live) when configured that way — back at the
logged-in desktop, no Windows login screen.

### Why two “clean” snapshots?

| Snapshot | Kind | Purpose |
|----------|------|---------|
| **`Clean`** | Disk-only | Long-term golden image after setup. Restore = full boot + login. Created by `baseline`. |
| **`CleanSession`** | Live (RAM + disk) | Daily “reset to my analysis desktop.” Restore = instant resume. Created by `snapshot` while logged in. |

Think of **Baseline** as “factory reset of the disk,” and **CleanSession** as
“bookmark of my ready desktop.”

Use `baseline` after big setup changes (gateway network, Sysmon, tools).

---

## Network modes

| Mode | Use when |
|------|----------|
| `network gateway` | Default analysis path — lab guest on intnet via Linux gateway |
| `network offline` | Isolation (intnet, no WAN through the gateway) |
| `network none` / `hostonly` | No sample egress / host-only |

`network quarantine` and `network nat` now enable **gateway** (host-NAT mitm
is retired).

### FakeNet vs permissive

These are **separate workflows**. Both keep **full-frame LAN PCAP** (including
dropped WAN attempts). The guest IP/DNS does not change.

| Mode | What the guest sees |
|------|---------------------|
| **FakeNet** (default) | No WAN. FakeNet-NG answers DNS/HTTP/SMTP/etc. locally and holes the rest. |
| **Permissive** | Allowlisted **real internet**. TCP 80/443 MITM. Extra TCP/UDP ports you list go to WAN. DNS forced to the gateway unless you turn that off. Attempts outside the allowlist are dropped, still in PCAP, and highlighted in Traffic. |

Permissive mode **intentionally permits controlled external communication**.

```powershell
.\quarantine-vm.ps1 gateway mode               # show
.\quarantine-vm.ps1 gateway mode fakenet       # sinkhole (default)
.\quarantine-vm.ps1 gateway mode permissive    # allowlisted internet + MITM
```

Edit the allowlist in the UI (**Permissive allowlist**) or in
`network.gateway.permissive` (`tcpPorts`, `udpPorts`, `forceDnsToGateway`,
`allowIcmp`). Default ports are TCP 80 and 443.

Analysis daemons (FakeNet, mitm, capture) run as dedicated non-root users with
bounded capabilities. FakeNet HTTPS is signed with the **same mitmproxy CA**
the guest already trusts. Certificate pinning can still fail.

The desktop UI shows your **host public IP and ISP** before Launch so you can
confirm a VPN is on. Set `ui.homeIspPatterns` to substrings of your home ISP
(sample config ships **empty** — nothing is flagged until you add one). Disable
with `"ui": { "warnPublicIpBeforeLaunch": false }`.

Logs (treat as evidence): proxy flows, PCAPs, inbox SHA256 — under
`{vmDataDir}\logs\`.

---

## Snapshots in one minute

| Kind | When you take it | What restore does |
|------|------------------|-------------------|
| **Live** | VM is **running** | Resumes the exact desktop (no POST / login) |
| **Disk-only** | VM off, or `snapshot -Offline`, or `baseline` | Cold boot; you log in again |

`baseline` always produces disk-only **`Clean`**.  
`snapshot` while running produces live **`CleanSession`**.  
`preserve` while running produces live **`Evidence-*`**.

---

## Daily cheat sheet

```powershell
.\quarantine-vm.ps1 reset -Clean
# ... analysis in the guest ...
.\quarantine-vm.ps1 preserve -SnapshotName "case-42"
.\quarantine-vm.ps1 reset -Clean
.\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-case-42
```

```powershell
.\quarantine-vm.ps1 snapshots
.\quarantine-vm.ps1 status
```

---

## Command reference

| Command | Purpose |
|---------|---------|
| `create` / `install` | Build VM / first Windows setup |
| `start` / `stop` | Boot / shut down (`-Force` = power off) |
| `baseline` | New disk-only **`Clean`** (flattens old snapshots) |
| `snapshot` | Live **`CleanSession`** (or named); `-Force` replaces |
| `preserve` | Save **`Evidence-*`** of the current session |
| `reset -Clean` | Restore clean session and start |
| `reset -SnapshotName …` | Restore any snapshot |
| `snapshots` / `status` | List snapshots / VM state |
| `manifest view` / `diff` | Compare clean vs evidence |
| `ui` | Desktop app for the same workflow |
| `network …` / `gateway …` | Isolation, internet path, FakeNet/permissive |
| `capture start\|stop` | Packet / proxy capture |
| `inbox push\|open\|close` | One-way sample transfer |
| `guest …` | Run commands / copy files into guest |
| `sysmon fetch` | Download Sysmon from Microsoft |
| `stealth` | Soften VBox MAC/CPU/ACPI fingerprints (powered off) |
| `guest-additions` | Mount Guest Additions ISO (optional fallback) |
| `-GuestAdditions` | Use guestcontrol / VBOXSVR / clipboard for this command |

---

## Guest helpers

**Inbox** (preferred sample transfer; agent copy by default):

```powershell
.\quarantine-vm.ps1 inbox push .\sample.exe
.\quarantine-vm.ps1 inbox open    # guest: C:\Users\Public\Quarantine\inbox
.\quarantine-vm.ps1 inbox close
```

With `-GuestAdditions`, `inbox open` mounts `\\VBOXSVR\quarantine-in` instead.

**Guest control** (agent HTTP by default; `-GuestAdditions` for VBox guestcontrol):

```powershell
.\quarantine-vm.ps1 guest test
.\quarantine-vm.ps1 guest run whoami
.\quarantine-vm.ps1 guest copy .\tool.exe
```

Clipboard is **disabled** by default (needs Guest Additions):

```powershell
.\quarantine-vm.ps1 -GuestAdditions clipboard hosttoguest
```

---

## Storage layout

Lab VM data lives under **`vmDataDir`** (example: `C:\QuarantineLab`):

```
{vmDataDir}\Quarantine-Win11\
  Quarantine-Win11.vbox
  Quarantine-Win11.vdi
  Snapshots\          # Clean, CleanSession, Evidence-*
{vmDataDir}\logs\     # proxy, pcap, manifests, inbox
{vmDataDir}\secrets\  # passwords, SSH keys, agent token — do not commit
```

Move an old VM home into that layout:

```powershell
.\quarantine-vm.ps1 consolidate
```

---

## Safety

- Use a host you can rebuild; VM escape is rare but possible.
- Do not sign into personal accounts inside the guest.
- Always `preserve` (if you care) then `reset -Clean` after a session.
- Keep VirtualBox updated; treat host inbox paths as semi-trusted.
- Default residual guest surface is the agent listener (TCP 9443 from the gateway IP).
- Guest Additions, host-to-guest clipboard, and `\\VBOXSVR` are residual **only when you pass `-GuestAdditions`**. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Configuration

Copy `config/quarantine-vm.example.json` → `config/quarantine-vm.json`.
The live file is gitignored.

| Field | Meaning |
|-------|---------|
| `vmName` / `vmDataDir` | VM name and disk location |
| `cleanSnapshotName` | Disk baseline name (default `Clean`) |
| `manifest.sessionBaselineSnapshot` | Live clean name (default `CleanSession`) |
| `guest` / `payload` | Usernames and passwords in gitignored `config/quarantine-vm.json` (`setup secrets` generates missing passwords). Payload default in the sample is `analyst`. |
| `network.gateway.password` / `sshPrivateKey` | Gateway password in config JSON; ed25519 key under `{vmDataDir}/secrets`. Password SSH is off. |
| `network.mode` | Always `gateway` for analysis (Linux VM). |
| `network.gateway.trafficMode` | Default `fakenet`. `permissive` is allowlisted real internet. |
| `network.gateway.permissive` | WAN allowlist: `tcpPorts` (default 80,443), `udpPorts`, `forceDnsToGateway`, `allowIcmp`. |
| `ui.homeIspPatterns` | Optional ISP/org substrings to flag as home (non-VPN) in the Launch prompt. Empty by default. |
| `isolation.stealth` | Fingerprint softening |
| `sysmon.hostSysmonExe` | Local path after `sysmon fetch` (`tools\Sysmon64.exe`) |

Gateway details: [`gateway/README.md`](gateway/README.md).  
Go architecture / build: [`go/README.md`](go/README.md).  
Releases: [`docs/RELEASING.md`](docs/RELEASING.md).
