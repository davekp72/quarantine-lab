# Quarantine VM

An isolated **VirtualBox Windows lab** for opening suspicious email, malware samples, and other quarantine work.

**Main command:** `.\quarantine-vm.ps1`  
**Desktop UI:** `.\quarantine-vm.ps1 ui`

---

## The workflow (what you do every day)

```
  Set up VM  →  Baseline  →  CleanSession  →  Do stuff  →  Evidence  →  Compare
     once         once          once/refresh     each run      save         review
```

| Step | What it means | Command |
|------|----------------|---------|
| **1. Set up VM** | Create the guest, install Windows, harden it, optional gateway | See [One-time setup](#1-set-up-vm-one-time) |
| **2. Baseline** | Freeze a clean **disk** image named `Clean` (cold boot later) | `.\quarantine-vm.ps1 baseline` |
| **3. CleanSession** | Freeze a **logged-in desktop** you can jump back to instantly | `.\quarantine-vm.ps1 snapshot` (VM running) |
| **4. Do stuff** | Open samples, browse, click the phishing link, etc. | Work inside the guest |
| **5. Evidence** | Save that (possibly bad) session before you wipe it | `.\quarantine-vm.ps1 preserve` |
| **6. Compare** | Diff files / registry / network vs the clean session | `.\quarantine-vm.ps1 manifest view ...` or **UI** |

Then return to a known-good desktop:

```powershell
.\quarantine-vm.ps1 reset -Clean
```

That restores **CleanSession** (live) when configured that way — you’re back at the logged-in desktop, no Windows login screen.

---

## Why two “clean” snapshots?

| Snapshot | Kind | Purpose |
|----------|------|---------|
| **`Clean`** | Disk-only | Long-term golden image after setup. Restore = full boot + login. Created by `baseline`. |
| **`CleanSession`** | Live (RAM + disk) | Daily “reset to my analysis desktop.” Restore = instant resume. Created by `snapshot` while logged in. |

Think of **Baseline** as “factory reset of the disk,” and **CleanSession** as “bookmark of my ready desktop.”

---

## 1. Set up VM (one-time)

### Prerequisites

- [VirtualBox](https://www.oracle.com/virtualization/virtualbox/) 7.x  
- A Windows 10/11 x64 ISO  
- Roughly 4 GB RAM / 80 GB disk for the guest (editable in config)

### Create and install

```powershell
# Dependencies + config
.\Setup-Dependencies.ps1

# Copy/edit config if needed
copy config\quarantine-vm.example.json config\quarantine-vm.json

# Unique passwords + gateway SSH keys (writes {vmDataDir}\secrets\)
.\quarantine-vm.ps1 setup secrets

.\quarantine-vm.ps1 create
.\quarantine-vm.ps1 install
```

Complete Windows setup in the VirtualBox window. Autologon runs once; disable it before the Clean baseline (`.\quarantine-vm.ps1 guest disable-autologon` while the VM is running, or `baseline` does this if the guest is up).

**Stuck on “Let’s connect you to a network”?**  
Press **Shift+F10**, run `oobe\bypassnro`, reboot, then finish with a **local account**.  
(Or temporarily use `.\quarantine-vm.ps1 network nat` for setup, then `network offline` or `network gateway` afterward.)

### After Windows is up

1. Install **Guest Additions** (needed for paste, guest control, resize):

   ```powershell
   .\quarantine-vm.ps1 guest-additions
   ```

   In the guest: run the installer from the DVD drive, then reboot.

2. Create your accounts (config names):
   - **`quarantine`** — admin (lab tooling, Sysmon, guest control)
   - **`jkcooper`** (or `payload.username`) — standard user for samples

3. Harden lightly: pause updates, turn off Defender cloud submission, disable lock screen / sleep on the payload account (so live restore doesn’t hit a lock screen).

4. **Optional — internet via gateway** (recommended if the sample needs the net):

   ```powershell
   .\quarantine-vm.ps1 gateway create
   # Install Ubuntu on that VM (OpenSSH + Guest Additions), then:
   .\quarantine-vm.ps1 gateway provision
   .\quarantine-vm.ps1 gateway export-ca
   .\quarantine-vm.ps1 network gateway
   ```

5. **Guest provision** (one elevated script: agent, guestcontrol ACLs, gateway NIC/proxy/CA, Sysmon, event-log grant, disable autologon):

   ```powershell
   .\quarantine-vm.ps1 guest provision
   ```

   In the guest (elevated PowerShell as `quarantine`), run **only** this line:

   ```powershell
   & 'C:\Users\Public\Quarantine\Invoke-QuarantineGuestProvision.ps1'
   ```

   Do not paste `Set-ExecutionPolicy` after it. The script sets Bypass itself; a second line becomes a `>>` continuation.

   Then on the host: `.\quarantine-vm.ps1 agent health`

   Details: [`gateway/README.md`](gateway/README.md).

6. **Optional — soften VirtualBox fingerprints** (MAC / CPU profile / ACPI; Guest Additions stay):

   ```powershell
   # VM powered off
   .\quarantine-vm.ps1 stealth
   ```

When the guest looks the way you want it, shut it down and continue.

---

## 2. Take Baseline

Powers off the VM, flattens old snapshots, and saves a fresh **disk-only** snapshot named **`Clean`**.

```powershell
.\quarantine-vm.ps1 baseline
```

Use this after big setup changes (gateway network, Sysmon, tools). Restore later with a cold boot if needed.

---

## 3. Take a CleanSession

1. Start the VM and **log in as the payload user** (the account you run samples under).
2. Arrange the desktop; leave the VM **running** (do not shut down).
3. On the host:

```powershell
.\quarantine-vm.ps1 snapshot
```

That creates a live snapshot named **`CleanSession`** (from `manifest.sessionBaselineSnapshot`).  
Replace an existing one without prompting:

```powershell
.\quarantine-vm.ps1 snapshot -Force
```

You now have a one-click “back to clean desktop” via `reset -Clean`.

---

## 4. Do stuff

Work inside the guest as usual: open the sample, click the link, run the installer.

Useful host helpers:

```powershell
# Drop a file into the guest inbox
.\quarantine-vm.ps1 inbox push .\sample.exe
.\quarantine-vm.ps1 inbox open
# In guest: copy from \\VBOXSVR\quarantine-in, then:
.\quarantine-vm.ps1 inbox close

# If using the gateway — capture traffic for this session
.\quarantine-vm.ps1 capture start
# ... analyze ...
.\quarantine-vm.ps1 capture stop
```

The desktop UI (`.\quarantine-vm.ps1 ui`) shows your **host public IP and ISP** before Launch so you can confirm the VPN is on. Configured home ISPs (`ui.homeIspPatterns`, default **Community Fibre**) show in red; any other provider shows in green. Disable with `"ui": { "warnPublicIpBeforeLaunch": false }` in config.

Clipboard paste (host → guest only by default):

```powershell
.\quarantine-vm.ps1 clipboard hosttoguest
```

---

## 5. Evidence

Before you reset, **save the dirty session**:

```powershell
.\quarantine-vm.ps1 preserve
# or with a label:
.\quarantine-vm.ps1 preserve -SnapshotName "phishing-email-1"
```

That creates an **`Evidence-...`** live snapshot (disk + RAM) if the VM is still running.

Then go back to clean:

```powershell
.\quarantine-vm.ps1 reset -Clean
```

Re-open an evidence session later:

```powershell
.\quarantine-vm.ps1 reset -SnapshotName "Evidence-phishing-email-1"
.\quarantine-vm.ps1 snapshots
```

---

## 6. Compare

Diff the clean session against an evidence snapshot (files, registry, network artifacts):

```powershell
# Interactive UI
.\quarantine-vm.ps1 ui

# Or CLI
.\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-phishing-email-1
.\quarantine-vm.ps1 manifest diff  -FromSnapshot CleanSession -ToSnapshot Evidence-phishing-email-1
```

`Clean` (disk baseline) can also be a compare source if you prefer that over `CleanSession`.

---

## Daily cheat sheet

```powershell
.\quarantine-vm.ps1 reset -Clean              # start from clean desktop
# ... do the analysis in the guest ...
.\quarantine-vm.ps1 preserve -SnapshotName "case-42"
.\quarantine-vm.ps1 reset -Clean              # throw away the live mess
.\quarantine-vm.ps1 manifest view -FromSnapshot CleanSession -ToSnapshot Evidence-case-42
```

List everything:

```powershell
.\quarantine-vm.ps1 snapshots
.\quarantine-vm.ps1 status
```

---

## Network modes (short)

| Mode | Use when |
|------|----------|
| `network gateway` | Default analysis path — lab guest on intnet via Linux gateway |
| `network offline` | Isolation (intnet, no WAN through the gateway) |
| `network none` / `hostonly` | No sample egress / host-only |

`network quarantine` and `network nat` now enable **gateway** (host-NAT mitm is retired).

### Gateway traffic: FakeNet vs permissive

Both keep **full-frame LAN PCAP** (every protocol, including dropped WAN attempts). The guest IP/DNS does not change.

| Mode | What the guest sees |
|------|---------------------|
| **FakeNet** (default) | No WAN. FakeNet-NG answers DNS/HTTP/SMTP/etc. locally and holes the rest. |
| **Permissive** | Allowlisted real internet. TCP 80/443 MITM. Extra TCP/UDP ports you list go to WAN. DNS forced to the gateway unless you turn that off. Attempts outside the allowlist are dropped, still in PCAP, and highlighted in Traffic. |

Edit the allowlist in the UI (**Permissive allowlist**) or in `network.gateway.permissive` (`tcpPorts`, `udpPorts`, `forceDnsToGateway`, `allowIcmp`). Default ports are standard web: TCP 80 and 443.

```powershell
.\quarantine-vm.ps1 gateway provision          # once (installs FakeNet on the appliance)
.\quarantine-vm.ps1 gateway mode               # show
.\quarantine-vm.ps1 gateway mode fakenet       # sinkhole (default)
.\quarantine-vm.ps1 gateway mode permissive    # allowlisted internet + MITM
```

Analysis daemons (FakeNet, mitm, capture) run as dedicated non-root users with bounded capabilities; `gateway provision` / `gateway mode` sync those units and patches.
The desktop UI Gateway panel has the same **FakeNet** / **Permissive** buttons (confirms before opening WAN). FakeNet HTTPS is signed with the **same mitmproxy CA** the guest already trusts. Certificate pinning can still fail. Use permissive when you need real upstream sites.

Gateway session sketch:

```powershell
.\quarantine-vm.ps1 network gateway
.\quarantine-vm.ps1 start
.\quarantine-vm.ps1 capture start
# ... work ...
.\quarantine-vm.ps1 capture stop   # logs under D:\Vbox\LabVM\logs\
```

Logs (treat as evidence): proxy flows, PCAPs, inbox SHA256 — under `D:\Vbox\LabVM\logs\`.

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
| `stealth` | Soften VBox MAC/CPU/ACPI fingerprints (powered off) |
| `guest-additions` | Mount Guest Additions ISO |

---

## Guest helpers

**Inbox** (preferred sample transfer):

```powershell
.\quarantine-vm.ps1 inbox push .\sample.exe
.\quarantine-vm.ps1 inbox open    # guest: \\VBOXSVR\quarantine-in
.\quarantine-vm.ps1 inbox close
```

**Guest control** (needs Guest Additions + `guest` credentials in config):

```powershell
.\quarantine-vm.ps1 guest test
.\quarantine-vm.ps1 guest run whoami
.\quarantine-vm.ps1 guest copy .\tool.exe
```

---

## Storage layout

Everything for the lab VM lives under **`D:\Vbox\LabVM`** (set `vmDataDir` in config):

```
D:\Vbox\LabVM\Quarantine-Win11\
  Quarantine-Win11.vbox
  Quarantine-Win11.vdi
  Snapshots\          # Clean, CleanSession, Evidence-*
D:\Vbox\LabVM\logs\   # proxy, pcap, manifests, inbox
```

Move an old VM home into that layout:

```powershell
.\quarantine-vm.ps1 consolidate
```

---

## Safety

- Use a host you can rebuild; VM escape is rare but possible.
- Don’t sign into personal accounts inside the guest.
- Always `preserve` (if you care) then `reset -Clean` after a session.
- Keep VirtualBox updated; treat host clipboard/inbox paths as semi-trusted.

---

## Configuration

Copy `config/quarantine-vm.example.json` → `config/quarantine-vm.json`.

Important fields:

| Field | Meaning |
|-------|---------|
| `vmName` / `vmDataDir` | VM name and disk location |
| `cleanSnapshotName` | Disk baseline name (default `Clean`) |
| `manifest.sessionBaselineSnapshot` | Live clean name (default `CleanSession`) |
| `guest` / `payload` | Usernames plus `passwordFile` under `{vmDataDir}/secrets` (never commit passwords) |
| `network.gateway.passwordFile` / `sshPrivateKey` | Unique gateway password (guestcontrol/sudo) and ed25519 key. Password SSH is off. |
| `network.mode` | Always `gateway` for analysis (Linux VM). Host-NAT mitm is retired. `intnet` remains for offline isolation. |
| `network.gateway.trafficMode` | Default `fakenet`. `permissive` is allowlisted real internet. |
| `network.gateway.permissive` | WAN allowlist: `tcpPorts` (default 80,443), `udpPorts`, `forceDnsToGateway`, `allowIcmp`. |
| `isolation.stealth` | Fingerprint softening |

Full example: [`config/quarantine-vm.example.json`](config/quarantine-vm.example.json).  
Gateway details: [`gateway/README.md`](gateway/README.md).
