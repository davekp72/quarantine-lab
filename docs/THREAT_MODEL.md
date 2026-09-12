# Threat model

Quarantine Lab reduces the chance that opening suspect content infects the
operator’s daily-driver OS. It does **not** provide high-assurance isolation
(no hardware-enforced guest, no formally verified hypervisor).

## Assets

| Asset | Why it matters |
|-------|----------------|
| Host OS, files, and credentials | Primary thing we are trying not to lose |
| Lab VM disks and snapshots | Evidence and the next clean restore point |
| Gateway logs / PCAPs / proxy flows | Network evidence; may contain victim data |
| Operator identity | Personal accounts inside the guest become malware-accessible |

## Intended use

1. Restore a disposable **CleanSession** (logged-in analysis desktop).
2. Introduce a sample via the agent inbox (`C:\Users\Public\Quarantine\inbox`) or, with `-GuestAdditions`, the read-only `\\VBOXSVR` share / host-to-guest paste.
3. Execute or open it in the guest as a **non-admin payload user**.
4. Capture evidence (snapshot, Sysmon/USN/registry, PCAP/proxy).
5. Restore CleanSession (or the disk **Clean** baseline after setup changes).

Default network path is the Linux **gateway** VM on an internal network.

## Trust boundaries

```
 Operator / host
        |  VirtualBox (primary escape boundary)
        |  Agent HTTP 127.0.0.1:9443 → gateway NAT → guest:9443
        v
 Windows analysis guest (payload user + lab admin + agent service)
        |  intnet 10.66.0.0/24
        v
 Linux gateway (FakeNet or permissive MITM + nftables)
        |  NAT uplink (FakeNet: no LAN→WAN; permissive: allowlist)
        v
 Internet
```

**VirtualBox is the primary escape boundary.** A guest-to-host escape can
reach the host regardless of gateway policy. Guest Additions (HGCM, shared
folders, clipboard) are **not** installed by default; they are an optional
`-GuestAdditions` fallback.

## Network workflows (do not mix them up)

| Mode | Intent | WAN |
|------|--------|-----|
| **FakeNet** (default) | Sample talks to local fake services (DNS/HTTP/SMTP/…). | No. Attempts are sinkholed or dropped; still in LAN PCAP. |
| **Permissive** | Sample needs real sites or live C2 on an allowlist. | Yes, for listed TCP/UDP ports. Default web ports are MITM’d. Traffic outside the allowlist is dropped and still captured. |
| **Offline / intnet** | No gateway WAN; guest only sees the lab LAN. | No. |

Permissive mode **intentionally permits controlled external communication**.
That is a different threat than FakeNet. Confirm the host VPN/ISP banner
before Launch if you care about source IP.

## Residual attack surfaces

These remain even when the lab is configured as intended:

- **Hypervisor** — USB, drag-drop, audio, and persistent shared folders are
  disabled by default; clipboard is disabled unless `-GuestAdditions` is used.
- **Guest agent** — SYSTEM HTTP on TCP 9443, reachable from the host only via
  the gateway NAT bind on `127.0.0.1`. File/exec APIs are allowlisted. Token
  theft at SYSTEM still means fake evidence.
- **Guest Additions (opt-in)** — 3D, shared folders, drag-drop, clipboard, and
  additions bugs. Only in play when you pass `-GuestAdditions`.
- **Inbox** — default is an agent copy into `C:\Users\Public\Quarantine\inbox`.
  Treat the host inbox directory as semi-trusted after use. `\\VBOXSVR` is the
  `-GuestAdditions` path.
- **Clipboard** — disabled by default. Host-to-guest paste (Additions) can
  carry hostile content onto the guest; do not copy secrets out of the guest.
- **Gateway** — nftables bugs, FakeNet patches, or a permissive allowlist
  that is too wide. Analysis daemons run as dedicated users; fail-closed
  emergency nftables drop LAN→WAN if the normal ruleset will not load.
- **Operator** — personal email/cloud accounts in the guest, reusing host
  passwords, skipping `reset -Clean`, or running permissive while believing
  you are in FakeNet.

## Out of scope

- Detecting every sample or reconstructing every artifact
- Protecting the guest from the sample (the guest is sacrificial)
- Hiding the lab from malware that fingerprints VMs (stealth settings only
  soften common VirtualBox tells)
- Multi-tenant / untrusted operators on the same host

## Operator rules

- Use a host you can wipe.
- Keep VirtualBox updated.
- Never use personal accounts or production credentials in the guest.
- Prefer FakeNet; switch to permissive only when you need real WAN.
- `preserve` then `reset -Clean` after each case.
- Put your home ISP substring in `ui.homeIspPatterns` if you want the UI to
  flag non-VPN egress (the sample config ships with an empty list).
