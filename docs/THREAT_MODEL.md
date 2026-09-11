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
2. Introduce a sample via the read-only inbox share or host-to-guest paste.
3. Execute or open it in the guest as a **non-admin payload user**.
4. Capture evidence (snapshot, Sysmon/USN/registry, PCAP/proxy).
5. Restore CleanSession (or the disk **Clean** baseline after setup changes).

Default network path is the Linux **gateway** VM on an internal network.

## Trust boundaries

```
 Operator / host
        |  VirtualBox + Guest Additions  <-- primary escape boundary
        v
 Windows analysis guest (payload user + lab admin)
        |  intnet 10.66.0.0/24
        v
 Linux gateway (FakeNet or permissive MITM + nftables)
        |  NAT uplink (FakeNet: no LAN→WAN; permissive: allowlist)
        v
 Internet
```

**VirtualBox is the primary escape boundary.** A guest-to-host escape, a
buggy Guest Additions shared feature, or a hostile USB/clipboard path can
reach the host regardless of gateway policy.

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

- **Hypervisor / Guest Additions** — 3D, shared folders, drag-drop, and
  additions bugs. This project disables USB, drag-drop, audio, and persistent
  shared folders by default; clipboard is host-to-guest only.
- **Clipboard** — host-to-guest paste can carry hostile content onto the
  guest; a guest-to-host escape or mis-set bidirectional clipboard can go
  the other way. Do not copy secrets out of the guest.
- **Inbox share** — temporary read-only `quarantine-in` is the supported
  sample path. Treat that host directory as semi-trusted after use.
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
