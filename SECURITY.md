# Security policy

## This is a risk-reduction lab, not a guarantee

Quarantine Lab is for opening suspect files and running malware **inside
disposable VirtualBox snapshots**. It reduces accidental host exposure. It
**cannot guarantee containment**. VirtualBox is the primary escape boundary.
Treat the host as potentially compromised after a session that matters.

Read the threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Intended use

- Open suspicious email, documents, and binaries in a **CleanSession** snapshot.
- Prefer **FakeNet** (no real WAN) unless you explicitly need live C2 or updates.
- **Permissive** mode is a separate workflow: it intentionally allows
  controlled external communication (default TCP 80/443 MITM).
- Do **not** sign into personal accounts or reuse host credentials in the guest.
- Preserve evidence, then `reset -Clean`. Rebuild the host if you do not trust it.

## Residual attack surfaces

- VirtualBox
- Guest agent listener (TCP 9443 from the gateway IP; allowlisted file/exec)
- Guest Additions, host-to-guest clipboard, and `\\VBOXSVR` **when `-GuestAdditions` is used**
- Permissive-mode WAN allowlist and DNS policy
- Operator error (wrong snapshot, personal accounts, VPN off)

## Reporting vulnerabilities

Please **do not** open a public issue for exploitable bugs in containment,
credential handling, or guest-to-host paths.

- Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository if it is enabled.
- Otherwise email the maintainer listed on the GitHub profile that owns
  [quarantine-lab](https://github.com/davekp72/quarantine-lab).

Include: affected version or commit, setup (host OS, VirtualBox version),
and a minimal reproduction that does **not** include live malware samples.

On GitHub, also enable **secret scanning** / push protection and **private
vulnerability reporting** for this repository (Settings → Code security).
