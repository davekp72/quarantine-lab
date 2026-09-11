# Quarantine Gateway Appliance
#
# Topology
#   NIC1 (WAN): VirtualBox NAT → internet
#   NIC2 (LAN): intnet `quarantine-net` → 10.66.0.1/24
#   Lab guest: intnet, 10.66.0.15/24, gateway/DNS 10.66.0.1
#
# Services
#   dnsmasq          DNS (+ optional DHCP) — permissive mode
#   nftables         forward + MASQUERADE; :80/:443 → mitm :8082 (permissive)
#                    FakeNet mode: no LAN→WAN; listeners on :53/:80/:443/:25
#                    SSH (:22) accepted on WAN only (host NAT PF); blocked from LAN guest
#                    permissive: RFC1918 drop, MITM :80/:443, extra ports from allowlist
#                    FakeNet: no LAN→WAN; listeners on :53/:80/:443/:25
#                    output (both modes): drop private/link-local/metadata; pin public DNS;
#                    allow lab LAN replies; permissive upstream ports from allowlist (default 80/443)
#   mitmdump :8080   explicit proxy (PAC fallback) — block_private resolves DNS
#   mitmdump :8082   transparent MITM (stopped in FakeNet mode)
#   FakeNet-NG       optional LAN sinkhole (switch with gateway mode)
#   tcpdump          LAN PCAP under /var/log/quarantine/pcap (all protocols)
#
# Service isolation
#   mitm + capture: quarantine-mitm / quarantine-capture (non-root + caps).
#   FakeNet: root (NFQUEUE/iptables + privileged ports); non-root was unreliable.
#   ExecStartPre=+quarantine-ensure-service-users prepares users/dirs/venv perms.
#   nftables output still drops private/metadata and allowlists public upstream.
#   mitm CA: /var/lib/quarantine-mitm

# Guest Windows (Configure-QuarantineGuestNetwork.ps1 -Mode gateway):
#   Outbound allow (normal internet). Only special block: SSH to the gateway itself.
#   Private/host-LAN isolation is enforced on this appliance, not by guest port pinning.#
# Host NAT port-forwards (gateway VM) bind 127.0.0.1 only (SSH :2222, agent :9443).
#
# Re-apply nftables after template edits (from host):
#   Copy into the gateway /tmp:
#     nftables.conf, nftables-fakenet.conf (optional),
#     nftables-permissive-{forward,nat,output}.inc,
#     scripts/nft-inject-permissive.py, scripts/enable-agent-forward.sh,
#     scripts/apply-nftables-harden.sh
#   Then: /tmp/apply-nftables-harden.sh '<gateway-sudo-password>'
#   Or re-run: .\quarantine-vm.ps1 gateway provision
#
# Host commands (after implement)
#   .\quarantine-vm.ps1 gateway create
#   .\quarantine-vm.ps1 gateway start
#   .\quarantine-vm.ps1 gateway provision   # copy scripts + run first-boot via guestcontrol
#   .\quarantine-vm.ps1 network gateway
#   .\quarantine-vm.ps1 gateway status
#   .\quarantine-vm.ps1 gateway clean-pcaps              # drop leftover PCAPs (keeps active)
#   .\quarantine-vm.ps1 gateway clean-pcaps --older-than 7d
#   .\quarantine-vm.ps1 gateway clean-pcaps --include-proxy
#   .\quarantine-vm.ps1 gateway mode               # show permissive | fakenet
#   .\quarantine-vm.ps1 gateway mode fakenet       # default: sinkhole (no WAN)
#   .\quarantine-vm.ps1 gateway mode permissive    # allowlisted internet + MITM
#
# Manual first boot (if not using cloud-init)
#   1. Install Ubuntu Server in Quarantine-Gateway VM (2 NICs: NAT + intnet)
#   2. Create user matching network.gateway.username; password from secrets\gateway-password.txt
#   3. Enable OpenSSH + install Guest Additions
#   4. On host: .\quarantine-vm.ps1 setup secrets
#      .\quarantine-vm.ps1 gateway provision
#      (provision installs the host SSH key, disables password SSH, removes NOPASSWD:ALL)
#   SSH after provision:
#      ssh -i D:\Vbox\LabVM\secrets\gateway-id_ed25519 -p 2222 quarantine@127.0.0.1
#
# first-boot notes (Ubuntu 24+/26+)
#   - Disables systemd-resolved stub listener so dnsmasq can bind :53 on 10.66.0.1
#   - Chmods netplan YAML to 600 (netplan rejects world-readable files)
#
# Guest lab VM
#   Run Configure-QuarantineGuestNetwork.ps1 -Mode Gateway
#   (static 10.66.0.15, GW/DNS 10.66.0.1, PAC http://10.66.0.1:8080/quarantine.pac, install CA)
#
# Traffic modes (switch anytime; guest IP/DNS unchanged)
#   fakenet    — default: FakeNet-NG sinkhole; no LAN→WAN; all LAN traffic captured
#   permissive — allowlisted WAN (default TCP 80/443 MITM + DNS via gateway); other ports dropped
#                 Attempts still appear in PCAP and are highlighted as policy breaches.
#   FakeNet HTTPS reuses the mitmproxy CA (same cert installed in the Windows guest).
#   FakeNet-NG uses iptables NFQUEUE on the LAN iface. Config sets LinuxFlushIptables=No
#   so nftables (WAN SSH, agent DNAT) is not wiped. Re-provision once to install the venv:
#     .\quarantine-vm.ps1 gateway provision
#