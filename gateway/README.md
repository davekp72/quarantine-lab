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
#                    LAN→WAN drops RFC1918/link-local/CGNAT before general accept
#   mitmdump :8080   explicit proxy (PAC fallback) — block_private resolves DNS
#   mitmdump :8082   transparent MITM (stopped in FakeNet mode)
#   FakeNet-NG       optional LAN sinkhole (switch with gateway mode)
#   tcpdump          LAN PCAP under /var/log/quarantine/pcap (all protocols)
#
# Guest Windows (Configure-QuarantineGuestNetwork.ps1 -Mode gateway):
#   Outbound allow (normal internet). Only special block: SSH to the gateway itself.
#   Private/host-LAN isolation is enforced on this appliance, not by guest port pinning.#
# Host NAT port-forwards (gateway VM) bind 127.0.0.1 only (SSH :2222, agent :9443).
#
# Re-apply nftables after template edits (from host):
#   Copy gateway/nftables.conf + scripts/apply-nftables-harden.sh into the gateway, then:
#     /tmp/apply-nftables-harden.sh '<gateway-sudo-password>'
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
#   .\quarantine-vm.ps1 gateway mode fakenet       # sinkhole (no WAN)
#   .\quarantine-vm.ps1 gateway mode permissive    # internet + MITM
#
# Manual first boot (if not using cloud-init)
#   1. Install Ubuntu Server in Quarantine-Gateway VM (2 NICs: NAT + intnet)
#   2. Create user matching config network.gateway (username/password)
#   3. Enable OpenSSH + install Guest Additions
#   4. Optional (faster provision): passwordless sudo for that user:
#        echo 'quarantine ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/quarantine
#   5. On host: .\quarantine-vm.ps1 gateway provision
#      (provision uses sudo -S if NOPASSWD is not set)
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
#   permissive — default: WAN NAT, dnsmasq, mitm :80/:443, other ports forwarded
#   fakenet    — FakeNet-NG MultiHost sinkhole; no LAN→WAN; DNS/HTTP/HTTPS/SMTP faked
#   FakeNet HTTPS reuses the mitmproxy CA (same cert installed in the Windows guest).
#   FakeNet-NG uses iptables NFQUEUE on the LAN iface. Config sets LinuxFlushIptables=No
#   so nftables (WAN SSH, agent DNAT) is not wiped. Re-provision once to install the venv:
#     .\quarantine-vm.ps1 gateway provision
#