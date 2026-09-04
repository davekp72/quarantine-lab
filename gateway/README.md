# Quarantine Gateway Appliance
#
# Topology
#   NIC1 (WAN): VirtualBox NAT → internet
#   NIC2 (LAN): intnet `quarantine-net` → 10.66.0.1/24
#   Lab guest: intnet, 10.66.0.15/24, gateway/DNS 10.66.0.1
#
# Services
#   dnsmasq          DNS (+ optional DHCP)
#   nftables         forward + MASQUERADE + REDIRECT :80/:443 → mitm :8082
#   mitmdump :8080   explicit proxy (PAC fallback)
#   mitmdump :8082   transparent MITM
#   tcpdump          LAN PCAP under /var/log/quarantine/pcap
#
# Host commands (after implement)
#   .\quarantine-vm.ps1 gateway create
#   .\quarantine-vm.ps1 gateway start
#   .\quarantine-vm.ps1 gateway provision   # copy scripts + run first-boot via guestcontrol
#   .\quarantine-vm.ps1 network gateway
#   .\quarantine-vm.ps1 gateway status
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
