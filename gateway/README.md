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
#   1. Install Ubuntu Server 22.04/24.04 in Quarantine-Gateway VM (2 NICs)
#   2. Attach shared folder or copy this `gateway/` tree to /opt/quarantine-gateway-src
#   3. sudo bash /opt/quarantine-gateway-src/first-boot.sh
#
# Guest lab VM
#   Run Configure-QuarantineGuestNetwork.ps1 -Mode Gateway
#   (static 10.66.0.15, GW/DNS 10.66.0.1, PAC http://10.66.0.1:8080/quarantine.pac, install CA)
