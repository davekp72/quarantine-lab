#!/bin/bash
# Repair WAN DHCP + DNS on Quarantine-Gateway (no dhclient required).
set -euo pipefail

LAN_IF="${QUARANTINE_LAN_IF:-enp0s8}"
WAN_IF="${QUARANTINE_WAN_IF:-enp0s3}"
LAN_IP="${QUARANTINE_LAN_GATEWAY:-10.66.0.1}"

if [[ -f /etc/quarantine-gateway/ifaces.env ]]; then
  # shellcheck disable=SC1091
  source /etc/quarantine-gateway/ifaces.env || true
fi

echo "Repairing WAN/DNS: WAN=$WAN_IF LAN=$LAN_IF LAN_IP=$LAN_IP"

mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/disable-stub.conf <<EOF
[Resolve]
DNSStubListener=no
EOF

# LAN: address only — never put public DNS here
cat >/etc/netplan/99-quarantine-lan.yaml <<EOF
network:
  version: 2
  ethernets:
    ${LAN_IF}:
      dhcp4: false
      addresses: [${LAN_IP}/24]
      optional: true
EOF

# WAN: DHCP via netplan (uses systemd-networkd / NetworkManager — not dhclient)
cat >/etc/netplan/98-quarantine-wan.yaml <<EOF
network:
  version: 2
  ethernets:
    ${WAN_IF}:
      dhcp4: true
      dhcp6: false
      nameservers:
        addresses: [10.0.2.3, 1.1.1.1, 8.8.8.8]
EOF

chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
netplan apply || true

ip link set "$WAN_IF" up || true
ip link set "$LAN_IF" up || true

# Force DHCP renew without dhclient
if command -v networkctl >/dev/null 2>&1; then
  networkctl renew "$WAN_IF" || networkctl reconfigure "$WAN_IF" || true
fi
if command -v nmcli >/dev/null 2>&1; then
  nmcli device connect "$WAN_IF" || true
fi

# Wait briefly for DHCP lease
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ip -4 addr show dev "$WAN_IF" | grep -q 'inet '; then
    break
  fi
  sleep 1
done

if ! ip -4 addr show dev "$LAN_IF" | grep -q " ${LAN_IP}/"; then
  ip addr add "${LAN_IP}/24" dev "$LAN_IF" 2>/dev/null || true
fi

rm -f /etc/resolv.conf
printf 'nameserver 10.0.2.3\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' >/etc/resolv.conf
systemctl restart systemd-resolved 2>/dev/null || true
if [[ -L /etc/resolv.conf ]] || grep -q '127.0.0.53' /etc/resolv.conf 2>/dev/null; then
  rm -f /etc/resolv.conf
  printf 'nameserver 10.0.2.3\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n' >/etc/resolv.conf
fi

echo "=== addresses ==="
ip -4 addr
echo "=== routes ==="
ip route
echo "=== resolv.conf ==="
cat /etc/resolv.conf
echo "=== tests ==="
ping -c 2 -W 3 10.0.2.3 || true
getent hosts gb.archive.ubuntu.com || true
ping -c 2 -W 3 gb.archive.ubuntu.com || true
echo "Repair finished."
