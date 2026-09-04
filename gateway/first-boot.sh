#!/bin/bash
# Quarantine Gateway first-boot / provision script.
# Idempotent: safe to re-run. Expects Debian/Ubuntu with systemd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT=/opt/quarantine-gateway
LOG=/var/log/quarantine
LAN_CIDR="${QUARANTINE_LAN_CIDR:-10.66.0.0/24}"
LAN_IP="${QUARANTINE_LAN_GATEWAY:-10.66.0.1}"
LAN_IF="${QUARANTINE_LAN_IF:-}"
WAN_IF="${QUARANTINE_WAN_IF:-}"

mkdir -p "$OPT" "$LOG/pcap" "$LOG/proxy" /etc/quarantine-gateway
cp -a "$ROOT/." "$OPT/"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  nftables dnsmasq tcpdump python3 python3-pip python3-venv \
  iptables ca-certificates curl openssl net-tools iproute2

# Detect interfaces: prefer eth0/enp0s3 as WAN (NAT), eth1/enp0s8 as LAN (intnet)
detect_ifaces() {
  local -a ifs=()
  while read -r name; do
    [[ "$name" == "lo" ]] && continue
    ifs+=("$name")
  done < <(ls /sys/class/net | sort)
  if [[ -z "$WAN_IF" && ${#ifs[@]} -ge 1 ]]; then WAN_IF="${ifs[0]}"; fi
  if [[ -z "$LAN_IF" && ${#ifs[@]} -ge 2 ]]; then LAN_IF="${ifs[1]}"; fi
  if [[ -z "$LAN_IF" ]]; then LAN_IF="${WAN_IF:-eth0}"; fi
  if [[ -z "$WAN_IF" ]]; then WAN_IF=eth0; fi
}
detect_ifaces

echo "WAN=$WAN_IF LAN=$LAN_IF LAN_IP=$LAN_IP" | tee /etc/quarantine-gateway/ifaces.env

# LAN static address (netplan if present, else systemd-networkd, else ip)
configure_lan() {
  if command -v netplan >/dev/null 2>&1 && [[ -d /etc/netplan ]]; then
    cat >/etc/netplan/99-quarantine-lan.yaml <<EOF
network:
  version: 2
  ethernets:
    ${LAN_IF}:
      dhcp4: false
      addresses: [${LAN_IP}/24]
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF
    # Keep WAN on DHCP if separate
    if [[ "$WAN_IF" != "$LAN_IF" ]]; then
      cat >/etc/netplan/98-quarantine-wan.yaml <<EOF
network:
  version: 2
  ethernets:
    ${WAN_IF}:
      dhcp4: true
EOF
    fi
    netplan apply || true
  else
    ip addr flush dev "$LAN_IF" 2>/dev/null || true
    ip addr add "${LAN_IP}/24" dev "$LAN_IF" 2>/dev/null || true
    ip link set "$LAN_IF" up || true
  fi
}
configure_lan

# IP forwarding
cat >/etc/sysctl.d/99-quarantine-gateway.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=0
EOF
sysctl --system >/dev/null || sysctl -w net.ipv4.ip_forward=1

# dnsmasq
install -m 0644 "$OPT/dnsmasq.conf" /etc/dnsmasq.d/quarantine-gateway.conf
# Disable default dnsmasq conflicting bind if packaged defaults exist
if [[ -f /etc/dnsmasq.conf ]]; then
  sed -i 's/^#\?bind-interfaces.*/bind-interfaces/' /etc/dnsmasq.conf || true
fi
systemctl enable dnsmasq
systemctl restart dnsmasq

# nftables — substitute interface names
sed -e "s/__WAN__/${WAN_IF}/g" -e "s/__LAN__/${LAN_IF}/g" -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
  "$OPT/nftables.conf" >/etc/nftables.conf
systemctl enable nftables
systemctl restart nftables

# mitmproxy venv
python3 -m venv /opt/quarantine-gateway/venv
/opt/quarantine-gateway/venv/bin/pip install --upgrade pip
/opt/quarantine-gateway/venv/bin/pip install 'mitmproxy>=10,<12'

# PAC for explicit fallback (gateway LAN IP)
sed "s/__GATEWAY__/${LAN_IP}/g" "$OPT/mitm/quarantine.pac" >/etc/quarantine-gateway/quarantine.pac
cp "$OPT/mitm/block_private.py" /etc/quarantine-gateway/block_private.py

install -m 0644 "$OPT/systemd/quarantine-mitm-explicit.service" /etc/systemd/system/
install -m 0644 "$OPT/systemd/quarantine-mitm-transparent.service" /etc/systemd/system/
install -m 0644 "$OPT/systemd/quarantine-capture.service" /etc/systemd/system/
install -m 0755 "$OPT/scripts/start-capture.sh" /usr/local/sbin/quarantine-capture-start
install -m 0755 "$OPT/scripts/stop-capture.sh" /usr/local/sbin/quarantine-capture-stop
install -m 0755 "$OPT/scripts/status.sh" /usr/local/sbin/quarantine-gateway-status
install -m 0755 "$OPT/scripts/sync-hint.txt" /etc/quarantine-gateway/sync-hint.txt 2>/dev/null || true

systemctl daemon-reload
systemctl enable quarantine-mitm-explicit quarantine-mitm-transparent
systemctl restart quarantine-mitm-explicit quarantine-mitm-transparent

# Export CA once mitm has run
sleep 2
CA_SRC=""
for c in /root/.mitmproxy/mitmproxy-ca-cert.pem /home/*/.mitmproxy/mitmproxy-ca-cert.pem; do
  [[ -f "$c" ]] && CA_SRC="$c" && break
done
if [[ -n "$CA_SRC" ]]; then
  openssl x509 -in "$CA_SRC" -outform DER -out /etc/quarantine-gateway/mitmproxy-ca-cert.cer 2>/dev/null \
    || cp "$CA_SRC" /etc/quarantine-gateway/mitmproxy-ca-cert.pem
  cp "$CA_SRC" /var/log/quarantine/proxy/mitmproxy-ca-cert.pem 2>/dev/null || true
fi

touch /opt/quarantine-gateway/.installed
echo "Quarantine gateway provisioned. LAN ${LAN_IP} on ${LAN_IF}, WAN ${WAN_IF}"
/usr/local/sbin/quarantine-gateway-status || true
