#!/bin/bash
# Apply hardened nftables (no LAN SSH). Arg1 = sudo password when NOPASSWD is unset.
set -euo pipefail
PASS="${1:-}"

cat >/tmp/do-nft-root.sh <<'EOS'
#!/bin/bash
set -euo pipefail
install -d /opt/quarantine-gateway/scripts
cp /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf
cp /tmp/enable-agent-forward.sh /opt/quarantine-gateway/scripts/enable-agent-forward.sh
chmod +x /opt/quarantine-gateway/scripts/enable-agent-forward.sh

if [[ -f /etc/quarantine-gateway/ifaces.env ]]; then
  # shellcheck disable=SC1091
  source /etc/quarantine-gateway/ifaces.env
fi
WAN_IF="${WAN_IF:-enp0s3}"
LAN_IF="${LAN_IF:-enp0s8}"
LAN_IP="${LAN_IP:-10.66.0.1}"
LAN_CIDR=10.66.0.0/24
GUEST_IP=10.66.0.15
AGENT_PORT=9443

sed -e "s/__WAN__/${WAN_IF}/g" \
    -e "s/__LAN__/${LAN_IF}/g" \
    -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
    -e "s/__LAN_IP__/${LAN_IP}/g" \
    -e "s/__GUEST_IP__/${GUEST_IP}/g" \
    -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
    /opt/quarantine-gateway/nftables.conf >/etc/nftables.conf

nft -f /etc/nftables.conf
echo "=== inet filter input ==="
nft list chain inet filter input
echo "=== inet filter forward ==="
nft list chain inet filter forward
EOS
chmod +x /tmp/do-nft-root.sh

if [[ -n "$PASS" ]]; then
  printf '%s\n' "$PASS" | sudo -S -p '' bash /tmp/do-nft-root.sh
else
  sudo -n bash /tmp/do-nft-root.sh
fi
