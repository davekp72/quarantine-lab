#!/bin/bash
# Apply hardened nftables (no LAN SSH). Arg1 = sudo password when NOPASSWD is unset.
set -euo pipefail
PASS="${1:-}"

cat >/tmp/do-nft-root.sh <<'EOS'
#!/bin/bash
set -euo pipefail
install -d /opt/quarantine-gateway/scripts /etc/quarantine-gateway /usr/local/lib/quarantine
cp /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf
cp /tmp/enable-agent-forward.sh /opt/quarantine-gateway/scripts/enable-agent-forward.sh
chmod +x /opt/quarantine-gateway/scripts/enable-agent-forward.sh
if [[ -f /tmp/quarantine-nftables-permissive-forward.inc ]]; then
  install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /opt/quarantine-gateway/nftables-permissive-forward.inc
  install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /etc/quarantine-gateway/nftables-permissive-forward.inc
fi
if [[ -f /tmp/quarantine-nftables-permissive-nat.inc ]]; then
  install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /opt/quarantine-gateway/nftables-permissive-nat.inc
  install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /etc/quarantine-gateway/nftables-permissive-nat.inc
fi
if [[ -f /tmp/quarantine-nftables-permissive-output.inc ]]; then
  install -m 0644 /tmp/quarantine-nftables-permissive-output.inc /opt/quarantine-gateway/nftables-permissive-output.inc
  install -m 0644 /tmp/quarantine-nftables-permissive-output.inc /etc/quarantine-gateway/nftables-permissive-output.inc
fi
if [[ -f /tmp/quarantine-nftables-fakenet.conf ]]; then
  install -m 0644 /tmp/quarantine-nftables-fakenet.conf /opt/quarantine-gateway/nftables-fakenet.conf
fi
if [[ -f /tmp/nft-inject-permissive.py ]]; then
  install -m 0755 /tmp/nft-inject-permissive.py /opt/quarantine-gateway/scripts/nft-inject-permissive.py
  install -m 0755 /tmp/nft-inject-permissive.py /usr/local/lib/quarantine/nft-inject-permissive.py
fi

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

MODE=permissive
if [[ -f /etc/quarantine-gateway/traffic-mode ]]; then
  MODE=$(tr -d '[:space:]' </etc/quarantine-gateway/traffic-mode | tr '[:upper:]' '[:lower:]')
fi
TEMPLATE=/opt/quarantine-gateway/nftables.conf
case "$MODE" in
  fakenet)
    if [[ -f /opt/quarantine-gateway/nftables-fakenet.conf ]]; then
      TEMPLATE=/opt/quarantine-gateway/nftables-fakenet.conf
    fi
    ;;
esac

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
sed -e "s/__WAN__/${WAN_IF}/g" \
    -e "s/__LAN__/${LAN_IF}/g" \
    -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
    -e "s/__LAN_IP__/${LAN_IP}/g" \
    -e "s/__GUEST_IP__/${GUEST_IP}/g" \
    -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
    "$TEMPLATE" >"$rendered"
if grep -q '__PERMISSIVE_' "$rendered" 2>/dev/null; then
  python3 /opt/quarantine-gateway/scripts/nft-inject-permissive.py "$rendered" \
    /etc/quarantine-gateway/nftables-permissive-forward.inc \
    /etc/quarantine-gateway/nftables-permissive-nat.inc \
    /etc/quarantine-gateway/nftables-permissive-output.inc
  sed -i -e "s/__WAN__/${WAN_IF}/g" -e "s/__LAN__/${LAN_IF}/g" "$rendered"
fi
if grep -q '__PERMISSIVE_' "$rendered" 2>/dev/null; then
  echo "nftables placeholders remain after render:" >&2
  grep -n '__PERMISSIVE_' "$rendered" >&2 || true
  exit 1
fi
cp "$rendered" /etc/nftables.conf

nft -f /etc/nftables.conf
echo "=== inet filter input ==="
nft list chain inet filter input
echo "=== inet filter forward ==="
nft list chain inet filter forward
echo "=== inet filter output ==="
nft list chain inet filter output
EOS
chmod +x /tmp/do-nft-root.sh

if [[ -n "$PASS" ]]; then
  printf '%s\n' "$PASS" | sudo -S -p '' bash /tmp/do-nft-root.sh
else
  sudo -n bash /tmp/do-nft-root.sh
fi
