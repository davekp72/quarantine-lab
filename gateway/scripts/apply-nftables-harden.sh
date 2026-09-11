#!/bin/bash
# Apply hardened nftables (no LAN SSH). Arg1 = sudo password when NOPASSWD is unset.
set -euo pipefail
PASS="${1:-}"

cat >/tmp/do-nft-root.sh <<'EOS'
#!/bin/bash
set -euo pipefail
install -d /opt/quarantine-gateway/scripts /etc/quarantine-gateway
cp /tmp/quarantine-nftables.conf /opt/quarantine-gateway/nftables.conf
cp /tmp/enable-agent-forward.sh /opt/quarantine-gateway/scripts/enable-agent-forward.sh
chmod +x /opt/quarantine-gateway/scripts/enable-agent-forward.sh
if [[ -f /tmp/quarantine-nftables-permissive-forward.inc ]]; then
  install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /opt/quarantine-gateway/nftables-permissive-forward.inc
  if [[ ! -f /etc/quarantine-gateway/nftables-permissive-forward.inc ]]; then
    install -m 0644 /tmp/quarantine-nftables-permissive-forward.inc /etc/quarantine-gateway/nftables-permissive-forward.inc
  fi
fi
if [[ -f /tmp/quarantine-nftables-permissive-nat.inc ]]; then
  install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /opt/quarantine-gateway/nftables-permissive-nat.inc
  if [[ ! -f /etc/quarantine-gateway/nftables-permissive-nat.inc ]]; then
    install -m 0644 /tmp/quarantine-nftables-permissive-nat.inc /etc/quarantine-gateway/nftables-permissive-nat.inc
  fi
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

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
sed -e "s/__WAN__/${WAN_IF}/g" \
    -e "s/__LAN__/${LAN_IF}/g" \
    -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
    -e "s/__LAN_IP__/${LAN_IP}/g" \
    -e "s/__GUEST_IP__/${GUEST_IP}/g" \
    -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
    /opt/quarantine-gateway/nftables.conf >"$rendered"
if grep -q '__PERMISSIVE_' "$rendered" 2>/dev/null; then
  python3 - "$rendered" \
    /etc/quarantine-gateway/nftables-permissive-forward.inc \
    /etc/quarantine-gateway/nftables-permissive-nat.inc <<'PY'
import pathlib, sys
path, wan, nat = sys.argv[1], sys.argv[2], sys.argv[3]
t = pathlib.Path(path).read_text()
w = pathlib.Path(wan).read_text() if pathlib.Path(wan).is_file() else ""
n = pathlib.Path(nat).read_text() if pathlib.Path(nat).is_file() else ""
t = t.replace("__PERMISSIVE_WAN_RULES__\n", w if w.endswith("\n") or w == "" else w + "\n")
t = t.replace("__PERMISSIVE_WAN_RULES__", w)
t = t.replace("__PERMISSIVE_DNS_NAT__\n", n if n.endswith("\n") or n == "" else n + "\n")
t = t.replace("__PERMISSIVE_DNS_NAT__", n)
pathlib.Path(path).write_text(t)
PY
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
EOS
chmod +x /tmp/do-nft-root.sh

if [[ -n "$PASS" ]]; then
  printf '%s\n' "$PASS" | sudo -S -p '' bash /tmp/do-nft-root.sh
else
  sudo -n bash /tmp/do-nft-root.sh
fi
