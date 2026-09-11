#!/bin/bash
# Forward host agent TCP to the Windows lab guest on the quarantine LAN.
# Host:127.0.0.1:PORT → VBox NAT PF on this gateway → DNAT → GUEST_IP:PORT
set -euo pipefail

GUEST_IP="${1:-10.66.0.15}"
AGENT_PORT="${2:-9443}"
LAN_IP="${3:-10.66.0.1}"
LAN_CIDR="${4:-10.66.0.0/24}"

OPT=/opt/quarantine-gateway
ETC=/etc/quarantine-gateway

if [[ -f "$ETC/ifaces.env" ]]; then
  # shellcheck disable=SC1091
  source "$ETC/ifaces.env"
fi
WAN_IF="${WAN_IF:-}"
LAN_IF="${LAN_IF:-}"

if [[ -z "${WAN_IF}" || -z "${LAN_IF}" ]]; then
  mapfile -t ifs < <(ls /sys/class/net | grep -v '^lo$' | sort)
  WAN_IF="${WAN_IF:-${ifs[0]:-eth0}}"
  LAN_IF="${LAN_IF:-${ifs[1]:-${WAN_IF}}}"
fi

current_mode() {
  if [[ -f "$ETC/traffic-mode" ]]; then
    tr -d '[:space:]' <"$ETC/traffic-mode" | tr '[:upper:]' '[:lower:]'
  else
    echo fakenet
  fi
}

first_existing() {
  local cand
  for cand in "$@"; do
    if [[ -f "$cand" ]]; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

pick_template() {
  local mode
  mode="$(current_mode)"
  case "$mode" in
    permissive|mitm|internet)
      first_existing "$OPT/nftables.conf" /tmp/quarantine-nftables.conf
      ;;
    *)
      first_existing \
        "$OPT/nftables-fakenet.conf" \
        /tmp/quarantine-nftables-fakenet.conf \
        "$OPT/nftables.conf" \
        /tmp/quarantine-nftables.conf
      ;;
  esac
}

inject_nft_snippets() {
  local rendered="$1"
  local wan_rules nat_rules out_rules injector
  wan_rules="$(first_existing "$ETC/nftables-permissive-forward.inc" "$OPT/nftables-permissive-forward.inc" || true)"
  nat_rules="$(first_existing "$ETC/nftables-permissive-nat.inc" "$OPT/nftables-permissive-nat.inc" || true)"
  out_rules="$(first_existing "$ETC/nftables-permissive-output.inc" "$OPT/nftables-permissive-output.inc" || true)"
  injector="$(first_existing "$OPT/scripts/nft-inject-permissive.py" /usr/local/lib/quarantine/nft-inject-permissive.py || true)"
  if [[ -z "$injector" ]]; then
    echo "nft-inject-permissive.py missing" >&2
    return 1
  fi
  python3 "$injector" "$rendered" "${wan_rules:-}" "${nat_rules:-}" "${out_rules:-}"
}

TEMPLATE="$(pick_template || true)"
if [[ -z "$TEMPLATE" ]]; then
  echo "nftables.conf template not found" >&2
  exit 1
fi

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
  inject_nft_snippets "$rendered"
  sed -i -e "s/__WAN__/${WAN_IF}/g" -e "s/__LAN__/${LAN_IF}/g" "$rendered"
fi
if grep -q '__PERMISSIVE_' "$rendered" 2>/dev/null; then
  echo "nftables placeholders remain after render:" >&2
  grep -n '__PERMISSIVE_' "$rendered" >&2 || true
  exit 1
fi
cp "$rendered" /etc/nftables.conf
nft -f /etc/nftables.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "agent-forward ${WAN_IF}:${AGENT_PORT} -> ${GUEST_IP}:${AGENT_PORT} snat ${LAN_IP} (template=$(basename "$TEMPLATE") mode=$(current_mode))"
