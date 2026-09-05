#!/bin/bash
# Forward host agent TCP to the Windows lab guest on the quarantine LAN.
# Host:127.0.0.1:PORT → VBox NAT PF on this gateway → DNAT → GUEST_IP:PORT
set -euo pipefail

GUEST_IP="${1:-10.66.0.15}"
AGENT_PORT="${2:-9443}"
LAN_IP="${3:-10.66.0.1}"
LAN_CIDR="${4:-10.66.0.0/24}"

if [[ -f /etc/quarantine-gateway/ifaces.env ]]; then
  # shellcheck disable=SC1091
  source /etc/quarantine-gateway/ifaces.env
fi
WAN_IF="${WAN_IF:-}"
LAN_IF="${LAN_IF:-}"

if [[ -z "${WAN_IF}" || -z "${LAN_IF}" ]]; then
  mapfile -t ifs < <(ls /sys/class/net | grep -v '^lo$' | sort)
  WAN_IF="${WAN_IF:-${ifs[0]:-eth0}}"
  LAN_IF="${LAN_IF:-${ifs[1]:-${WAN_IF}}}"
fi

TEMPLATE=""
for cand in /opt/quarantine-gateway/nftables.conf /tmp/quarantine-nftables.conf; do
  if [[ -f "$cand" ]]; then
    TEMPLATE="$cand"
    break
  fi
done
if [[ -z "$TEMPLATE" ]]; then
  echo "nftables.conf template not found" >&2
  exit 1
fi

sed -e "s/__WAN__/${WAN_IF}/g" \
    -e "s/__LAN__/${LAN_IF}/g" \
    -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
    -e "s/__LAN_IP__/${LAN_IP}/g" \
    -e "s/__GUEST_IP__/${GUEST_IP}/g" \
    -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
    "$TEMPLATE" >/etc/nftables.conf

nft -f /etc/nftables.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "agent-forward ${WAN_IF}:${AGENT_PORT} -> ${GUEST_IP}:${AGENT_PORT} snat ${LAN_IP}"
