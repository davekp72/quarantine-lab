#!/bin/bash
set -euo pipefail
# shellcheck disable=SC1091
[[ -f /etc/quarantine-gateway/ifaces.env ]] && source /etc/quarantine-gateway/ifaces.env
# ifaces.env uses LAN=; accept LAN_IF= too
LAN_IF="${LAN_IF:-${LAN:-}}"
if [[ -z "$LAN_IF" || ! -d "/sys/class/net/$LAN_IF" ]]; then
  # Prefer non-WAN interface with an address, else second non-lo iface
  for cand in /sys/class/net/*; do
    name=$(basename "$cand")
    [[ "$name" == "lo" ]] && continue
    [[ -n "${WAN:-}" && "$name" == "$WAN" ]] && continue
    if ip -4 addr show dev "$name" 2>/dev/null | grep -q ' inet '; then
      LAN_IF="$name"
      break
    fi
  done
fi
if [[ -z "$LAN_IF" ]]; then
  mapfile -t ifs < <(ls /sys/class/net | grep -v '^lo$' | sort)
  if [[ ${#ifs[@]} -ge 2 ]]; then LAN_IF="${ifs[1]}"; else LAN_IF="${ifs[0]:-eth1}"; fi
fi
OUTDIR=/var/log/quarantine/pcap
mkdir -p "$OUTDIR"
STAMP=$(date -u +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/gateway-lan-$STAMP.pcap"
echo "$PCAP" >/var/run/quarantine-capture.path
# Ensure path exists immediately (tcpdump also creates/truncates on -w)
: >"$PCAP"
echo "capturing on $LAN_IF -> $PCAP"
# Capture all LAN frames (guest↔gateway): DNS, ICMP, TCP, UDP
exec /usr/bin/tcpdump -i "$LAN_IF" -n -s 0 -U -w "$PCAP"
