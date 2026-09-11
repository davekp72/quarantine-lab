#!/bin/bash
set -euo pipefail
# shellcheck disable=SC1091
if [[ -r /etc/quarantine-gateway/ifaces.env ]]; then
  source /etc/quarantine-gateway/ifaces.env
fi
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
# Parent dirs are created as root by quarantine-ensure-service-users (ExecStartPre=+).
STAMP=$(date -u +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/gateway-lan-$STAMP.pcap"
PATHFILE="$OUTDIR/current.path"
echo "$PCAP" >"$PATHFILE"
if [[ -d /run/quarantine ]]; then
  echo "$PCAP" >/run/quarantine/capture.path 2>/dev/null || true
fi
# Ensure path exists immediately (tcpdump also creates/truncates on -w)
: >"$PCAP"
echo "capturing on $LAN_IF -> $PCAP"
# Full-frame LAN capture (guest↔gateway): DNS, ICMP, TCP, UDP, dropped WAN attempts, FakeNet.
exec /usr/bin/tcpdump -i "$LAN_IF" -n -s 0 -U -w "$PCAP"
