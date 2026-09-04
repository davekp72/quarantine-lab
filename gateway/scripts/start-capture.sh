#!/bin/bash
set -euo pipefail
# shellcheck disable=SC1091
[[ -f /etc/quarantine-gateway/ifaces.env ]] && source /etc/quarantine-gateway/ifaces.env
LAN_IF="${LAN_IF:-eth1}"
OUTDIR=/var/log/quarantine/pcap
mkdir -p "$OUTDIR"
STAMP=$(date -u +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/gateway-lan-$STAMP.pcap"
echo "$PCAP" >/var/run/quarantine-capture.path
# Capture all LAN frames (guest↔gateway): DNS, ICMP, TCP, UDP
exec /usr/bin/tcpdump -i "$LAN_IF" -n -s 0 -U -w "$PCAP"
