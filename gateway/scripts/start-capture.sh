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
  mapfile -t ifs < <(ls /sys/class/net 2>/dev/null | grep -v '^lo$' | sort || true)
  if [[ ${#ifs[@]} -ge 2 ]]; then LAN_IF="${ifs[1]}"; else LAN_IF="${ifs[0]:-eth1}"; fi
fi
if [[ -z "$LAN_IF" || ! -d "/sys/class/net/$LAN_IF" ]]; then
  echo "capture: LAN interface '${LAN_IF:-}' not found" >&2
  ls -1 /sys/class/net >&2 || true
  exit 1
fi
if [[ ! -x /usr/bin/tcpdump ]]; then
  echo "capture: /usr/bin/tcpdump missing" >&2
  exit 1
fi
OUTDIR=/var/log/quarantine/pcap
# Parent dirs are created as root by quarantine-ensure-service-users (ExecStartPre=+).
STAMP=$(date -u +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/gateway-lan-$STAMP.pcap"
PATHFILE="$OUTDIR/current.path"
echo "$PCAP" >"$PATHFILE"
# Host poll historically read /var/run/quarantine-capture.path (symlink to /run).
# Write every location the stop/sync/host paths still consult.
install -d -m 0755 /run/quarantine 2>/dev/null || true
for marker in \
  "$PATHFILE" \
  /run/quarantine/capture.path \
  /run/quarantine-capture.path \
  /var/run/quarantine-capture.path
do
  echo "$PCAP" >"$marker" 2>/dev/null || true
done
# Ensure path exists immediately (tcpdump also creates/truncates on -w)
: >"$PCAP"
echo "capturing on $LAN_IF -> $PCAP"
# Full-frame LAN capture (guest↔gateway): DNS, ICMP, TCP, UDP, dropped WAN attempts, FakeNet.
# Ubuntu's usr.bin.tcpdump AppArmor profile is unloaded by ensure-service-users /
# the unit sets AppArmorProfile=unconfined so -w under $OUTDIR is allowed.
exec /usr/bin/tcpdump -i "$LAN_IF" -n -s 0 -U -w "$PCAP"
