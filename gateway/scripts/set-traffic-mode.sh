#!/bin/bash
# Switch gateway traffic path: permissive (MITM+WAN) <-> fakenet (sinkhole).
# Usage: quarantine-set-traffic-mode permissive|fakenet|status|boot
set -euo pipefail

MODE="${1:-status}"
OPT=/opt/quarantine-gateway
ETC=/etc/quarantine-gateway
MODE_FILE="$ETC/traffic-mode"
LOG=/var/log/quarantine

LAN_CIDR="${QUARANTINE_LAN_CIDR:-10.66.0.0/24}"
GUEST_IP="${QUARANTINE_GUEST_IP:-10.66.0.15}"
AGENT_PORT="${QUARANTINE_AGENT_PORT:-9443}"

if [[ -f "$ETC/ifaces.env" ]]; then
  # shellcheck disable=SC1091
  source "$ETC/ifaces.env"
fi
WAN_IF="${WAN:-${WAN_IF:-enp0s3}}"
LAN_IF="${LAN:-${LAN_IF:-enp0s8}}"
LAN_IP="${LAN_IP:-10.66.0.1}"

mkdir -p "$ETC" "$LOG/fakenet" "$LOG/pcap" "$LOG/proxy"

current_mode() {
  if [[ -f "$MODE_FILE" ]]; then
    tr -d '[:space:]' <"$MODE_FILE" | tr '[:upper:]' '[:lower:]'
  else
    echo permissive
  fi
}

apply_nft() {
  local template="$1"
  if [[ ! -f "$template" ]]; then
    echo "missing nftables template: $template" >&2
    return 1
  fi
  sed -e "s/__WAN__/${WAN_IF}/g" \
      -e "s/__LAN__/${LAN_IF}/g" \
      -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
      -e "s/__LAN_IP__/${LAN_IP}/g" \
      -e "s/__GUEST_IP__/${GUEST_IP}/g" \
      -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
      "$template" >/etc/nftables.conf
  nft -f /etc/nftables.conf
}

render_fakenet_ini() {
  local src="$OPT/fakenet/quarantine.ini"
  if [[ ! -f "$src" ]]; then
    echo "missing FakeNet config: $src (re-run gateway provision)" >&2
    return 1
  fi
  sed -e "s/__LAN__/${LAN_IF}/g" -e "s/__LAN_IP__/${LAN_IP}/g" \
    "$src" >"$ETC/fakenet.ini"
}

# FakeNet uses iptables NFQUEUE. LinuxFlushIptables=No so leftovers can linger.
cleanup_nfqueue() {
  if ! command -v iptables >/dev/null 2>&1; then
    return 0
  fi
  iptables -t mangle -F 2>/dev/null || true
  iptables -t raw -F 2>/dev/null || true
  # Remove any remaining NFQUEUE jumps without flushing filter (nftables-nft).
  while iptables -t mangle -D PREROUTING -j NFQUEUE 2>/dev/null; do :; done
  while iptables -t filter -D INPUT -j NFQUEUE 2>/dev/null; do :; done
  while iptables -t filter -D FORWARD -j NFQUEUE 2>/dev/null; do :; done
}

require_fakenet() {
  if [[ ! -x /opt/quarantine-gateway/venv-fakenet/bin/python ]]; then
    echo "FakeNet venv missing. Re-run: .\\quarantine-vm.ps1 gateway provision" >&2
    return 1
  fi
  if ! /opt/quarantine-gateway/venv-fakenet/bin/python -c 'import fakenet' 2>/dev/null; then
    echo "FakeNet-NG is not installed in venv-fakenet. Re-run gateway provision." >&2
    return 1
  fi
}

mode_fakenet() {
  require_fakenet || return 1
  render_fakenet_ini || return 1
  # Disable MITM/dnsmasq so they cannot start after FakeNet on reboot
  # (systemd Conflicts would otherwise stop FakeNet).
  systemctl disable --now quarantine-mitm-explicit quarantine-mitm-transparent dnsmasq 2>/dev/null || true
  systemctl reset-failed quarantine-fakenet 2>/dev/null || true
  # Stop FakeNet before nft flush — otherwise flush ruleset wipes NFQUEUE.
  systemctl stop quarantine-fakenet 2>/dev/null || true
  apply_nft "$OPT/nftables-fakenet.conf" || return 1
  systemctl start quarantine-fakenet || return 1
  if ! systemctl is-active --quiet quarantine-fakenet; then
    echo "quarantine-fakenet failed to start" >&2
    journalctl -u quarantine-fakenet -n 40 --no-pager >&2 || true
    return 1
  fi
  echo fakenet >"$MODE_FILE"
  echo "traffic-mode=fakenet (sinkhole; no WAN for lab guest)"
}

mode_permissive() {
  systemctl disable --now quarantine-fakenet 2>/dev/null || true
  cleanup_nfqueue
  apply_nft "$OPT/nftables.conf"
  systemctl enable --now dnsmasq 2>/dev/null || true
  systemctl enable --now quarantine-mitm-explicit quarantine-mitm-transparent 2>/dev/null || true
  echo permissive >"$MODE_FILE"
  echo "traffic-mode=permissive (internet + MITM + PCAP)"
}

case "$MODE" in
  status|"")
    echo "traffic-mode=$(current_mode)"
    systemctl is-active quarantine-fakenet 2>/dev/null | awk '{print "fakenet="$1}'
    systemctl is-active dnsmasq quarantine-mitm-transparent 2>/dev/null | paste -d= - - | sed 's/^/svc /' || true
    ;;
  boot)
    case "$(current_mode)" in
      fakenet)
        if ! mode_fakenet; then
          echo "FakeNet unavailable on boot; falling back to permissive" >&2
          mode_permissive
        fi
        ;;
      *) mode_permissive ;;
    esac
    ;;
  fakenet|sinkhole)
    mode_fakenet
    ;;
  permissive|mitm|internet)
    mode_permissive
    ;;
  *)
    echo "Usage: $0 permissive|fakenet|status|boot" >&2
    exit 2
    ;;
esac
