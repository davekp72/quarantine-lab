#!/bin/bash
set -euo pipefail
echo "=== Quarantine Gateway Status ==="
[[ -f /etc/quarantine-gateway/ifaces.env ]] && cat /etc/quarantine-gateway/ifaces.env
MODE=permissive
[[ -f /etc/quarantine-gateway/traffic-mode ]] && MODE=$(tr -d '[:space:]' </etc/quarantine-gateway/traffic-mode)
echo "traffic-mode=$MODE"
echo "ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo ?)"
echo -n "units: "
systemctl is-active dnsmasq nftables quarantine-mitm-explicit quarantine-mitm-transparent quarantine-capture quarantine-fakenet 2>/dev/null | paste -sd' ' - || true
echo "--- listeners ---"
ss -lntup 2>/dev/null | grep -E ':53|:80 |:443 |:25 |:1337|:8080|:8082' || netstat -lntup 2>/dev/null | grep -E ':53|:80 |:443 |:25 |:1337|:8080|:8082' || true
echo "--- latest pcap ---"
ls -lt /var/log/quarantine/pcap 2>/dev/null | head -5 || true
if [[ -d /var/log/quarantine/fakenet ]]; then
  echo "--- fakenet log ---"
  ls -lt /var/log/quarantine/fakenet 2>/dev/null | head -5 || true
  if [[ -f /var/log/quarantine/fakenet/fakenet.log ]]; then
    echo "--- fakenet.log (tail) ---"
    tail -n 40 /var/log/quarantine/fakenet/fakenet.log || true
  fi
fi
echo "--- dns bind ---"
ss -ulnp 2>/dev/null | grep ':53' || true
ss -tlnp 2>/dev/null | grep ':53' || true
echo "OK"
