#!/bin/bash
set -euo pipefail
echo "=== Quarantine Gateway Status ==="
[[ -f /etc/quarantine-gateway/ifaces.env ]] && cat /etc/quarantine-gateway/ifaces.env
echo "ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo ?)"
systemctl is-active dnsmasq nftables quarantine-mitm-explicit quarantine-mitm-transparent quarantine-capture 2>/dev/null | paste - - - - - || true
echo "--- listeners ---"
ss -lntup 2>/dev/null | grep -E ':53|:8080|:8082' || netstat -lntup 2>/dev/null | grep -E ':53|:8080|:8082' || true
echo "--- latest pcap ---"
ls -lt /var/log/quarantine/pcap 2>/dev/null | head -5 || true
echo "OK"
