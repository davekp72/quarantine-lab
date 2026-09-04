#!/bin/bash
set -euo pipefail
pkill -f 'tcpdump -i' 2>/dev/null || true
if [[ -f /var/run/quarantine-capture.path ]]; then
  echo "PCAP: $(cat /var/run/quarantine-capture.path)"
fi
systemctl stop quarantine-capture 2>/dev/null || true
exit 0
