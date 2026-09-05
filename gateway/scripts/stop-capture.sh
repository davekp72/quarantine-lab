#!/bin/bash
# Kill tcpdump only. Do NOT call "systemctl stop" here — this script is also
# ExecStop for quarantine-capture.service, and systemctl stop from ExecStop deadlocks
# until TimeoutStopSec (often 90s).
set +e
pkill -TERM -x tcpdump 2>/dev/null
pkill -TERM -f '/usr/bin/tcpdump -i' 2>/dev/null
sleep 0.15
pkill -KILL -x tcpdump 2>/dev/null
pkill -KILL -f '/usr/bin/tcpdump -i' 2>/dev/null
if [[ -f /var/run/quarantine-capture.path ]]; then
  echo "PCAP: $(cat /var/run/quarantine-capture.path)"
fi
exit 0
