#!/bin/bash
# Stop tcpdump, stage PCAP + proxy logs for host copyfrom.
# Prints the staged PCAP basename on stdout (may be empty).
# Do NOT call "systemctl stop" from ExecStop scripts — that deadlocks.
set +e
HINT="${1:-}"
PCAP=""
if [ -n "$HINT" ] && [ -f "$HINT" ]; then PCAP="$HINT"; fi
if [ -z "$PCAP" ] && [ -f /var/run/quarantine-capture.path ]; then
  PCAP=$(cat /var/run/quarantine-capture.path 2>/dev/null)
fi
if [ -z "$PCAP" ] || [ ! -f "$PCAP" ]; then
  PCAP=$(ls -1t /var/log/quarantine/pcap/*.pcap 2>/dev/null | head -1)
fi

pkill -TERM -x tcpdump 2>/dev/null
pkill -TERM -f /usr/bin/tcpdump 2>/dev/null
sleep 0.2
pkill -KILL -x tcpdump 2>/dev/null
pkill -KILL -f /usr/bin/tcpdump 2>/dev/null
# kill unit processes without running ExecStop
systemctl kill -s SIGKILL quarantine-capture 2>/dev/null
systemctl reset-failed quarantine-capture 2>/dev/null

BASE=""
if [ -n "$PCAP" ] && [ -f "$PCAP" ]; then
  BASE=$(basename "$PCAP")
  cp -a "$PCAP" "/tmp/$BASE"
  chmod 644 "/tmp/$BASE"
fi
tar -C /var/log/quarantine/proxy -cf /tmp/qproxy-bundle.tar \
  access.log errors.log access-transparent.log 2>/dev/null
chmod 644 /tmp/qproxy-bundle.tar 2>/dev/null
printf '%s\n' "$BASE"
exit 0
