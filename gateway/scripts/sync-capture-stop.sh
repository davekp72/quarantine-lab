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

PROXY=/var/log/quarantine/proxy
MITM_BIN=/opt/quarantine-gateway/venv/bin/python
EXPORT=/usr/local/lib/quarantine/export-flows-jsonl.py
# Prefer live JSONL; if empty, export from mitm hardcopy (already decrypted).
if [[ ! -s "$PROXY/flows.jsonl" && -s "$PROXY/flows.mitm" && -x "$MITM_BIN" && -f "$EXPORT" ]]; then
  "$MITM_BIN" "$EXPORT" "$PROXY/flows.mitm" "$PROXY/flows.jsonl" 2>/tmp/quarantine-export-flows.err || true
fi
if [[ ! -s "$PROXY/flows-transparent.jsonl" && -s "$PROXY/flows-transparent.mitm" && -x "$MITM_BIN" && -f "$EXPORT" ]]; then
  "$MITM_BIN" "$EXPORT" "$PROXY/flows-transparent.mitm" "$PROXY/flows-transparent.jsonl" 2>>/tmp/quarantine-export-flows.err || true
fi
# Merge transparent into primary flows.jsonl for a single evidence artifact.
if [[ -s "$PROXY/flows-transparent.jsonl" ]]; then
  cat "$PROXY/flows-transparent.jsonl" >>"$PROXY/flows.jsonl" 2>/dev/null || true
fi

tar -C "$PROXY" -cf /tmp/qproxy-bundle.tar \
  access.log errors.log access-transparent.log \
  flows.jsonl flows.mitm flows-transparent.jsonl flows-transparent.mitm \
  2>/dev/null
chmod 644 /tmp/qproxy-bundle.tar 2>/dev/null
printf '%s\n' "$BASE"
exit 0
