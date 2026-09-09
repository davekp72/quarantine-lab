#!/bin/bash
# Install block_private.py and restart mitm services. Arg1 = sudo password.
set -euo pipefail
PASS="${1:-}"
cat >/tmp/do-mitm-update.sh <<'EOS'
#!/bin/bash
set -euo pipefail
install -d /opt/quarantine-gateway/mitm
cp /tmp/block_private.py /opt/quarantine-gateway/mitm/block_private.py
if [[ -d /opt/quarantine-gateway-src/mitm ]]; then
  cp /tmp/block_private.py /opt/quarantine-gateway-src/mitm/block_private.py
fi
# Prefer path used by systemd unit WorkingDirectory if present
for d in /opt/quarantine-gateway /opt/quarantine-gateway-src; do
  if [[ -f "$d/mitm/block_private.py" ]]; then
    echo "updated $d/mitm/block_private.py"
  fi
done
systemctl restart quarantine-mitm-explicit quarantine-mitm-transparent
systemctl is-active quarantine-mitm-explicit quarantine-mitm-transparent
echo '=== forward chain ==='
nft list chain inet filter forward
EOS
chmod +x /tmp/do-mitm-update.sh
if [[ -n "$PASS" ]]; then
  printf '%s\n' "$PASS" | sudo -S -p '' bash /tmp/do-mitm-update.sh
else
  sudo -n bash /tmp/do-mitm-update.sh
fi
