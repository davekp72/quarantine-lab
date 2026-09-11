#!/bin/bash
# Stage mitmproxy CA where VirtualBox guestcontrol (user quarantine) can read it.
set -euo pipefail
mkdir -p /etc/quarantine-gateway /tmp /var/log/quarantine/proxy

if [[ -x /usr/local/sbin/quarantine-ensure-service-users ]]; then
  /usr/local/sbin/quarantine-ensure-service-users || true
fi

SRC=""
for c in \
  /var/lib/quarantine-mitm/mitmproxy-ca-cert.pem \
  /var/lib/quarantine-mitm/mitmproxy-ca-cert.cer \
  /etc/quarantine-gateway/mitmproxy-ca-cert.cer \
  /etc/quarantine-gateway/mitmproxy-ca-cert.pem \
  /root/.mitmproxy/mitmproxy-ca-cert.pem \
  /root/.mitmproxy/mitmproxy-ca-cert.cer
do
  if [[ -f "$c" ]]; then
    SRC="$c"
    break
  fi
done

if [[ -z "$SRC" ]]; then
  systemctl restart quarantine-mitm-explicit || true
  sleep 3
  for c in /var/lib/quarantine-mitm/mitmproxy-ca-cert.pem /root/.mitmproxy/mitmproxy-ca-cert.pem; do
    if [[ -f "$c" ]]; then
      SRC="$c"
      break
    fi
  done
fi

if [[ -z "$SRC" || ! -f "$SRC" ]]; then
  echo "mitmproxy CA not found under /var/lib/quarantine-mitm or /etc/quarantine-gateway" >&2
  ls -la /var/lib/quarantine-mitm /root/.mitmproxy 2>/dev/null || true
  exit 1
fi

case "$SRC" in
  *.pem)
    openssl x509 -in "$SRC" -outform DER -out /tmp/quarantine-ca.cer 2>/dev/null \
      || cp "$SRC" /tmp/quarantine-ca.cer
    ;;
  *)
    cp "$SRC" /tmp/quarantine-ca.cer
    ;;
esac

cp -f /tmp/quarantine-ca.cer /etc/quarantine-gateway/mitmproxy-ca-cert.cer
if [[ "$SRC" == *.pem ]]; then
  cp -f "$SRC" /etc/quarantine-gateway/mitmproxy-ca-cert.pem
  cp -f "$SRC" /var/log/quarantine/proxy/mitmproxy-ca-cert.pem 2>/dev/null || true
fi
chmod 644 /tmp/quarantine-ca.cer /etc/quarantine-gateway/mitmproxy-ca-cert.cer
# Allow guestcontrol user to copyfrom
if id quarantine >/dev/null 2>&1; then
  chown quarantine:quarantine /tmp/quarantine-ca.cer
fi
echo "staged $SRC -> /tmp/quarantine-ca.cer"
