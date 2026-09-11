#!/bin/bash
# Create unprivileged service accounts and owned dirs for analysis daemons.
# Safe to run repeatedly from ExecStartPre=+ (as root).
set -euo pipefail

MITM_HOME=/var/lib/quarantine-mitm
FAKENET_HOME=/var/lib/quarantine-fakenet
CAPTURE_HOME=/var/lib/quarantine-capture
LOG=/var/log/quarantine
ETC=/etc/quarantine-gateway

ensure_user() {
  local user="$1" home="$2"
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$home" --create-home \
      --shell /usr/sbin/nologin "$user"
  fi
  install -d -o "$user" -g "$user" -m 0750 "$home"
}

# Parent log dir must be traversable by service users (not 0700 root).
install -d -o root -g root -m 0755 "$LOG"
install -d -o root -g root -m 0755 "$ETC"
install -d -o root -g root -m 0755 /usr/local/lib/quarantine

ensure_user quarantine-mitm "$MITM_HOME"
ensure_user quarantine-fakenet "$FAKENET_HOME"
ensure_user quarantine-capture "$CAPTURE_HOME"

install -d -o quarantine-mitm -g quarantine-mitm -m 0750 "$MITM_HOME" "$LOG/proxy"
install -d -o quarantine-fakenet -g quarantine-fakenet -m 0750 \
  "$FAKENET_HOME" "$LOG/fakenet" "$LOG/fakenet/www" "$LOG/fakenet/certs"
# FakeNet leaf-cert cache under the venv (must be writable by service user).
shopt -s nullglob
for d in /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs; do
  install -d -o quarantine-fakenet -g quarantine-fakenet -m 0750 "$d/temp_certs"
done
shopt -u nullglob
# Also allow writing packaged configs dir if FakeNet creates siblings there.
for d in /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet; do
  if [[ -d "$d" ]]; then
    chgrp -R quarantine-fakenet "$d/configs" 2>/dev/null || true
    chmod -R g+rwX "$d/configs" 2>/dev/null || true
  fi
done
install -d -o quarantine-capture -g quarantine-capture -m 0750 "$CAPTURE_HOME" "$LOG/pcap"

# Fix leftovers from earlier root-owned runs so the service user can append.
chown -R quarantine-mitm:quarantine-mitm "$LOG/proxy" 2>/dev/null || true
chown -R quarantine-fakenet:quarantine-fakenet "$LOG/fakenet" 2>/dev/null || true
chown -R quarantine-capture:quarantine-capture "$LOG/pcap" 2>/dev/null || true

# Prefer existing lab CA (guest already trusts it). Migrate off /root/.mitmproxy.
migrate_mitm_ca() {
  local src="" f dir
  for f in \
    "$MITM_HOME/mitmproxy-ca.pem" \
    /root/.mitmproxy/mitmproxy-ca.pem \
    /home/quarantine/.mitmproxy/mitmproxy-ca.pem; do
    if [[ -f "$f" ]]; then
      src="$f"
      break
    fi
  done
  if [[ -z "$src" ]]; then
    for f in /home/*/.mitmproxy/mitmproxy-ca.pem; do
      if [[ -f "$f" ]]; then
        src="$f"
        break
      fi
    done
  fi
  if [[ -n "$src" && "$src" != "$MITM_HOME/mitmproxy-ca.pem" ]]; then
    cp -a "$src" "$MITM_HOME/mitmproxy-ca.pem"
    dir="$(dirname "$src")"
    for f in mitmproxy-ca-cert.pem mitmproxy-ca-cert.cer mitmproxy-dhparam.pem; do
      if [[ -f "$dir/$f" && ! -f "$MITM_HOME/$f" ]]; then
        cp -a "$dir/$f" "$MITM_HOME/$f"
      fi
    done
  fi
  chown -R quarantine-mitm:quarantine-mitm "$MITM_HOME"
  chmod 750 "$MITM_HOME"
  chmod 640 "$MITM_HOME/mitmproxy-ca.pem" 2>/dev/null || true
  chmod 644 "$MITM_HOME/mitmproxy-ca-cert.pem" 2>/dev/null || true
}

migrate_mitm_ca

# Seed CA if still missing (same cert FakeNet will reuse).
if [[ ! -f "$MITM_HOME/mitmproxy-ca.pem" && -x /opt/quarantine-gateway/venv/bin/mitmdump ]]; then
  timeout 12 /opt/quarantine-gateway/venv/bin/mitmdump \
    --set confdir="$MITM_HOME" \
    --listen-host 127.0.0.1 \
    --listen-port 18080 \
    >/tmp/mitm-ca-seed.log 2>&1 || true
  pkill -f 'mitmdump --listen-host 127.0.0.1 --listen-port 18080' 2>/dev/null || true
  chown -R quarantine-mitm:quarantine-mitm "$MITM_HOME"
fi

# Stage world-readable CA export for guest install / FakeNet.
if [[ -f "$MITM_HOME/mitmproxy-ca-cert.pem" ]]; then
  openssl x509 -in "$MITM_HOME/mitmproxy-ca-cert.pem" -outform DER \
    -out "$ETC/mitmproxy-ca-cert.cer" 2>/dev/null || true
  cp -f "$MITM_HOME/mitmproxy-ca-cert.pem" "$ETC/mitmproxy-ca-cert.pem"
  chmod 644 "$ETC/mitmproxy-ca-cert.cer" "$ETC/mitmproxy-ca-cert.pem" 2>/dev/null || true
fi

# Configs readable by service users; FakeNet CA key group-readable.
chmod 755 "$ETC"
chmod a+r "$ETC/quarantine.pac" "$ETC/block_private.py" 2>/dev/null || true
chmod a+r "$ETC/fakenet.ini" 2>/dev/null || true
if [[ -f "$ETC/fakenet-ca-key.pem" ]]; then
  chgrp quarantine-fakenet "$ETC/fakenet-ca-key.pem" 2>/dev/null || true
  chmod 640 "$ETC/fakenet-ca-key.pem"
fi
chmod 644 "$ETC/fakenet-ca-cert.pem" 2>/dev/null || true
# FakeNet republishes CRL + CDP under /etc; must be group-writable.
for f in mitmproxy-ca.crl fakenet-ca.crl fakenet-cdp.url; do
  touch "$ETC/$f" 2>/dev/null || true
  if [[ -e "$ETC/$f" ]]; then
    chgrp quarantine-fakenet "$ETC/$f" 2>/dev/null || true
    chmod 664 "$ETC/$f" 2>/dev/null || true
  fi
done

# Service users must be able to traverse/exec the shared venvs (often installed 750 root).
fix_opt_tree() {
  local root="$1"
  [[ -d "$root" ]] || return 0
  chmod 755 "$root"
  find "$root" -type d -exec chmod 755 {} +
  find "$root" -type f -executable -exec chmod 755 {} +
  find "$root" -type f ! -executable -exec chmod 644 {} +
}
chmod 755 /opt/quarantine-gateway 2>/dev/null || true
fix_opt_tree /opt/quarantine-gateway/venv
fix_opt_tree /opt/quarantine-gateway/venv-fakenet
# Scripts under /opt used by services
chmod 755 /opt/quarantine-gateway/scripts 2>/dev/null || true
find /opt/quarantine-gateway/scripts -type f -name '*.sh' -exec chmod 755 {} + 2>/dev/null || true
chmod 755 /usr/local/sbin/quarantine-fakenet-explicit-proxy 2>/dev/null || true
chmod 755 /usr/local/sbin/quarantine-capture-start /usr/local/sbin/quarantine-capture-stop 2>/dev/null || true

# Runtime path for capture (optional; primary path is under $LOG/pcap).
install -d -o quarantine-capture -g quarantine-capture -m 0755 /run/quarantine 2>/dev/null || true

# Service users must read resolver config (often left 640 after netplan/repair scripts).
chmod 644 /etc/resolv.conf /etc/hosts /etc/nsswitch.conf 2>/dev/null || true
# Output firewall blocks RFC1918 DNS — drop VBox NAT resolver if present.
if [[ -f /etc/resolv.conf ]] && grep -qE 'nameserver[[:space:]]+10\.' /etc/resolv.conf; then
  tmp=$(mktemp)
  grep -vE 'nameserver[[:space:]]+10\.' /etc/resolv.conf >"$tmp" || true
  if grep -q nameserver "$tmp"; then
    cp "$tmp" /etc/resolv.conf
    chmod 644 /etc/resolv.conf
  fi
  rm -f "$tmp"
fi
# ifaces.env readable by capture
chmod 644 /etc/quarantine-gateway/ifaces.env 2>/dev/null || true

# Ubuntu's usr.bin.tcpdump profile only allows writes under /tmp and /var/log/tcpdump,
# not /var/log/quarantine/pcap. Unload it so tcpdump -w succeeds as quarantine-capture.
if [[ -f /etc/apparmor.d/usr.bin.tcpdump ]]; then
  install -d /etc/apparmor.d/disable
  ln -sfn /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/usr.bin.tcpdump
  if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R /etc/apparmor.d/usr.bin.tcpdump 2>/dev/null || true
  fi
fi

echo "service-users ok mitm=$MITM_HOME fakenet=$FAKENET_HOME capture=$CAPTURE_HOME"
