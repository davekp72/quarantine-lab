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

# Use the same mitmproxy CA the Windows guest already trusts (permissive MITM CA).
ensure_fakenet_ca() {
  local combined=""
  local cert_out="$ETC/fakenet-ca-cert.pem"
  local key_out="$ETC/fakenet-ca-key.pem"
  local cer_out="$ETC/mitmproxy-ca-cert.cer"
  local www=/var/log/quarantine/fakenet/www
  local pybin=/opt/quarantine-gateway/venv-fakenet/bin/python
  local c pkg_www year
  for c in /root/.mitmproxy/mitmproxy-ca.pem \
           /home/quarantine/.mitmproxy/mitmproxy-ca.pem \
           /home/*/.mitmproxy/mitmproxy-ca.pem; do
    if [[ -f "$c" ]]; then
      combined="$c"
      break
    fi
  done
  if [[ -z "$combined" ]]; then
    echo "ERROR: mitmproxy CA not found under /root/.mitmproxy (run permissive mode once or gateway export-ca)." >&2
    return 1
  fi
  mkdir -p "$ETC" /var/log/quarantine/fakenet/certs "$www"
  # mitmproxy-ca.pem is key+cert; split for FakeNet Static_CA. Do not modify the source.
  if ! openssl pkey -in "$combined" -out "$key_out" 2>/dev/null; then
    if ! openssl rsa -in "$combined" -out "$key_out" 2>/dev/null; then
      echo "ERROR: could not extract FakeNet CA private key from $combined" >&2
      return 1
    fi
  fi
  if ! openssl x509 -in "$combined" -out "$cert_out" 2>/dev/null; then
    echo "ERROR: could not extract FakeNet CA cert from $combined" >&2
    return 1
  fi
  chmod 600 "$key_out"
  chmod 644 "$cert_out"
  openssl x509 -in "$cert_out" -outform DER -out "$cer_out" 2>/dev/null || cp -f "$cert_out" "$cer_out"
  chmod 644 "$cer_out"
  # Empty CRL file so leaf-cert caching in ssl_utils does not regenerate endlessly.
  : >"$ETC/fakenet-ca.crl"
  cp -f "$ETC/fakenet-ca.crl" /var/log/quarantine/fakenet/certs/ca.crl 2>/dev/null || true

  # Seed FakeNet HTTP webroot with package defaults + the same CA (guest HTTP install).
  if [[ -x "$pybin" ]]; then
    pkg_www="$("$pybin" -c 'import fakenet, pathlib; print(pathlib.Path(fakenet.__file__).resolve().parent / "defaultFiles")' 2>/dev/null || true)"
    if [[ -n "$pkg_www" && -d "$pkg_www" ]]; then
      cp -a "$pkg_www/." "$www/" 2>/dev/null || true
      cp -f "$cer_out" "$pkg_www/mitmproxy-ca-cert.cer"
      cp -f "$cert_out" "$pkg_www/mitmproxy-ca-cert.pem"
    fi
  fi
  cp -f "$cer_out" "$www/mitmproxy-ca-cert.cer"
  cp -f "$cert_out" "$www/mitmproxy-ca-cert.pem"
  chmod 644 "$www/mitmproxy-ca-cert.cer" "$www/mitmproxy-ca-cert.pem"
  echo "http://${LAN_IP}/mitmproxy-ca.crl" >"$ETC/fakenet-cdp.url"

  echo "FakeNet HTTPS will use mitmproxy CA: $cert_out (from $combined)"
  echo "FakeNet CA subject/dates:"
  openssl x509 -in "$cert_out" -noout -subject -issuer -dates 2>/dev/null || true
  year="$(date -u +%Y 2>/dev/null || echo 0)"
  if [[ "$year" -lt 2024 || "$year" -gt 2038 ]]; then
    echo "WARNING: gateway clock is $(date -u 2>/dev/null). FakeNet leaves will use the CA validity window (Windows guest clock still applies)."
  fi
}

# Apply cryptography-based SSL patch so HTTPS UseSSL works on modern pyOpenSSL.
patch_fakenet_ssl() {
  local patch_src="$OPT/fakenet/ssl_utils_init.py"
  local pybin=/opt/quarantine-gateway/venv-fakenet/bin/python
  local ssl_dst
  if [[ ! -f "$patch_src" || ! -x "$pybin" ]]; then
    return 0
  fi
  ssl_dst="$("$pybin" -c 'import fakenet.listeners.ssl_utils as s, pathlib; print(pathlib.Path(s.__file__).resolve())' 2>/dev/null || true)"
  if [[ -z "$ssl_dst" || ! -f "$ssl_dst" ]]; then
    echo "WARNING: could not locate FakeNet ssl_utils to patch" >&2
    return 0
  fi
  install -m 0644 "$patch_src" "$ssl_dst"
  rm -rf "$(dirname "$ssl_dst")/__pycache__" \
    /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs/temp_certs \
    2>/dev/null || true
}

# Empty CRL signed by the lab MITM CA, served at the leaf CDP URL.
publish_fakenet_crl() {
  local pybin=/opt/quarantine-gateway/venv-fakenet/bin/python
  local www=/var/log/quarantine/fakenet/www
  local pkg_www
  echo "http://${LAN_IP}/mitmproxy-ca.crl" >"$ETC/fakenet-cdp.url"
  mkdir -p "$www" /var/log/quarantine/fakenet/certs
  if [[ ! -x "$pybin" ]]; then
    echo "WARNING: cannot publish FakeNet CRL (venv python missing)" >&2
    return 0
  fi
  if ! "$pybin" - <<PY
from fakenet.listeners.ssl_utils import publish_mitm_crl
written = publish_mitm_crl(
    "/etc/quarantine-gateway/fakenet-ca-cert.pem",
    "/etc/quarantine-gateway/fakenet-ca-key.pem",
    [
        "/var/log/quarantine/fakenet/www/mitmproxy-ca.crl",
        "/var/log/quarantine/fakenet/www/ca.crl",
        "/etc/quarantine-gateway/mitmproxy-ca.crl",
        "/var/log/quarantine/fakenet/certs/ca.crl",
    ],
)
print("FakeNet CRL:", ", ".join(written))
if not written:
    raise SystemExit("CRL publish failed")
PY
  then
    echo "WARNING: FakeNet CRL publish failed" >&2
    return 0
  fi
  pkg_www="$("$pybin" -c 'import fakenet, pathlib; print(pathlib.Path(fakenet.__file__).resolve().parent / "defaultFiles")' 2>/dev/null || true)"
  if [[ -n "$pkg_www" && -d "$pkg_www" && -f "$www/mitmproxy-ca.crl" ]]; then
    cp -f "$www/mitmproxy-ca.crl" "$pkg_www/mitmproxy-ca.crl" 2>/dev/null || true
  fi
  chmod 644 "$www/mitmproxy-ca.crl" "$www/ca.crl" 2>/dev/null || true
}

# FakeNet uses iptables NFQUEUE. LinuxFlushIptables=No so leftovers can linger.
cleanup_nfqueue() {
  if ! command -v iptables >/dev/null 2>&1; then
    return 0
  fi
  iptables -t mangle -F 2>/dev/null || true
  iptables -t raw -F 2>/dev/null || true
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

# Guest DNS is the gateway LAN IP. FakeNet must own UDP/TCP 53 there.
free_dns_port() {
  systemctl stop dnsmasq 2>/dev/null || true
  mkdir -p /etc/systemd/resolved.conf.d
  cat >/etc/systemd/resolved.conf.d/disable-stub.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved 2>/dev/null || true
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    # dnsmasq/named must be gone from :53
    if ss -ulnp 2>/dev/null | grep -E ':53\b' | grep -qE 'dnsmasq|named|unbound'; then
      sleep 0.5
      continue
    fi
    return 0
  done
  echo "WARNING: UDP/53 still occupied:" >&2
  ss -ulnp 2>/dev/null | grep ':53' >&2 || true
}

dns_listener_up() {
  ss -ulnp 2>/dev/null | grep -E ':53\b' | grep -qiE 'python|fakenet'
}

mode_fakenet() {
  require_fakenet || return 1
  ensure_fakenet_ca || return 1
  render_fakenet_ini || return 1
  patch_fakenet_ssl
  # Disable MITM/dnsmasq so they cannot start after FakeNet on reboot
  # (systemd Conflicts would otherwise stop FakeNet).
  systemctl disable --now quarantine-mitm-explicit quarantine-mitm-transparent dnsmasq 2>/dev/null || true
  systemctl reset-failed quarantine-fakenet 2>/dev/null || true
  systemctl stop quarantine-fakenet 2>/dev/null || true
  free_dns_port
  : >"$LOG/fakenet/fakenet.log" 2>/dev/null || true
  # Drop cached FakeNet leaves (old CDP / 1970-dated / CA-as-leaf) so they are re-signed.
  rm -rf /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs/temp_certs \
    /var/log/quarantine/fakenet/certs
  mkdir -p /var/log/quarantine/fakenet/certs
  publish_fakenet_crl
  apply_nft "$OPT/nftables-fakenet.conf" || return 1
  systemctl start quarantine-fakenet || return 1
  if ! systemctl is-active --quiet quarantine-fakenet; then
    echo "quarantine-fakenet failed to start" >&2
    journalctl -u quarantine-fakenet -n 40 --no-pager >&2 || true
    return 1
  fi
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if dns_listener_up; then
      break
    fi
    sleep 1
  done
  if ! dns_listener_up; then
    echo "FakeNet is running but UDP/53 is not listening — DNS from the lab guest will time out." >&2
    echo "--- fakenet.log ---" >&2
    tail -n 50 "$LOG/fakenet/fakenet.log" >&2 || true
    journalctl -u quarantine-fakenet -n 40 --no-pager >&2 || true
    return 1
  fi
  # Confirm TLS listener came up (UseSSL on :443)
  if ! ss -tlnp 2>/dev/null | grep -E ':443\b' | grep -qiE 'python|fakenet'; then
    echo "WARNING: FakeNet TCP/443 is not listening (HTTPS may be down)" >&2
    tail -n 30 "$LOG/fakenet/fakenet.log" >&2 || true
  fi
  if command -v dig >/dev/null 2>&1; then
    dig +time=2 +tries=1 @"$LAN_IP" fakenet-check.local A >/dev/null 2>&1 || true
  fi
  if command -v openssl >/dev/null 2>&1; then
    echo "FakeNet TLS leaf for SNI google.com:"
    echo | openssl s_client -connect "${LAN_IP}:443" -servername google.com 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates -ext crlDistributionPoints 2>/dev/null || true
    echo "FakeNet CRL:"
    openssl crl -inform DER -in /var/log/quarantine/fakenet/www/mitmproxy-ca.crl -noout -issuer -lastupdate -nextupdate 2>/dev/null || true
  fi
  echo fakenet >"$MODE_FILE"
  echo "traffic-mode=fakenet (sinkhole; DNS/HTTP/HTTPS on ${LAN_IP} with mitm CA; no WAN)"
  echo "Guest CA (HTTP): http://${LAN_IP}/mitmproxy-ca-cert.cer"
  echo "Guest CRL (HTTP): http://${LAN_IP}/mitmproxy-ca.crl"
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
    echo "fakenet=$(systemctl is-active quarantine-fakenet 2>/dev/null || true)"
    echo "dnsmasq=$(systemctl is-active dnsmasq 2>/dev/null || true)"
    echo "mitm=$(systemctl is-active quarantine-mitm-transparent 2>/dev/null || true)"
    if dns_listener_up; then
      echo "dns-listener=up"
    else
      echo "dns-listener=down"
    fi
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
