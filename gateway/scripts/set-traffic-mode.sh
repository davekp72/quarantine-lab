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
    echo fakenet
  fi
}

inject_nft_snippets() {
  local rendered="$1"
  local wan_rules="$ETC/nftables-permissive-forward.inc"
  local nat_rules="$ETC/nftables-permissive-nat.inc"
  local out_rules="$ETC/nftables-permissive-output.inc"
  local injector="$OPT/scripts/nft-inject-permissive.py"
  if [[ ! -f "$injector" ]]; then
    injector=/usr/local/lib/quarantine/nft-inject-permissive.py
  fi
  python3 "$injector" "$rendered" "$wan_rules" "$nat_rules" "$out_rules"
}

apply_nft() {
  local template="$1"
  if [[ ! -f "$template" ]]; then
    echo "missing nftables template: $template" >&2
    return 1
  fi
  local rendered
  rendered=$(mktemp)
  sed -e "s/__WAN__/${WAN_IF}/g" \
      -e "s/__LAN__/${LAN_IF}/g" \
      -e "s|__LAN_CIDR__|${LAN_CIDR}|g" \
      -e "s/__LAN_IP__/${LAN_IP}/g" \
      -e "s/__GUEST_IP__/${GUEST_IP}/g" \
      -e "s/__AGENT_PORT__/${AGENT_PORT}/g" \
      "$template" >"$rendered"
  inject_nft_snippets "$rendered"
  sed -i -e "s/__WAN__/${WAN_IF}/g" -e "s/__LAN__/${LAN_IF}/g" "$rendered"
  cp "$rendered" /etc/nftables.conf
  rm -f "$rendered"
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
  for c in /var/lib/quarantine-mitm/mitmproxy-ca.pem \
           /root/.mitmproxy/mitmproxy-ca.pem \
           /home/quarantine/.mitmproxy/mitmproxy-ca.pem \
           /home/*/.mitmproxy/mitmproxy-ca.pem; do
    if [[ -f "$c" ]]; then
      combined="$c"
      break
    fi
  done
  if [[ -z "$combined" ]]; then
    echo "ERROR: mitmproxy CA not found under /var/lib/quarantine-mitm (run gateway provision / export-ca)." >&2
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
  # FakeNet service user must read the CA key
  if id quarantine-fakenet >/dev/null 2>&1; then
    chgrp quarantine-fakenet "$key_out" 2>/dev/null || true
    chmod 640 "$key_out"
  fi
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
  cat >"$www/quarantine.pac" <<EOF
function FindProxyForURL(url, host) {
    return "PROXY ${LAN_IP}:8080";
}
EOF
  chmod 644 "$www/quarantine.pac"
  cat >"$ETC/fakenet-proxy.env" <<EOF
QUARANTINE_LAN_IP=${LAN_IP}
QUARANTINE_FAKENET_WWW=/var/log/quarantine/fakenet/www
QUARANTINE_FAKENET_PROXY_PORTS=8080,8081
EOF

  echo "FakeNet HTTPS will use mitmproxy CA: $cert_out (from $combined)"
  echo "FakeNet CA subject/dates:"
  openssl x509 -in "$cert_out" -noout -subject -issuer -dates 2>/dev/null || true
  year="$(date -u +%Y 2>/dev/null || echo 0)"
  if [[ "$year" -lt 2024 || "$year" -gt 2038 ]]; then
    echo "WARNING: gateway clock is $(date -u 2>/dev/null). FakeNet leaves will use the CA validity window (Windows guest clock still applies)."
  fi
}

# Apply cryptography-based SSL patch so HTTPS UseSSL works on modern pyOpenSSL.
# Replace FakeNet HTTPListener with the CONNECT-capable copy (browser PAC HTTPS).
patch_fakenet_ssl() {
  local patch_src="$OPT/fakenet/ssl_utils_init.py"
  local http_patch="$OPT/fakenet/patch_httplistener.py"
  local http_src="$OPT/fakenet/HTTPListener.py"
  local pybin=/opt/quarantine-gateway/venv-fakenet/bin/python
  local ssl_dst http_dst
  if [[ ! -x "$pybin" ]]; then
    echo "ERROR: FakeNet venv python missing: $pybin" >&2
    return 1
  fi
  if [[ -f "$patch_src" ]]; then
    ssl_dst="$("$pybin" -c 'import fakenet.listeners.ssl_utils as s, pathlib; print(pathlib.Path(s.__file__).resolve())' 2>/dev/null || true)"
    if [[ -n "$ssl_dst" && -f "$ssl_dst" ]]; then
      install -m 0644 "$patch_src" "$ssl_dst"
      rm -rf "$(dirname "$ssl_dst")/__pycache__" 2>/dev/null || true
    else
      echo "ERROR: could not locate FakeNet ssl_utils to patch" >&2
      return 1
    fi
  fi
  if [[ ! -f "$http_src" ]]; then
    echo "ERROR: missing CONNECT HTTPListener: $http_src" >&2
    return 1
  fi
  http_dst="$("$pybin" -c 'import fakenet.listeners.HTTPListener as h, pathlib; print(pathlib.Path(h.__file__).resolve())' 2>/dev/null || true)"
  if [[ -z "$http_dst" || ! -f "$http_dst" ]]; then
    echo "ERROR: could not locate FakeNet HTTPListener to replace" >&2
    return 1
  fi
  if [[ -f "$http_patch" ]]; then
    "$pybin" "$http_patch" "$http_dst" "$http_src" || return 1
  else
    install -m 0644 "$http_src" "$http_dst" || return 1
  fi
  rm -rf "$(dirname "$http_dst")/__pycache__" 2>/dev/null || true
  if ! grep -q 'QUARANTINE_CONNECT_PATCH_V3' "$http_dst"; then
    echo "ERROR: HTTPListener CONNECT copy did not install" >&2
    return 1
  fi
  # Allow non-root FakeNet when systemd grants CAP_NET_ADMIN (required with User=quarantine-fakenet).
  local priv_patch="$OPT/fakenet/patch_diverter_privcheck.py"
  if [[ ! -f "$priv_patch" ]]; then
    echo "ERROR: missing FakeNet diverter privcheck patch: $priv_patch" >&2
    return 1
  fi
  local div_dst
  div_dst="$("$pybin" -c 'import fakenet.diverters.diverterbase as d, pathlib; print(pathlib.Path(d.__file__).resolve())' 2>/dev/null || true)"
  if [[ -z "$div_dst" || ! -f "$div_dst" ]]; then
    echo "ERROR: could not locate FakeNet diverterbase to patch" >&2
    return 1
  fi
  "$pybin" "$priv_patch" "$div_dst" || return 1
  rm -rf "$(dirname "$div_dst")/__pycache__" 2>/dev/null || true
  if ! grep -q 'CapEff:' "$div_dst" || ! grep -q '1 << 12' "$div_dst"; then
    echo "ERROR: diverter privcheck patch did not apply" >&2
    return 1
  fi
  rm -rf /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs/temp_certs \
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
  # FakeNet and old experiments may leave iptables-legacy NAT OUTPUT redirects.
  # Those bounce gateway-originated HTTP (mitmproxy → origin:80) to local :80,
  # which is closed in permissive mode → errno 111 → 502 Bad Gateway.
  local ipt
  for ipt in iptables iptables-nft iptables-legacy ip6tables ip6tables-nft ip6tables-legacy; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    $ipt -t mangle -F 2>/dev/null || true
    $ipt -t raw -F 2>/dev/null || true
    $ipt -t nat -F OUTPUT 2>/dev/null || true
    $ipt -t nat -F PREROUTING 2>/dev/null || true
    $ipt -t nat -F 2>/dev/null || true
    while $ipt -t mangle -D PREROUTING -j NFQUEUE 2>/dev/null; do :; done
    while $ipt -t filter -D INPUT -j NFQUEUE 2>/dev/null; do :; done
    while $ipt -t filter -D FORWARD -j NFQUEUE 2>/dev/null; do :; done
  done
  conntrack -F 2>/dev/null || true
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
  patch_fakenet_ssl || return 1
  # Disable MITM/dnsmasq so they cannot start after FakeNet on reboot
  # (systemd Conflicts would otherwise stop FakeNet).
  systemctl disable --now quarantine-mitm-explicit quarantine-mitm-transparent dnsmasq quarantine-fakenet-proxy 2>/dev/null || true
  systemctl reset-failed quarantine-fakenet 2>/dev/null || true
  systemctl stop quarantine-fakenet 2>/dev/null || true
  free_dns_port
  : >"$LOG/fakenet/fakenet.log" 2>/dev/null || true
  # Drop cached FakeNet leaves (old CDP / 1970-dated / CA-as-leaf) so they are re-signed.
  rm -rf /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs/temp_certs \
    /var/log/quarantine/fakenet/certs
  mkdir -p /var/log/quarantine/fakenet/certs /var/log/quarantine/fakenet/www
  if [[ -x /usr/local/sbin/quarantine-ensure-service-users ]]; then
    /usr/local/sbin/quarantine-ensure-service-users || true
  fi
  chown -R quarantine-fakenet:quarantine-fakenet \
    /var/log/quarantine/fakenet /var/log/quarantine/fakenet/certs /var/log/quarantine/fakenet/www \
    2>/dev/null || true
  chmod 755 /var/log/quarantine/fakenet /var/log/quarantine/fakenet/certs /var/log/quarantine/fakenet/www
  publish_fakenet_crl
  # CRL/www served by FakeNet HTTPListener — keep readable/writable by service user.
  chown -R quarantine-fakenet:quarantine-fakenet /var/log/quarantine/fakenet/www 2>/dev/null || true
  apply_nft "$OPT/nftables-fakenet.conf" || return 1
  systemctl daemon-reload 2>/dev/null || true
  systemctl start quarantine-fakenet || return 1
  if ! systemctl is-active --quiet quarantine-fakenet; then
    echo "quarantine-fakenet failed to start" >&2
    journalctl -u quarantine-fakenet -n 40 --no-pager >&2 || true
    return 1
  fi
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
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
  # Confirm TLS listener came up (UseSSL on :443) and CONNECT proxy (:8080)
  if ! ss -tlnp 2>/dev/null | grep -E ':443\b' | grep -qiE 'python|fakenet'; then
    echo "WARNING: FakeNet TCP/443 is not listening (HTTPS may be down)" >&2
    tail -n 30 "$LOG/fakenet/fakenet.log" >&2 || true
  fi
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -tlnp 2>/dev/null | grep -qE ':8080\b'; then
      break
    fi
    sleep 0.5
  done
  if ! ss -tlnp 2>/dev/null | grep -qE ':8080\b'; then
    echo "ERROR: FakeNet TCP/8080 is not listening (browsers using PAC/CONNECT will fail)" >&2
    tail -n 50 "$LOG/fakenet/fakenet.log" >&2 || true
    journalctl -u quarantine-fakenet -n 40 --no-pager >&2 || true
    return 1
  fi
  if ! /opt/quarantine-gateway/venv-fakenet/bin/python \
      "$OPT/fakenet/test_connect_proxy.py" "$LAN_IP" 8080; then
    echo "ERROR: browser HTTPS path failed (CONNECT+TLS via :8080). HTTP-only browsers would still work." >&2
    echo "--- fakenet.log ---" >&2
    tail -n 80 "$LOG/fakenet/fakenet.log" >&2 || true
    return 1
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
  echo "Guest browser PAC/CONNECT: FakeNet HTTPListener on ${LAN_IP}:8080"
}

mode_permissive() {
  systemctl disable --now quarantine-fakenet-proxy quarantine-fakenet 2>/dev/null || true
  cleanup_nfqueue
  apply_nft "$OPT/nftables.conf" || return 1
  systemctl enable --now dnsmasq 2>/dev/null || true
  systemctl enable --now quarantine-mitm-explicit quarantine-mitm-transparent || return 1
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -tlnp 2>/dev/null | grep -qE ':8080\b' \
      && ss -tlnp 2>/dev/null | grep -qE ':8082\b'; then
      break
    fi
    sleep 0.5
  done
  if ! ss -tlnp 2>/dev/null | grep -qE ':8080\b'; then
    echo "ERROR: explicit mitmproxy :8080 is not listening" >&2
    journalctl -u quarantine-mitm-explicit -n 40 --no-pager >&2 || true
    return 1
  fi
  if ! ss -tlnp 2>/dev/null | grep -qE ':8082\b'; then
    echo "ERROR: transparent mitmproxy :8082 is not listening (curl --noproxy would miss MITM)" >&2
    journalctl -u quarantine-mitm-transparent -n 40 --no-pager >&2 || true
    return 1
  fi
  if ! nft list chain ip nat prerouting 2>/dev/null | grep -qE 'redirect to :?8082'; then
    echo "ERROR: nftables is not redirecting guest :80/:443 to mitm :8082" >&2
    nft list chain ip nat prerouting >&2 || true
    return 1
  fi
  # mitmproxy outbound HTTP must work (PowerShell curl / IWR uses the explicit proxy).
  local http_code
  http_code="$(curl -4 --noproxy '*' -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 12 http://example.com/ 2>/dev/null || true)"
  echo "gateway-upstream http://example.com/ -> ${http_code:-fail}"
  if [[ "$http_code" != "200" && "$http_code" != "301" && "$http_code" != "302" ]]; then
    echo "ERROR: gateway cannot fetch HTTP from WAN (mitmproxy will 502 for guest HTTP)." >&2
    echo "Check VBox NAT / host firewall for outbound TCP 80." >&2
    return 1
  fi
  http_code="$(curl -4 --noproxy '*' -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 12 http://neverssl.com/online/ 2>/dev/null || true)"
  echo "gateway-upstream http://neverssl.com/online/ -> ${http_code:-fail}"
  echo permissive >"$MODE_FILE"
  echo "traffic-mode=permissive (allowlisted internet + MITM + PCAP)"
  echo "Guest browser PAC/CONNECT: mitmproxy ${LAN_IP}:8080"
  echo "Guest curl/direct :80/:443: redirected to mitmproxy ${LAN_IP}:8082"
}

case "$MODE" in
  status|"")
    echo "traffic-mode=$(current_mode)"
    echo "fakenet=$(systemctl is-active quarantine-fakenet 2>/dev/null || true)"
    echo "dnsmasq=$(systemctl is-active dnsmasq 2>/dev/null || true)"
    echo "mitm=$(systemctl is-active quarantine-mitm-transparent 2>/dev/null || true)"
    echo "fakenet-proxy=$(systemctl is-active quarantine-fakenet-proxy 2>/dev/null || true)"
    if dns_listener_up; then
      echo "dns-listener=up"
    else
      echo "dns-listener=down"
    fi
    ;;
  boot)
    case "$(current_mode)" in
      permissive|mitm|internet)
        mode_permissive
        ;;
      *)
        if ! mode_fakenet; then
          echo "ERROR: FakeNet unavailable on boot; leaving previous nftables (not opening WAN)." >&2
          exit 1
        fi
        ;;
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
