#!/bin/bash
# Install / repair FakeNet-NG venv on the quarantine gateway.
# Requires WAN DNS (apt + pip). Safe to re-run.
set -euo pipefail

OPT=/opt/quarantine-gateway
ETC=/etc/quarantine-gateway
LAN_IF="${QUARANTINE_LAN_IF:-enp0s8}"
LAN_IP="${QUARANTINE_LAN_GATEWAY:-10.66.0.1}"

if [[ -f "$ETC/ifaces.env" ]]; then
  # shellcheck disable=SC1091
  source "$ETC/ifaces.env" || true
fi
LAN_IF="${LAN:-${LAN_IF}}"
LAN_IP="${LAN_IP:-10.66.0.1}"

export DEBIAN_FRONTEND=noninteractive

# VBox NAT often breaks apt over IPv6 even when IPv4 ping works.
mkdir -p /etc/apt/apt.conf.d
cat >/etc/apt/apt.conf.d/99quarantine-force-ipv4 <<'EOF'
Acquire::ForceIPv4 "true";
EOF

wait_dns() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    # Prefer IPv4 resolution for apt mirrors
    if getent ahostsv4 pypi.org >/dev/null 2>&1 || getent ahostsv4 archive.ubuntu.com >/dev/null 2>&1; then
      return 0
    fi
    if getent hosts pypi.org >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

ensure_wan_dns() {
  if [[ -x /usr/local/sbin/quarantine-repair-wan-dns ]]; then
    /usr/local/sbin/quarantine-repair-wan-dns || true
  elif [[ -f "$OPT/scripts/repair-wan-dns.sh" ]]; then
    bash "$OPT/scripts/repair-wan-dns.sh" || true
  fi
  # Prefer public DNS first — VBox 10.0.2.3 is flaky for apt under load
  rm -f /etc/resolv.conf
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 10.0.2.3\n' >/etc/resolv.conf
  wait_dns || true
  pin_apt_mirrors
}

# VirtualBox NAT DNS often fails mid-apt ("Temporary failure resolving") even when
# ping works. Pin IPv4 mirror addresses so apt does not need the resolver.
pin_apt_mirrors() {
  local ip=""
  local host
  for host in archive.ubuntu.com gb.archive.ubuntu.com security.ubuntu.com; do
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    if [[ -z "$ip" ]]; then
      # Last-known Canonical mirror A records (best-effort fallback)
      case "$host" in
        security.ubuntu.com) ip=185.125.190.81 ;;
        *) ip=185.125.190.82 ;;
      esac
    fi
    if ! grep -qE "[[:space:]]${host}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
      echo "$ip $host" >>/etc/hosts
    else
      sed -i -E "s/^[0-9a-fA-F:.]+[[:space:]]+${host}([[:space:]].*)?$/${ip} ${host}/" /etc/hosts || true
    fi
  done
  # Also try resolving via dig/curl if getent only returned IPv6 earlier
  if command -v curl >/dev/null 2>&1; then
    curl -4 -fsS --connect-timeout 5 -o /dev/null http://archive.ubuntu.com/ubuntu/ || true
  fi
}

has_nfqueue_headers() {
  [[ -f /usr/include/libnetfilter_queue/libnetfilter_queue.h ]] ||
    pkg-config --exists libnetfilter_queue 2>/dev/null
}

ensure_wan_dns

apt_retry() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if apt-get update -y; then
      return 0
    fi
    echo "apt-get update attempt $attempt failed — repairing DNS"
    ensure_wan_dns
    sleep $((attempt * 2))
  done
  return 1
}

apt_retry || true

# Required build deps (do NOT bundle optional python3.12 — missing packages fail the whole line)
installed=0
for attempt in 1 2 3 4 5; do
  if apt-get install -y --no-install-recommends \
    build-essential python3-dev python3-venv libffi-dev \
    libnetfilter-queue-dev libnfnetlink-dev; then
    installed=1
    break
  fi
  echo "apt FakeNet deps attempt $attempt failed — repairing DNS and retrying"
  ensure_wan_dns
  apt-get update -y || true
  sleep $((attempt * 2))
done

# Optional: FakeNet historically happier on 3.12; Ubuntu 26 may only ship 3.14
apt-get install -y --no-install-recommends python3.12 python3.12-venv python3.12-dev || true

if [[ "$installed" -ne 1 ]] || ! has_nfqueue_headers; then
  echo "ERROR: libnetfilter-queue-dev is not installed (WAN DNS / apt failed)." >&2
  echo "Fix gateway internet, then re-run: .\\quarantine-vm.ps1 gateway provision" >&2
  echo "Tip: from gateway, try: sudo quarantine-repair-wan-dns && sudo apt-get update" >&2
  exit 1
fi

py=python3
if command -v python3.12 >/dev/null 2>&1; then
  py=python3.12
fi

mkdir -p /var/log/quarantine/fakenet "$ETC"
need_venv=0
if [[ ! -x /opt/quarantine-gateway/venv-fakenet/bin/python ]]; then
  need_venv=1
elif ! /opt/quarantine-gateway/venv-fakenet/bin/python -c 'import netfilterqueue, netifaces, fakenet' 2>/dev/null; then
  need_venv=1
fi

if [[ "$need_venv" -eq 1 ]]; then
  rm -rf /opt/quarantine-gateway/venv-fakenet
  "$py" -m venv /opt/quarantine-gateway/venv-fakenet
fi

pip=/opt/quarantine-gateway/venv-fakenet/bin/pip
pybin=/opt/quarantine-gateway/venv-fakenet/bin/python

"$pip" install --upgrade pip setuptools wheel
# Prefer current cryptography/pyOpenSSL — FakeNet SSL is patched below for modern APIs.
if ! "$pip" install --prefer-binary \
  'NetfilterQueue>=1.1.0' dnslib dpkt pyopenssl cryptography \
  pyftpdlib netifaces jinja2; then
  echo "ERROR: FakeNet dependency build failed (netfilterqueue/netifaces)." >&2
  exit 1
fi

if ! "$pybin" -c 'import fakenet' 2>/dev/null; then
  if ! "$pip" install --prefer-binary \
    'https://github.com/mandiant/flare-fakenet-ng/archive/refs/heads/master.zip'; then
    echo "ERROR: FakeNet-NG pip install failed." >&2
    exit 1
  fi
fi

# Patch FakeNet SSL (X509Extension removed from pyOpenSSL) so HTTPS listeners work.
patch_src="$OPT/fakenet/ssl_utils_init.py"
if [[ -f "$patch_src" ]]; then
  ssl_dst="$("$pybin" -c 'import fakenet.listeners.ssl_utils as s, pathlib; print(pathlib.Path(s.__file__).resolve())')"
  install -m 0644 "$patch_src" "$ssl_dst"
  # Drop cached bytecode + any previously generated CA that may be half-written
  rm -rf "$(dirname "$ssl_dst")/__pycache__" \
    /opt/quarantine-gateway/venv-fakenet/lib/python*/site-packages/fakenet/configs/temp_certs \
    2>/dev/null || true
  echo "Patched FakeNet SSL utils -> $ssl_dst"
fi

http_patch="$OPT/fakenet/patch_httplistener.py"
http_src="$OPT/fakenet/HTTPListener.py"
http_dst="$("$pybin" -c 'import fakenet.listeners.HTTPListener as h, pathlib; print(pathlib.Path(h.__file__).resolve())')"
if [[ -f "$http_src" && -n "$http_dst" ]]; then
  if [[ -f "$http_patch" ]]; then
    "$pybin" "$http_patch" "$http_dst" "$http_src"
  else
    install -m 0644 "$http_src" "$http_dst"
  fi
  rm -rf "$(dirname "$http_dst")/__pycache__" 2>/dev/null || true
  echo "Installed FakeNet HTTPListener CONNECT -> $http_dst"
fi

priv_patch="$OPT/fakenet/patch_diverter_privcheck.py"
if [[ -f "$priv_patch" ]]; then
  div_dst="$("$pybin" -c 'import fakenet.diverters.diverterbase as d, pathlib; print(pathlib.Path(d.__file__).resolve())')"
  "$pybin" "$priv_patch" "$div_dst"
  rm -rf "$(dirname "$div_dst")/__pycache__" 2>/dev/null || true
fi

"$pybin" -c 'import fakenet, netfilterqueue, netifaces; from fakenet.listeners.ssl_utils import SSLWrapper; print("ok", fakenet.__file__)'

# Smoke-test cert generation (catches X509Extension regressions early)
"$pybin" - <<'PY'
import os, tempfile, datetime
from cryptography import x509
from fakenet.listeners.ssl_utils import SSLWrapper

td = tempfile.mkdtemp(prefix="fakenet-ssl-")
cfg = {"cert_dir": td, "static_ca": "No", "networkmode": "multihost", "webroot": None}
w = SSLWrapper(cfg)
assert os.path.isfile(w.ca_cert) and os.path.isfile(w.ca_key), "CA not created"
leaf_c, leaf_k, _ = w.create_cert("example.test", w.ca_cert, w.ca_key, td)
assert leaf_c and os.path.isfile(leaf_c), "leaf cert failed"
with open(leaf_c, "rb") as f:
    leaf = x509.load_pem_x509_certificate(f.read())
na = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after
assert na.year >= 2024, "leaf notAfter is %s" % na
try:
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert not bc.ca, "leaf must not be a CA cert"
except x509.ExtensionNotFound:
    pass
try:
    cdp = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert cdp is not None
except x509.ExtensionNotFound:
    raise SystemExit("leaf must have CDP (Schannel CRYPT_E_NO_REVOCATION_CHECK)")
# Static CA path: reuse the just-minted CA as FakeNet Static_CA
td2 = tempfile.mkdtemp(prefix="fakenet-static-")
cfg2 = {
    "cert_dir": td2,
    "static_ca": "Yes",
    "ca_cert": w.ca_cert,
    "ca_key": w.ca_key,
    "networkmode": "multihost",
    "webroot": None,
}
w2 = SSLWrapper(cfg2)
chain, key, _ = w2.create_cert("google.com", w2.ca_cert, w2.ca_key, td2)
assert os.path.isfile(chain) and os.path.isfile(key)
with open(chain, "rb") as f:
    signed = x509.load_pem_x509_certificate(f.read())
assert signed.issuer == x509.load_pem_x509_certificate(open(w.ca_cert, "rb").read()).subject
print("ssl-smoke-ok", w.ca_cert, leaf_c, chain)
PY

src="$OPT/fakenet/quarantine.ini"
if [[ -f "$src" ]]; then
  sed -e "s/__LAN__/${LAN_IF}/g" -e "s/__LAN_IP__/${LAN_IP}/g" \
    "$src" >"$ETC/fakenet.ini"
fi

echo "FakeNet-NG installed ($py)"
