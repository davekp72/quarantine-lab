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
# Build C extensions against installed headers
if ! "$pip" install --prefer-binary \
  'NetfilterQueue>=1.1.0' dnslib dpkt pyopenssl pyftpdlib netifaces jinja2 cryptography; then
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

"$pybin" -c 'import fakenet, netfilterqueue, netifaces; print("ok", fakenet.__file__)'

src="$OPT/fakenet/quarantine.ini"
if [[ -f "$src" ]]; then
  sed -e "s/__LAN__/${LAN_IF}/g" -e "s/__LAN_IP__/${LAN_IP}/g" \
    "$src" >"$ETC/fakenet.ini"
fi

echo "FakeNet-NG installed ($py)"
