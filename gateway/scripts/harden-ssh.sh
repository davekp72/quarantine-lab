#!/bin/bash
# Key-only SSH, no password auth, no unrestricted NOPASSWD sudo.
# Usage: quarantine-harden-ssh [username]
set -euo pipefail
USER_NAME="${1:-${QUARANTINE_USER:-quarantine}}"
PUB="${QUARANTINE_SSH_PUB:-/tmp/quarantine-gateway.pub}"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
if [[ -z "$HOME_DIR" ]]; then
  echo "user $USER_NAME not found" >&2
  exit 1
fi

install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh"
if [[ -f "$PUB" ]]; then
  cat "$PUB" >>"$HOME_DIR/.ssh/authorized_keys"
  sort -u "$HOME_DIR/.ssh/authorized_keys" -o "$HOME_DIR/.ssh/authorized_keys"
  chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
  chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
fi

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-quarantine-keys.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
EOF

# Drop unrestricted passwordless sudo if a previous image granted it.
if [[ -f /etc/sudoers.d/quarantine ]]; then
  if grep -q 'NOPASSWD:ALL' /etc/sudoers.d/quarantine 2>/dev/null; then
    rm -f /etc/sudoers.d/quarantine
  fi
fi
if grep -R --include='*' 'NOPASSWD:ALL' /etc/sudoers.d >/dev/null 2>&1; then
  grep -Rl 'NOPASSWD:ALL' /etc/sudoers.d | while read -r f; do
    rm -f "$f"
  done
fi

sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "ssh-harden=ok (keys only, sudo requires password)"
