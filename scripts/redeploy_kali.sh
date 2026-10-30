#!/usr/bin/env bash
#
# redeploy_kali.sh — push the latest committed autopwn to a Kali box that was
# already set up with kali_setup.sh, then restart the service.
#
# Run from the repo root on your dev machine:
#   scripts/redeploy_kali.sh                 # defaults to kali@192.168.132.223
#   scripts/redeploy_kali.sh kali@10.0.0.5   # or any user@host
#
# Ships the current git HEAD (commit your changes first), reinstalls it into the
# venv, and restarts the systemd service. Your scope.yaml and logs/ on the box
# are preserved. You'll be prompted for the SSH/sudo password unless you use keys.
set -euo pipefail

TARGET="${1:-kali@192.168.132.223}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARBALL="$(mktemp -t autopwn-XXXXXX).tar.gz"
trap 'rm -f "$TARBALL"' EXIT

echo "[*] Packaging HEAD ($(git -C "$ROOT" rev-parse --short HEAD)) ..."
git -C "$ROOT" archive --format=tar.gz -o "$TARBALL" HEAD

echo "[*] Uploading to $TARGET ..."
scp "$TARBALL" "$TARGET:/tmp/autopwn.tar.gz"

echo "[*] Installing + restarting on $TARGET ..."
# -t: allocate a TTY so sudo can prompt for the password.
ssh -t "$TARGET" '
  set -e
  VENV="$HOME/.local/share/autopwn-venv/bin"
  # Refresh the source over ~/autopwn, keeping scope.yaml and logs/ intact.
  mkdir -p ~/autopwn
  tar xzf /tmp/autopwn.tar.gz -C ~/autopwn
  # A stale (possibly root-owned) egg-info breaks the wheel build — drop it.
  rm -rf ~/autopwn/autopwn.egg-info
  "$VENV/pip" install --quiet --force-reinstall --no-deps ~/autopwn
  sudo systemctl restart autopwn
  sleep 2
  echo -n "service: "; systemctl is-active autopwn
  curl -s -o /dev/null -w "console: http %{http_code}\n" http://127.0.0.1:8000/api/summary || true
'

echo "[+] Redeploy complete. Hard-refresh the browser (Ctrl+F5) to drop cached assets."
