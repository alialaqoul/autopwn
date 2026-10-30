#!/usr/bin/env bash
#
# update_kali.sh — update autopwn ON the Kali box from GitHub, then restart.
#
# Run this ON the Kali host, inside the ~/autopwn git clone:
#   ~/autopwn/scripts/update_kali.sh
#
# Pulls origin/main, reinstalls into the venv, and restarts the service. Your
# scope.yaml and logs/ are untracked, so a pull/reinstall leaves them untouched.
#
# (This is the counterpart to redeploy_kali.sh, which pushes FROM your dev
# machine. Use this one when you're working on the Kali box itself.)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$HOME/.local/share/autopwn-venv/bin"
cd "$REPO"

echo "[*] Pulling latest from origin/main ..."
git pull --ff-only
# A stale (possibly root-owned) egg-info breaks the wheel build — drop it.
rm -rf "$REPO/autopwn.egg-info"
echo "[*] Reinstalling into the venv ..."
"$VENV/pip" install --quiet --force-reinstall --no-deps "$REPO"
echo "[*] Restarting the service ..."
sudo systemctl restart autopwn
sleep 2
echo -n "service: "; systemctl is-active autopwn
curl -s -o /dev/null -w "console: http %{http_code}\n" http://127.0.0.1:8000/api/summary || true
echo "[+] Updated to $(git rev-parse --short HEAD). Hard-refresh the browser (Ctrl+F5)."
