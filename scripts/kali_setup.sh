#!/usr/bin/env bash
#
# kali_setup.sh — install autopwn on a Kali box, auto-start it on every reboot,
# and drop a desktop shortcut that opens the web console.
#
# Run ON the Kali box as the 'kali' user (it uses sudo where needed):
#   chmod +x kali_setup.sh && ./kali_setup.sh
#
# Re-running is safe: it updates the install and refreshes the service/shortcut.
set -euo pipefail

APP_USER="${SUDO_USER:-$USER}"
APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root (this script lives in scripts/)
VENV_DIR="$APP_HOME/.local/share/autopwn-venv"
HOST="127.0.0.1"
PORT="8000"
URL="http://$HOST:$PORT"

echo "[*] autopwn source : $SRC_DIR"
echo "[*] install user   : $APP_USER ($APP_HOME)"
echo "[*] virtualenv     : $VENV_DIR"
echo "[*] console URL    : $URL"

# --- 1. system deps -----------------------------------------------------------
echo "[*] Installing python venv support..."
sudo apt-get update -y
sudo apt-get install -y python3-venv python3-pip

# --- 2. venv + package --------------------------------------------------------
echo "[*] Creating virtualenv and installing autopwn[web]..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install "$SRC_DIR[web]"

# --- 3. systemd service: auto-start on every reboot ---------------------------
# System service (runs as $APP_USER). Starts at boot with no login/DBus/linger
# dependency — more robust than a --user service over SSH.
echo "[*] Installing systemd system service..."
sudo tee /etc/systemd/system/autopwn.service >/dev/null <<EOF
[Unit]
Description=autopwn web console
After=network-online.target
Wants=network-online.target

[Service]
User=$APP_USER
WorkingDirectory=$SRC_DIR
ExecStart=$VENV_DIR/bin/autopwn web --host $HOST --port $PORT
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now autopwn.service
sleep 2
sudo systemctl --no-pager --full status autopwn.service || true

# --- 4. desktop shortcut ------------------------------------------------------
echo "[*] Creating desktop shortcut..."
DESKTOP_DIR="$APP_HOME/Desktop"
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/autopwn.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=autopwn console
Comment=Open the autopwn web console
Exec=xdg-open $URL
Icon=utilities-terminal
Terminal=false
Categories=Security;
EOF
chmod +x "$DESKTOP_DIR/autopwn.desktop"
# GNOME requires the launcher to be marked trusted
gio set "$DESKTOP_DIR/autopwn.desktop" metadata::trusted true 2>/dev/null || true

echo
echo "[+] Done."
echo "    Service : sudo systemctl status autopwn"
echo "    Console : $URL  (double-click 'autopwn console' on the desktop)"
echo "    Logs    : sudo journalctl -u autopwn -f"
