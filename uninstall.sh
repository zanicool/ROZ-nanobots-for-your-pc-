#!/bin/bash
set -e

SERVICE_FILE="/etc/systemd/system/nanobot.service"
INSTALL_DIR="/opt/nanobot"
CONFIG_DIR="/etc/nanobot"

echo "🗑️  Uninstalling NanoBot..."

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo ./uninstall.sh"
    exit 1
fi

systemctl stop nanobot.service 2>/dev/null || true
systemctl disable nanobot.service 2>/dev/null || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload
rm -rf "$INSTALL_DIR"

read -rp "Remove config ($CONFIG_DIR)? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -rf "$CONFIG_DIR"
    echo "Config removed."
fi

read -rp "Remove logs (/var/log/nanobot*)? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    rm -f /var/log/nanobot.log /var/log/nanobot_stats.json
    echo "Logs removed."
fi

echo "✅ NanoBot removed."
