#!/bin/bash
set -e

SERVICE_FILE="/etc/systemd/system/nanobot.service"
INSTALL_DIR="/opt/nanobot"

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

echo "✅ NanoBot removed."
