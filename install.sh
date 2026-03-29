#!/bin/bash
set -e

INSTALL_DIR="/opt/nanobot"
SERVICE_FILE="/etc/systemd/system/nanobot.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════╗"
echo "║   🤖 ROZ NanoBots Installer          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo ./install.sh"
    exit 1
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "Installing Python3..."
    apt-get install -y python3
fi

# Install files
echo "📁 Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/nanobot.py" "$INSTALL_DIR/nanobot.py"
chmod +x "$INSTALL_DIR/nanobot.py"

# Create service
echo "⚙️  Setting up systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=NanoBot - Self-healing system daemon
DefaultDependencies=no
After=sysinit.target
Before=basic.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/nanobot/nanobot.py
Restart=always
RestartSec=5

[Install]
WantedBy=sysinit.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable nanobot.service
systemctl start nanobot.service

echo ""
echo "✅ NanoBot installed and running!"
echo ""
echo "Commands:"
echo "  Status:  sudo systemctl status nanobot"
echo "  Logs:    sudo journalctl -u nanobot -f"
echo "  Stats:   python3 /opt/nanobot/nanobot.py status"
echo "  Stop:    sudo systemctl stop nanobot"
echo "  Remove:  sudo ./install.sh --uninstall"
