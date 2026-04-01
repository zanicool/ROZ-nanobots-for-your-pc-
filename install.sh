#!/bin/bash
set -e

INSTALL_DIR="/opt/nanobot"
SERVICE_FILE="/etc/systemd/system/nanobot.service"
CONFIG_DIR="/etc/nanobot"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════╗"
echo "║   🤖 ROZ NanoBots v5 Installer       ║"
echo "╚══════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root: sudo ./install.sh"
    exit 1
fi

# Handle --uninstall flag
if [ "$1" = "--uninstall" ]; then
    exec "$SCRIPT_DIR/uninstall.sh"
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

# Create default config if missing
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    python3 "$INSTALL_DIR/nanobot.py" config
    echo "📝 Default config created at $CONFIG_DIR/config.json"
fi

# Create service
echo "⚙️  Setting up systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ROZ NanoBots v5 - Self-healing system daemon
DefaultDependencies=no
After=sysinit.target network-online.target
Wants=network-online.target
Before=basic.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/nanobot/nanobot.py
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=sysinit.target
EOF

systemctl daemon-reload
systemctl enable nanobot.service
systemctl start nanobot.service

echo ""
echo "✅ NanoBot v5 installed and running!"
echo ""
echo "Commands:"
echo "  Status:     sudo systemctl status nanobot"
echo "  Dashboard:  python3 /opt/nanobot/nanobot.py status"
echo "  Logs:       sudo journalctl -u nanobot -f"
echo "  Config:     sudo nano /etc/nanobot/config.json"
echo "  Stop:       sudo systemctl stop nanobot"
echo "  Remove:     sudo ./uninstall.sh"
