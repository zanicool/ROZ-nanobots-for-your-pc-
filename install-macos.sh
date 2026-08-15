#!/bin/bash
# install-macos.sh - Install ROZ NanoBots on macOS via launchd
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$HOME/.local/share/nanobot"
PLIST_FILE="$HOME/Library/LaunchAgents/com.roz.nanobot.plist"
CONFIG_DIR="$HOME/.config/nanobot"

echo "╔══════════════════════════════════════╗"
echo "║   🤖 ROZ NanoBots v5 (macOS)         ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Handle --uninstall
if [ "$1" = "--uninstall" ]; then
    echo "Removing NanoBot..."
    launchctl bootout gui/$(id -u) "$PLIST_FILE" 2>/dev/null || true
    rm -f "$PLIST_FILE"
    rm -rf "$INSTALL_DIR"
    echo "✅ Removed. Config kept at $CONFIG_DIR"
    exit 0
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python3 required. Install: brew install python3"
    exit 1
fi

# Install files
echo "📁 Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/nanobot_macos.py" "$INSTALL_DIR/nanobot.py"
chmod +x "$INSTALL_DIR/nanobot.py"

# Create config
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    python3 "$INSTALL_DIR/nanobot.py" config
    echo "📝 Default config at $CONFIG_DIR/config.json"
fi

# Create launchd plist
echo "⚙️  Setting up launchd service..."
mkdir -p "$(dirname "$PLIST_FILE")"
cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.roz.nanobot</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${INSTALL_DIR}/nanobot.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${HOME}/Library/Logs/nanobot.log</string>
    <key>StandardErrorPath</key>
    <string>${HOME}/Library/Logs/nanobot-error.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
EOF

# Load service
launchctl bootout gui/$(id -u) "$PLIST_FILE" 2>/dev/null || true
launchctl bootstrap gui/$(id -u) "$PLIST_FILE"

echo ""
echo "✅ NanoBot v5 (macOS) installed and running!"
echo ""
echo "Commands:"
echo "  Status:     python3 $INSTALL_DIR/nanobot.py status"
echo "  Single run: python3 $INSTALL_DIR/nanobot.py heal"
echo "  Logs:       tail -f ~/Library/Logs/nanobot.log"
echo "  Config:     $CONFIG_DIR/config.json"
echo "  Stop:       launchctl bootout gui/\$(id -u) $PLIST_FILE"
echo "  Remove:     ./install-macos.sh --uninstall"
