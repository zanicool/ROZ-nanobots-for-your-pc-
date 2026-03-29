#!/bin/bash
set -e

echo "=== Installing NanoBot ==="

sudo cp /home/zani/nanobots/nanobot.service /etc/systemd/system/nanobot.service
sudo systemctl daemon-reload
sudo systemctl enable nanobot.service
sudo systemctl start nanobot.service

echo "=== NanoBot installed and running ==="
echo "Check status:  sudo systemctl status nanobot"
echo "View logs:     sudo journalctl -u nanobot -f"
