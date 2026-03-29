# 🤖 ROZ NanoBots

A self-healing Linux daemon that automatically detects and fixes system issues — like Iron Man's nanobots, but for your PC.

## What It Does

ROZ NanoBots runs in the background and automatically:

| Module | Description |
|---|---|
| Package Repair | Fixes broken dpkg/apt packages |
| System Updates | Keeps packages and drivers up to date |
| Kernel Health | Verifies kernel image, initramfs, and modules — reinstalls if missing |
| GRUB Recovery | Regenerates bootloader config |
| Filesystem Check | Detects read-only root, schedules fsck on errors |
| Disk Cleanup | Emergency cleanup when disk > 90% full |
| Inode Check | Prevents inode exhaustion |
| Service Healing | Restarts failed and crashed systemd services |
| Zombie Killer | Finds and kills zombie processes |
| OOM Protection | Detects out-of-memory events and tunes kernel |
| Memory Management | Clears caches when memory is critically low |
| Thermal Monitoring | Watches CPU temperature for overheating |
| Network Repair | Restarts networking if connectivity drops |
| DNS Fallback | Fixes broken DNS resolution |
| Kernel Panic Detection | Catches critical kernel messages |
| Log Rotation | Prevents /var/log from filling up |
| Stats Tracking | Logs every fix for lifetime statistics |

## Installation

```bash
git clone https://github.com/zanicool/ROZ-nanobots-for-your-pc-.git
cd ROZ-nanobots-for-your-pc-
sudo ./install.sh
```

This installs NanoBots to `/opt/nanobot` as a systemd service that:
- Starts automatically on boot (early boot stage)
- Restarts itself in 5 seconds if it crashes
- Runs a healing cycle every hour

## Usage

```bash
# Check service status
sudo systemctl status nanobot

# View live logs
sudo journalctl -u nanobot -f

# View lifetime stats dashboard
python3 /opt/nanobot/nanobot.py status
```

## Uninstall

```bash
sudo ./uninstall.sh
```

## Requirements

- Linux (Debian/Ubuntu based)
- Python 3.6+
- Root access (for system repairs)

## Configuration

Edit these variables at the top of `nanobot.py`:

| Variable | Default | Description |
|---|---|---|
| `INTERVAL` | `3600` | Seconds between healing cycles |
| `LOG_FILE` | `/var/log/nanobot.log` | Log file path |
| `STATS_FILE` | `/var/log/nanobot_stats.json` | Stats file path |

## License

MIT License — see [LICENSE](LICENSE)
