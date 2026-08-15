# 🤖 ROZ NanoBots v6.0.0

The biggest release yet — 40+ self-healing modules running as a single lightweight daemon.

## What's New in v6

- **40+ healing modules** covering packages, kernel, GPU, disk, network, security, and more
- **Arch Linux support** — full pacman integration alongside apt/dpkg
- **macOS support** — separate `nanobot_macos.py` for Homebrew-based systems
- **Real-time monitoring** — quick checks every 30 seconds, full heal every hour
- **Configurable everything** — `/etc/nanobot/config.json` controls all modules
- **Stats tracking** — lifetime repair statistics dashboard
- **Intrusion detection** — port scans, brute force, excessive connections
- **Config watchdog** — detects unauthorized changes to critical system files
- **Battery protection** — auto-hibernate at critical level on laptops
- **Low resource usage** — Nice 19 + idle I/O scheduling, won't impact your system

## Install

```bash
# Arch Linux (AUR)
yay -S roz-nanobots

# Any Linux
git clone https://github.com/zanicool/ROZ-nanobots-for-your-pc-.git
cd ROZ-nanobots-for-your-pc-
sudo ./install.sh

# macOS
sudo ./install-macos.sh
```

## Module Highlights

| Category | Modules |
|----------|---------|
| Storage | SMART monitoring, disk cleanup, inode check, fsck, fstab validation |
| System | Package repair, kernel health, GRUB recovery, service healing |
| Hardware | GPU healing, thermal monitoring, USB error detection, audio/bluetooth |
| Security | Intrusion detection, firewall check, permission healing, config watchdog |
| Network | Auto-repair, DNS fallback, time sync |
| Process | Zombie killer, runaway CPU killer, OOM protection, duplicate detection |

## Requirements

- Linux with systemd (or macOS with launchd)
- Python 3.6+
- Root access

## Full Changelog

See [README.md](https://github.com/zanicool/ROZ-nanobots-for-your-pc-/blob/main/README.md) for complete module list and configuration options.
