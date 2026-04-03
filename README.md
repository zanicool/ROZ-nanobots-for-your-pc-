# 🤖 ROZ NanoBots v6

A self-healing Linux daemon that automatically detects and fixes system issues — like Iron Man's nanobots, but for your PC.

## What It Does

ROZ NanoBots runs in the background and automatically:

| Module | Description |
|---|---|
| Package Repair | Fixes broken dpkg/apt packages and stale locks |
| System Updates | Keeps packages up to date |
| Kernel Health | Verifies kernel image, initramfs, and modules — reinstalls if missing |
| GRUB Recovery | Regenerates bootloader config |
| GPU Healing | Detects and reloads crashed NVIDIA/AMD GPU drivers |
| SMART Monitoring | Watches disk health for failing sectors and SMART failures |
| Filesystem Check | Detects read-only root, schedules fsck on errors |
| Fstab Validation | Verifies and mounts missing fstab entries |
| Disk Cleanup | Emergency cleanup when disk > 90% full, removes old kernels |
| Inode Check | Prevents inode exhaustion |
| Service Healing | Restarts failed/crashed systemd services with retry limits |
| Critical Services | Monitors essential services (journald, logind, dbus, cron) |
| Zombie Killer | Finds and kills zombie processes |
| Runaway Process Killer | Kills processes stuck at >95% CPU for >5 minutes |
| OOM Protection | Detects out-of-memory events and tunes kernel |
| Memory Management | Clears caches when memory is critically low |
| Swap Recovery | Re-enables swap or creates emergency swapfile |
| Thermal Monitoring | Watches all CPU/GPU thermal zones |
| Network Repair | Restarts networking and brings up interfaces if connectivity drops |
| DNS Fallback | Fixes broken DNS with systemd-resolved restart and fallback nameservers |
| Security Audit | Detects SSH brute force, world-writable files, SUID in temp dirs |
| Firewall Check | Warns if UFW/iptables is inactive |
| Time Sync | Re-enables NTP if clock is drifting |
| Permission Healing | Fixes critical file permissions (/etc/shadow, /tmp, etc.) |
| Kernel Panic Detection | Catches critical kernel messages |
| Crash Recovery | Cleans crash dumps from /var/crash |
| Log Rotation | Prevents /var/log from filling up |
| Docker Healing | Restarts dead containers, prunes dangling resources |
| USB Monitoring | Detects USB errors and resets controllers |
| Intrusion Detection | Spots port scans, brute force, excessive connections |
| Config Watchdog | Detects unauthorized changes to critical config files |
| Battery Protection | Warns on low battery, auto-hibernates at critical level |
| Coredump Cleanup | Removes old crash dumps to save disk space |
| Entropy Check | Ensures enough randomness for crypto, installs haveged |
| Journal Health | Fixes corrupt journal entries, controls journal size |
| Duplicate Process Detection | Kills duplicate instances of singleton services |
| Disk I/O Latency | Warns when disk response times are dangerously high |
| Orphan Package Cleanup | Purges residual configs from removed packages |
| Broken Symlink Healing | Finds and fixes broken symlinks in system dirs |
| Hostname Validation | Restores hostname if it gets corrupted |
| Locale Healing | Fixes broken locale settings |
| Xorg / Display Healing | Monitors Xorg errors and display server health |
| Audio Healing | Restarts PulseAudio/PipeWire if audio stops working |
| Bluetooth Healing | Unblocks and restarts bluetooth if it fails |
| Cron Healing | Ensures cron is running, validates crontabs |
| Tmpfiles Healing | Cleans old temp files, ensures /tmp is writable |
| Stats Tracking | Logs every fix for lifetime statistics |

## Installation

```bash
git clone https://github.com/zanicool/ROZ-nanobots-for-your-pc-.git
cd ROZ-nanobots-for-your-pc-
sudo ./install.sh
```

This installs NanoBots to `/opt/nanobot` as a systemd service that:
- Starts automatically on boot (early boot stage)
- Waits for network before running
- Restarts itself in 5 seconds if it crashes
- Shuts down gracefully on SIGTERM
- Runs a full healing cycle every hour with quick checks every 30 seconds

## Usage

```bash
# Check service status
sudo systemctl status nanobot

# View live logs
sudo journalctl -u nanobot -f

# View lifetime stats dashboard
python3 /opt/nanobot/nanobot.py status

# Run a one-shot full heal
sudo python3 /opt/nanobot/nanobot.py heal

# Run a quick check
sudo python3 /opt/nanobot/nanobot.py quick

# Generate default config
sudo python3 /opt/nanobot/nanobot.py config
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

Edit `/etc/nanobot/config.json` (created on install):

| Variable | Default | Description |
|---|---|---|
| `interval` | `3600` | Seconds between full healing cycles |
| `realtime_interval` | `30` | Seconds between quick checks |
| `enable_updates` | `true` | Auto-update packages |
| `enable_security` | `true` | Run security audits |
| `enable_smart` | `true` | SMART disk monitoring |
| `enable_firewall_check` | `true` | Firewall status check |
| `enable_time_sync` | `true` | NTP sync check |
| `enable_permission_heal` | `true` | Fix critical file permissions |
| `enable_docker` | `true` | Docker container healing |
| `enable_usb_monitor` | `true` | USB device error detection |
| `enable_network_intrusion` | `true` | Network intrusion detection |
| `enable_config_watchdog` | `true` | Config file change detection |
| `enable_battery` | `true` | Battery monitoring and protection |
| `enable_coredump` | `true` | Coredump cleanup |
| `enable_entropy` | `true` | Entropy pool monitoring |
| `enable_journal_health` | `true` | Journal integrity checks |
| `enable_duplicate_process` | `true` | Duplicate process detection |
| `enable_disk_latency` | `true` | Disk I/O latency monitoring |
| `enable_orphan_cleanup` | `true` | Orphan package cleanup |
| `enable_symlink_heal` | `true` | Broken symlink repair |
| `enable_hostname_check` | `true` | Hostname validation |
| `enable_locale_check` | `true` | Locale healing |
| `enable_xorg_heal` | `true` | Xorg/display healing |
| `enable_audio_heal` | `true` | Audio subsystem healing |
| `enable_bluetooth_heal` | `true` | Bluetooth healing |
| `enable_cron_heal` | `true` | Cron service healing |
| `enable_tmpfiles` | `true` | Temp file cleanup |
| `critical_services` | `[journald, logind, dbus, cron]` | Services that must always be running |
| `watched_services` | `[]` | Additional services to monitor |
| `watched_configs` | `[/etc/passwd, /etc/shadow, ...]` | Config files to watch for changes |
| `max_restart_attempts` | `3` | Max restarts per service per cycle |
| `max_connections_per_ip` | `50` | Intrusion detection threshold |
| `ssh_max_failed_per_hour` | `50` | Brute force detection threshold |
| `disk_warn_pct` | `80` | Disk usage warning threshold |
| `disk_crit_pct` | `90` | Disk usage critical threshold |
| `mem_crit_mb` | `200` | Low memory threshold (MB) |
| `temp_warn_c` | `80` | Temperature warning (°C) |
| `temp_crit_c` | `90` | Temperature critical (°C) |
| `battery_crit_pct` | `10` | Battery critical threshold (%) |
| `max_log_size_mb` | `1000` | Max /var/log size before rotation |

## License

MIT License — see [LICENSE](LICENSE)
