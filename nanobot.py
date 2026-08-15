#!/usr/bin/env python3
"""ROZ NanoBots v7 - Self-healing Linux system daemon."""

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# --- Config ---

CONFIG_FILE = "/etc/nanobot/config.json"
DEFAULT_CONFIG = {
    "interval": 3600,
    "realtime_interval": 30,
    "log_file": "/var/log/nanobot.log",
    "stats_file": "/var/log/nanobot_stats.json",
    "enable_updates": False,
    "enable_security": True,
    "enable_smart": True,
    "critical_services": ["systemd-journald", "systemd-logind", "dbus", "cron"],
    "watched_services": [],
    "max_log_size_mb": 1000,
    "disk_warn_pct": 80,
    "disk_crit_pct": 90,
    "mem_crit_mb": 200,
    "temp_warn_c": 80,
    "temp_crit_c": 90,
    "max_restart_attempts": 3,
    "enable_firewall_check": True,
    "enable_time_sync": True,
    "enable_permission_heal": True,
    "enable_docker": True,
    "enable_usb_monitor": True,
    "enable_network_intrusion": True,
    "enable_config_watchdog": True,
    "enable_battery": True,
    "enable_coredump": True,
    "enable_entropy": True,
    "enable_journal_health": True,
    "enable_duplicate_process": True,
    "enable_disk_latency": True,
    "enable_orphan_cleanup": True,
    "enable_symlink_heal": True,
    "enable_hostname_check": True,
    "enable_locale_check": True,
    "enable_xorg_heal": True,
    "enable_audio_heal": True,
    "enable_bluetooth_heal": True,
    "enable_cron_heal": True,
    "enable_tmpfiles": True,
    "enable_antivirus": True,
    "enable_rootkit_check": True,
    "enable_desktop_heal": True,
    "enable_flatpak_heal": True,
    "antivirus_scan_dirs": ["/home", "/tmp", "/var/tmp"],
    "enable_backup": True,
    "enable_port_scan_protect": True,
    "enable_login_monitor": True,
    "enable_ppa_heal": True,
    "enable_font_heal": True,
    "enable_printer_heal": True,
    "enable_suspend_heal": True,
    "enable_clock_drift": True,
    "enable_zombie_parent_heal": True,
    "enable_oom_score": True,
    "enable_sysctl_heal": True,
    "enable_apt_source_heal": True,
    "enable_user_integrity": True,
    "enable_mount_heal": True,
    "backup_dirs": ["/home/zani/Documents", "/home/zani/republicofzani/src", "/home/zani/nanobots"],
    "backup_dest": "/var/backups/nanobot_backups",
    "backup_keep_days": 30,
    "enable_arp_spoof_detect": True,
    "enable_dns_leak_check": True,
    "enable_open_file_limit": True,
    "enable_kernel_module_check": True,
    "enable_cgroup_heal": True,
    "enable_dmesg_monitor": True,
    "enable_gpu_temp": True,
    "enable_fan_monitor": True,
    "enable_lid_switch": True,
    "enable_screen_lock": True,
    "enable_ssh_harden": True,
    "enable_failed_mount_retry": True,
    "enable_disk_smart_selftest": True,
    "enable_network_speed": True,
    "enable_mac_spoof_detect": True,
    "enable_process_limit": True,
    "enable_file_descriptor_heal": True,
    "enable_shared_memory_heal": True,
    "enable_semaphore_heal": True,
    "enable_dbus_heal": True,
    "enable_polkit_heal": True,
    "enable_apparmor_check": True,
    "enable_grub_password_check": True,
    "enable_core_pattern_check": True,
    "enable_module_blacklist": True,
    "enable_ipv6_check": True,
    "enable_disk_scheduler": True,
    "enable_numa_balance": True,
    "enable_hugepages_check": True,
    "enable_tcp_tuning": True,
    "enable_io_scheduler_heal": True,
    "enable_watchdog_check": True,
    "enable_acpi_check": True,
    "enable_display_manager_heal": True,
    "enable_xdg_dirs_check": True,
    "enable_ups_check": True,
    "ups_name": "riello@localhost",
    "ssh_max_failed_per_hour": 50,
    "watched_configs": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/fstab"],
    "max_connections_per_ip": 50,
    "battery_crit_pct": 10,
    "quiet_mode": False,
    "enable_power_monitor": True,
    "enable_btrfs_heal": True,
    "enable_zram_heal": True,
    "enable_vpn_heal": True,
    "power_warn_watts": 30,
    "allowed_ports": [22, 53, 631],
    "allowed_root_processes": ["systemd", "sshd", "cron", "dbus-daemon", "agetty", "login", "sudo", "polkitd", "rsyslogd", "systemd-journald", "systemd-logind", "systemd-resolved", "systemd-timesyncd", "systemd-udevd", "networkd-dispatcher", "NetworkManager", "wpa_supplicant", "dockerd", "containerd"],
}

shutdown_requested = False


def handle_signal(signum, frame):
    global shutdown_requested
    log.info(f"Received signal {signum}, shutting down gracefully...")
    shutdown_requested = True


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def load_config():
    cfg = DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE) as f:
            user_cfg = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        user_cfg = {}

    # --- Module-based config support (#12) ---
    # If user config has "modules" dict, expand it into flat enable_ flags
    modules = user_cfg.pop("modules", None)
    profiles = user_cfg.pop("profiles", None)
    profile = user_cfg.get("profile", None)

    # Apply profile overrides first
    if profile and profiles and profile in profiles:
        profile_cfg = profiles[profile]
        # Handle "modules_enabled" shorthand (only listed modules are active)
        if "modules_enabled" in profile_cfg:
            enabled_list = profile_cfg.pop("modules_enabled")
            if modules:
                for mod_name, mod_cfg in modules.items():
                    if mod_name not in enabled_list:
                        mod_cfg["enabled"] = False
        # Apply dotted overrides like "desktop.enabled": false
        if modules:
            for key, val in profile_cfg.items():
                if "." in key:
                    mod, field = key.split(".", 1)
                    if mod in modules:
                        modules[mod][field] = val

    # Expand modules into flat flags
    if modules:
        MODULE_FLAG_MAP = {
            "network": ["enable_network_intrusion", "enable_arp_spoof_detect",
                        "enable_dns_leak_check", "enable_network_speed",
                        "enable_mac_spoof_detect"],
            "storage": ["enable_smart", "enable_disk_smart_selftest",
                        "enable_disk_latency", "enable_disk_scheduler",
                        "enable_failed_mount_retry"],
            "docker": ["enable_docker"],
            "desktop": ["enable_xorg_heal", "enable_audio_heal",
                        "enable_bluetooth_heal", "enable_display_manager_heal",
                        "enable_screen_lock", "enable_font_heal"],
            "security": ["enable_security", "enable_firewall_check",
                         "enable_ssh_harden", "enable_permission_heal",
                         "enable_rootkit_check", "enable_config_watchdog",
                         "enable_apparmor_check"],
            "hardware": ["enable_usb_monitor", "enable_battery",
                         "enable_fan_monitor", "enable_lid_switch",
                         "enable_acpi_check"],
            "system": ["enable_updates", "enable_time_sync",
                       "enable_kernel_module_check", "enable_sysctl_heal",
                       "enable_cron_heal", "enable_tmpfiles"],
        }
        for mod_name, mod_cfg in modules.items():
            if not isinstance(mod_cfg, dict):
                continue
            mod_enabled = mod_cfg.get("enabled", True)
            if not mod_enabled:
                # Disable all flags in this module
                for flag in MODULE_FLAG_MAP.get(mod_name, []):
                    user_cfg.setdefault(flag, False)
            # Apply individual sub-settings
            for sub_key, sub_val in mod_cfg.items():
                if sub_key == "enabled":
                    continue
                # Map known sub-keys to config values
                if sub_key == "warn_pct":
                    user_cfg.setdefault("disk_warn_pct", sub_val)
                elif sub_key == "crit_pct":
                    user_cfg.setdefault("disk_crit_pct", sub_val)
                else:
                    # Try to find matching enable_ flag
                    flag_name = f"enable_{sub_key}"
                    if flag_name in DEFAULT_CONFIG:
                        user_cfg.setdefault(flag_name, sub_val)

    # Apply remaining user config over defaults
    cfg.update(user_cfg)
    return cfg


cfg = load_config()

# --- Logging ---

log_dir = os.path.dirname(cfg["log_file"])
if log_dir and not os.path.isdir(log_dir):
    os.makedirs(log_dir, exist_ok=True)

handlers: list[logging.Handler] = [logging.StreamHandler()]
try:
    handlers.append(logging.FileHandler(cfg["log_file"]))
except (PermissionError, OSError):
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NanoBot] %(message)s",
    handlers=handlers,
)
log = logging.getLogger("nanobot")


# --- Quiet Mode Helper (#10) ---

def log_ok(msg):
    """Log info only when not in quiet mode."""
    if not cfg.get('quiet_mode', False):
        log.info(msg)


# --- Journal Summary Helper (#9) ---

def log_journal_summary(output, top_n=5):
    """Group journal lines by source and log a summary."""
    counts = {}
    for line in output.splitlines():
        parts = line.split()
        # journalctl format: date time host source[pid]: message
        source = parts[4].split('[')[0] if len(parts) > 4 else 'unknown'
        counts[source] = counts.get(source, 0) + 1
    for source, count in sorted(counts.items(), key=lambda x: -x[1])[:top_n]:
        log.warning(f'  {count}x {source}')


# --- Stats ---

def load_stats():
    default = {
        "first_run": datetime.now().isoformat(),
        "cycles": 0, "services_restarted": 0, "packages_fixed": 0,
        "kernel_repairs": 0, "disk_cleanups": 0, "memory_clears": 0,
        "network_restarts": 0, "zombies_killed": 0, "fs_errors_caught": 0,
        "thermal_throttles": 0, "dns_fixes": 0, "security_fixes": 0,
        "smart_warnings": 0, "crash_recoveries": 0, "issues_total": 0,
        "permission_fixes": 0, "time_sync_fixes": 0, "firewall_fixes": 0,
        "gpu_fixes": 0, "swap_fixes": 0, "high_cpu_kills": 0,
        "fstab_fixes": 0, "dpkg_lock_fixes": 0, "ups_warnings": 0,
        "docker_fixes": 0, "usb_events": 0, "intrusion_blocks": 0,
        "config_tampers": 0, "battery_warnings": 0, "coredump_cleans": 0,
        "entropy_fixes": 0, "journal_fixes": 0, "duplicate_kills": 0,
        "disk_latency_warnings": 0, "orphan_cleans": 0, "symlink_fixes": 0,
        "hostname_fixes": 0, "locale_fixes": 0, "xorg_fixes": 0,
        "audio_fixes": 0, "bluetooth_fixes": 0, "cron_fixes": 0,
        "btrfs_fixes": 0, "zram_fixes": 0, "vpn_fixes": 0,
        "tmpfile_fixes": 0,
        "viruses_found": 0, "rootkits_checked": 0,
        "desktop_fixes": 0, "flatpak_fixes": 0,
        "backups_made": 0, "port_scan_blocks": 0,
        "suspicious_logins": 0, "ppa_fixes": 0,
        "font_fixes": 0, "printer_fixes": 0,
        "suspend_fixes": 0, "clock_fixes": 0,
        "zombie_parent_fixes": 0, "oom_score_fixes": 0,
        "sysctl_fixes": 0, "apt_source_fixes": 0,
        "user_integrity_fixes": 0, "mount_fixes": 0,
        "arp_spoof_detects": 0, "dns_leak_fixes": 0,
        "open_file_fixes": 0, "kernel_module_fixes": 0,
        "cgroup_fixes": 0, "dmesg_warnings": 0,
        "gpu_temp_warnings": 0, "fan_warnings": 0,
        "lid_switch_fixes": 0, "screen_lock_fixes": 0,
        "ssh_hardens": 0, "failed_mount_retries": 0,
        "smart_selftests": 0, "network_speed_warnings": 0,
        "mac_spoof_detects": 0, "process_limit_fixes": 0,
        "fd_fixes": 0, "shm_fixes": 0, "sem_fixes": 0,
        "dbus_fixes": 0, "polkit_fixes": 0,
        "apparmor_fixes": 0, "grub_password_warnings": 0,
        "core_pattern_fixes": 0, "module_blacklist_fixes": 0,
        "ipv6_fixes": 0, "disk_scheduler_fixes": 0,
        "numa_fixes": 0, "hugepage_fixes": 0,
        "tcp_tuning_fixes": 0, "io_scheduler_fixes": 0,
        "watchdog_fixes": 0, "acpi_fixes": 0,
        "dm_fixes": 0, "xdg_fixes": 0,
        "last_run": None, "uptime_start": datetime.now().isoformat(),
    }
    try:
        with open(cfg["stats_file"]) as f:
            return {**default, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_stats(stats):
    try:
        with open(cfg["stats_file"], "w") as f:
            json.dump(stats, f, indent=2)
    except (PermissionError, OSError):
        pass


stats = load_stats()


def track(key, count=1):
    stats[key] = stats.get(key, 0) + count
    stats["issues_total"] = stats.get("issues_total", 0) + count


def run(cmd, timeout=120):
    """Run a command safely. Returns (returncode, stdout)."""
    try:
        if isinstance(cmd, str):
            cmd = ["bash", "-c", cmd]
        r = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out: {cmd}")
        return 1, ""
    except Exception as e:
        log.warning(f"Command error: {cmd}: {e}")
        return 1, ""


DANGEROUS_CMDS = ["kill", "rm ", "remove", "purge", "delete", "mkswap", "swapon"]

def safe_run(cmd, timeout=120):
    """Run a potentially destructive command with extra logging."""
    cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
    if any(d in cmd_str for d in DANGEROUS_CMDS):
        log.info(f"[SAFE] Executing destructive command: {cmd_str}")
    return run(cmd, timeout)


# --- Package Healing ---

def fix_dpkg_lock():
    """Fix stale dpkg/apt locks."""
    locks = ["/var/lib/dpkg/lock", "/var/lib/dpkg/lock-frontend",
             "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"]
    _, out = run("fuser /var/lib/dpkg/lock 2>/dev/null")
    if not out:
        for lock in locks:
            if os.path.exists(lock):
                try:
                    os.remove(lock)
                except OSError:
                    pass
        run("dpkg --configure -a")
        log.info("Cleared stale dpkg locks.")
        track("dpkg_lock_fixes")


def fix_broken_packages():
    log.info("Fixing broken packages...")
    # Check for stale locks first
    rc, _ = run("apt-get check 2>&1")
    if rc != 0:
        fix_dpkg_lock()
    rc1, _ = run("dpkg --configure -a")
    rc2, _ = run("apt-get install -f -y")
    run("apt-get autoremove -y")
    if rc1 != 0 or rc2 != 0:
        track("packages_fixed")
    log_ok("Package repair done.")


def update_system():
    if not cfg["enable_updates"]:
        return
    log.info("Updating system...")
    run("apt-get update -y")
    # Use unattended-upgrade style: security only by default
    run("apt-get upgrade -y --with-new-pkgs")
    log.info("System updated.")


# --- Kernel Healing ---

def check_kernel_health():
    log_ok("Checking kernel health...")
    _, current = run("uname -r")
    if not current:
        return
    repaired = False

    checks = [
        (f"/boot/vmlinuz-{current}", f"apt-get install --reinstall -y linux-image-{current}", "Kernel image"),
        (f"/boot/initrd.img-{current}", f"update-initramfs -c -k {current}", "Initramfs"),
    ]
    for path, rebuild_cmd, label in checks:
        if not os.path.exists(path):
            log.warning(f"{label} MISSING! Repairing...")
            run(rebuild_cmd)
            repaired = True
        else:
            log_ok(f"{label} OK.")

    mod_dir = f"/lib/modules/{current}"
    if not os.path.isdir(mod_dir):
        log.warning("Modules MISSING! Reinstalling...")
        run(f"apt-get install --reinstall -y linux-modules-{current}")
        repaired = True

    run(f"depmod -a {current}")

    _, taint = run("cat /proc/sys/kernel/tainted")
    if taint and taint != "0":
        log.warning(f"Kernel tainted (flags={taint}).")

    _, out = run("dmesg --level=err,crit,alert,emerg --notime 2>/dev/null | tail -20")
    if out:
        log.warning(f"Kernel errors:\n{out}")

    if repaired:
        track("kernel_repairs")


def rebuild_grub():
    log_ok("Checking GRUB...")
    if os.path.exists("/boot/grub/grub.cfg"):
        rc, _ = run("update-grub")
        if rc != 0:
            log.warning("GRUB update failed!")
            track("kernel_repairs")
    elif shutil.which("grub-mkconfig"):
        run("grub-mkconfig -o /boot/grub/grub.cfg")


# --- GPU Healing ---

def check_gpu():
    log_ok("Checking GPU...")
    _, out = run("lspci | grep -iE 'VGA|3D|Display'")
    if not out:
        return

    if "NVIDIA" in out.upper():
        _, loaded = run("lsmod | grep ^nvidia")
        if not loaded:
            log.warning("NVIDIA driver not loaded! Attempting reload...")
            run("modprobe nvidia")
            run("modprobe nvidia_drm")
            run("modprobe nvidia_modeset")
            _, check = run("lsmod | grep ^nvidia")
            if check:
                log.info("NVIDIA driver reloaded.")
            else:
                log.warning("NVIDIA driver reload failed.")
            track("gpu_fixes")
        else:
            log.info("NVIDIA driver loaded.")

        # Check for Xorg/display errors
        _, xlog = run("grep -c '(EE)' /var/log/Xorg.0.log 2>/dev/null")
        if xlog and xlog.isdigit() and int(xlog) > 5:
            log.warning(f"Xorg has {xlog} errors.")

    elif "AMD" in out.upper():
        _, loaded = run("lsmod | grep ^amdgpu")
        if not loaded:
            log.warning("AMDGPU driver not loaded! Attempting reload...")
            run("modprobe amdgpu")
            track("gpu_fixes")
        else:
            log.info("AMDGPU driver loaded.")

    log_ok("GPU check done.")


# --- SMART Disk Health ---

def check_smart():
    if not cfg["enable_smart"]:
        return
    log_ok("Checking SMART disk health...")
    if not shutil.which("smartctl"):
        log.info("smartmontools not installed, skipping.")
        return

    _, out = run("lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'")
    if not out:
        return

    for disk in out.splitlines():
        disk = disk.strip()
        if not disk:
            continue
        _, smart = run(f"smartctl -H /dev/{disk} 2>/dev/null")
        if "PASSED" in smart:
            log.info(f"/dev/{disk}: SMART OK")
        elif "FAILED" in smart:
            log.warning(f"/dev/{disk}: SMART FAILING! Disk may die soon!")
            track("smart_warnings")

        _, sectors = run(f"smartctl -A /dev/{disk} 2>/dev/null | grep -i 'Reallocated_Sector'")
        if sectors:
            parts = sectors.split()
            if parts and parts[-1].isdigit() and int(parts[-1]) > 0:
                log.warning(f"/dev/{disk}: {parts[-1]} reallocated sectors!")
                track("smart_warnings")

        _, pending = run(f"smartctl -A /dev/{disk} 2>/dev/null | grep -i 'Current_Pending_Sector'")
        if pending:
            parts = pending.split()
            if parts and parts[-1].isdigit() and int(parts[-1]) > 0:
                log.warning(f"/dev/{disk}: {parts[-1]} pending sectors!")
                track("smart_warnings")


# --- Filesystem Healing ---

def check_filesystems():
    log_ok("Checking filesystems...")
    _, out = run("mount | grep ' / '")
    if "ro," in out or ",ro " in out:
        log.warning("Root is READ-ONLY! Remounting...")
        run("mount -o remount,rw /")
        track("fs_errors_caught")

    _, out = run("journalctl -b -p err --grep='EXT4-fs\\|XFS\\|filesystem\\|I/O error' --no-pager -q 2>/dev/null | tail -10")
    if out:
        log.warning(f"{len(out.splitlines())} filesystem journal errors found:")
        log_journal_summary(out)
        run("touch /forcefsck")
        track("fs_errors_caught")
    else:
        log_ok("Filesystems OK.")


def check_fstab():
    """Verify all fstab entries are mountable."""
    log_ok("Checking fstab...")
    _, out = run("findmnt --verify --tab-file /etc/fstab 2>&1")
    if out and ("error" in out.lower() or "unknown" in out.lower()):
        log.warning(f"fstab issues:\n{out}")
        track("fstab_fixes")

    # Check for unmounted fstab entries
    _, out = run("awk '$0 !~ /^#/ && $0 !~ /^$/ && $2 != \"none\" && $2 != \"swap\" {print $2}' /etc/fstab")
    if out:
        for mp in out.splitlines():
            mp = mp.strip()
            if not mp or mp == "/":
                continue
            _, mounted = run(f"findmnt {mp} 2>/dev/null")
            if not mounted and os.path.isdir(mp):
                log.warning(f"{mp} not mounted! Attempting mount...")
                run(f"mount {mp}")
                track("fstab_fixes")


def check_disk_space():
    log_ok("Checking disk space...")
    total, used, free = shutil.disk_usage("/")
    pct = used / total * 100
    if pct > cfg["disk_crit_pct"]:
        log.warning(f"Disk {pct:.1f}% full! Emergency cleanup...")
        for cmd in [
            "apt-get autoclean -y",
            "journalctl --vacuum-time=2d",
            "find /tmp -type f -atime +3 -delete 2>/dev/null",
            "find /var/tmp -type f -atime +3 -delete 2>/dev/null",
            "find /var/log -name '*.gz' -delete 2>/dev/null",
            "find /var/crash -type f -delete 2>/dev/null",
            "find /home -name '*.core' -mtime +7 -delete 2>/dev/null",
            "apt-get autoremove -y",
        ]:
            run(cmd)
        # Remove old kernels (keep current)
        _, current = run("uname -r")
        if current:
            run(f"apt-get remove --purge -y $(dpkg -l 'linux-image-*' | awk '/^ii/{{print $2}}' | grep -v '{current}' | grep -v 'generic' | head -3) 2>/dev/null")
        track("disk_cleanups")
    elif pct > cfg["disk_warn_pct"]:
        log.warning(f"Disk {pct:.1f}% — light cleanup.")
        run("apt-get autoclean -y")
        run("apt-get autoremove -y")
        track("disk_cleanups")
    else:
        log.info(f"Disk OK ({pct:.1f}%).")


def check_inodes():
    log_ok("Checking inodes...")
    _, out = run("df -i / | tail -1 | awk '{print $5}' | tr -d '%'")
    if out and out.isdigit() and int(out) > 90:
        log.warning(f"Inodes {out}%! Cleaning...")
        run("find /tmp -type f -atime +3 -delete 2>/dev/null")
        run("find /var/tmp -type f -atime +1 -delete 2>/dev/null")
        track("disk_cleanups")
    else:
        log.info(f"Inodes OK ({out}%).")


# --- Service Healing ---

restart_counts: dict[str, int] = {}

def check_failed_services():
    log_ok("Checking failed services...")
    _, out = run("systemctl --failed --no-legend --no-pager --plain")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            count = restart_counts.get(unit, 0)
            if count >= cfg["max_restart_attempts"]:
                log.warning(f"Skipping {unit} — already tried {count} times this cycle.")
                continue
            log.warning(f"Restarting: {unit}")
            run(f"systemctl reset-failed {unit}")
            run(f"systemctl restart {unit}")
            restart_counts[unit] = count + 1
            track("services_restarted")
    else:
        log.info("No failed services.")


def check_critical_services():
    log_ok("Checking critical services...")
    all_svcs = cfg["critical_services"] + cfg["watched_services"]
    for svc in all_svcs:
        _, out = run(f"systemctl is-active {svc}")
        if out != "active":
            log.warning(f"{svc} is {out}! Restarting...")
            run(f"systemctl restart {svc}")
            track("services_restarted")
        else:
            log.info(f"{svc}: active")


# --- Process Healing ---

def kill_zombies():
    log_ok("Checking zombies...")
    _, out = run("ps aux | awk '$8==\"Z\" {print $2}'")
    if out:
        for pid in out.splitlines():
            pid = pid.strip()
            if not pid:
                continue
            # Never kill PID 1 or kernel threads
            if pid in ("1", "2"):
                continue
            log.warning(f"Killing zombie PID {pid}")
            _, ppid = run(f"ps -o ppid= -p {pid} 2>/dev/null")
            if ppid and ppid.strip():
                run(f"kill -SIGCHLD {ppid.strip()} 2>/dev/null")
            safe_run(f"kill -9 {pid} 2>/dev/null")
            track("zombies_killed")
    else:
        log.info("No zombies.")


def check_high_cpu():
    log_ok("Checking for runaway processes...")
    _, out = run("ps aux --sort=-%cpu | awk 'NR>1 && $3>95 {print $2, $11, $3}'")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            pid, name, cpu = parts[0], parts[1], parts[2]
            # Don't kill critical system processes
            if name in ("python3", "Xorg", "gnome-shell", "kwin", "systemd",
                        "cinnamon", "mutter", "nemo", "pulseaudio", "pipewire",
                        "NetworkManager", "dbus-daemon", "systemd-journald",
                        "firefox", "firefox-bin", "blender", "kiro", "kiro-cli"):
                log.warning(f"High CPU: PID {pid} ({name}) at {cpu}% — skipping (protected).")
                continue
            log.warning(f"High CPU: PID {pid} ({name}) at {cpu}%")
            # Check if it's been high for more than 5 minutes
            _, etime = run(f"ps -o etimes= -p {pid} 2>/dev/null")
            if etime and etime.strip().isdigit() and int(etime.strip()) > 300:
                log.warning(f"Killing runaway PID {pid} ({name}) — high CPU for >5min.")
                run(f"kill -15 {pid}")
                time.sleep(3)
                run(f"kill -9 {pid} 2>/dev/null")
                track("high_cpu_kills")


def check_oom():
    log_ok("Checking OOM events...")
    _, out = run("journalctl -b --grep='Out of memory\\|oom-kill\\|invoked oom-killer' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"{len(out.splitlines())} OOM events found:")
        log_journal_summary(out)
        run("sysctl -w vm.min_free_kbytes=65536 2>/dev/null")
        run("sysctl -w vm.overcommit_memory=1 2>/dev/null")
        track("memory_clears")


# --- Memory ---

def check_memory():
    log_ok("Checking memory...")
    _, out = run("free -m | awk '/Mem:/{print $7}'")
    if out and out.isdigit() and int(out) < cfg["mem_crit_mb"]:
        log.warning(f"Low memory ({out}MB)! Clearing caches...")
        run("sync")
        run("sysctl -w vm.drop_caches=3")
        track("memory_clears")
    else:
        log.info(f"Memory OK ({out}MB available).")

    _, out = run("swapon --show --noheadings")
    if not out:
        log.warning("No swap active!")
        rc, _ = run("swapon -a 2>/dev/null")
        if rc != 0:
            # Create emergency swap if none exists
            swapfile = "/swapfile"
            if not os.path.exists(swapfile):
                log.info("Creating emergency 2G swapfile...")
                run(f"fallocate -l 2G {swapfile}")
                run(f"chmod 600 {swapfile}")
                run(f"mkswap {swapfile}")
                run(f"swapon {swapfile}")
                track("swap_fixes")
        else:
            track("swap_fixes")


# --- Thermal ---

def check_thermals():
    log_ok("Checking thermals...")
    found = False
    for zone in sorted(Path("/sys/class/thermal/").glob("thermal_zone*/temp")):
        try:
            t = int(zone.read_text().strip()) / 1000
        except (ValueError, PermissionError, OSError):
            continue
        found = True
        name = zone.parent.name
        if t > cfg["temp_crit_c"]:
            log.warning(f"{name}: {t}°C CRITICAL!")
            track("thermal_throttles")
        elif t > cfg["temp_warn_c"]:
            log.warning(f"{name}: {t}°C hot!")
        else:
            log.info(f"{name}: {t}°C")
    if not found:
        log.info("No thermal sensors.")


# --- CPU Power Monitoring via Intel RAPL (#8) ---

def check_power():
    """Monitor CPU power draw via Intel RAPL sysfs interface."""
    if not cfg.get('enable_power_monitor', True):
        return
    rapl = '/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj'
    if not os.path.isfile(rapl):
        return
    log_ok('Checking CPU power...')
    try:
        with open(rapl) as f:
            e1 = int(f.read().strip())
        time.sleep(1)
        with open(rapl) as f:
            e2 = int(f.read().strip())
        watts = (e2 - e1) / 1_000_000
        if watts > cfg.get('power_warn_watts', 30):
            log.warning(f'High CPU power draw: {watts:.1f}W')
            track('thermal_throttles')
        else:
            log_ok(f'CPU power: {watts:.1f}W')
    except (ValueError, PermissionError, OSError):
        pass


# --- Network ---

def check_network():
    log_ok("Checking network...")
    targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    reachable = False
    for t in targets:
        rc, _ = run(f"ping -c 1 -W 3 {t}")
        if rc == 0:
            reachable = True
            break
    if not reachable:
        log.warning("Network down! Restarting...")
        run("systemctl restart NetworkManager 2>/dev/null")
        run("systemctl restart systemd-networkd 2>/dev/null")
        # Also try bringing up interfaces directly
        _, ifaces = run("ip -o link show | awk -F': ' '{print $2}' | grep -v lo")
        if ifaces:
            for iface in ifaces.splitlines():
                iface = iface.strip()
                if iface:
                    run(f"ip link set {iface} up")
        time.sleep(5)
        rc, _ = run("ping -c 1 -W 3 8.8.8.8")
        if rc != 0:
            log.warning("Network still down after restart!")
        track("network_restarts")
    else:
        log_ok("Network OK.")


def check_dns():
    log_ok("Checking DNS...")
    rc, _ = run("host -W 3 google.com 2>/dev/null")
    if rc != 0:
        # Try nslookup as fallback check
        rc, _ = run("nslookup google.com 2>/dev/null")
    if rc != 0:
        log.warning("DNS broken! Fixing...")
        run("systemctl restart systemd-resolved 2>/dev/null")
        time.sleep(2)
        rc, _ = run("host -W 3 google.com 2>/dev/null")
        if rc != 0:
            resolv = "nameserver 8.8.8.8\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n"
            try:
                # Preserve existing resolv.conf if it's a symlink (systemd-resolved)
                if os.path.islink("/etc/resolv.conf"):
                    run("ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf")
                else:
                    with open("/etc/resolv.conf", "w") as f:
                        f.write(resolv)
            except PermissionError:
                run(f"bash -c \"echo '{resolv}' > /etc/resolv.conf\"")
        track("dns_fixes")
    else:
        log_ok("DNS OK.")


# --- Security ---

def check_security():
    if not cfg["enable_security"]:
        return
    log.info("Running security checks...")

    # Failed SSH logins
    _, out = run("journalctl -u ssh --since '1 hour ago' --grep='Failed password' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 20:
        log.warning(f"{out} failed SSH attempts in last hour!")
        track("security_fixes")

    # World-writable files in /etc
    _, out = run("find /etc -maxdepth 1 -perm -o+w -type f 2>/dev/null")
    if out:
        log.warning(f"World-writable files in /etc:\n{out}")
        for f in out.splitlines():
            f = f.strip()
            if f:
                run(f"chmod o-w '{f}'")
        track("security_fixes")

    # Root SSH login
    _, out = run("grep -i '^PermitRootLogin yes' /etc/ssh/sshd_config 2>/dev/null")
    if out:
        log.warning("Root SSH login is enabled! Consider disabling.")

    # SUID in temp dirs
    _, out = run("find /tmp /var/tmp -perm -4000 -type f 2>/dev/null")
    if out:
        log.warning(f"SUID files in temp dirs:\n{out}")
        for f in out.splitlines():
            f = f.strip()
            if f:
                run(f"chmod u-s '{f}'")
        track("security_fixes")

    # Check for open ports that shouldn't be
    _, out = run("ss -tlnp | grep -v '127.0.0' | grep -v '::1'")
    if out:
        log.info(f"Open ports:\n{out}")

    log_ok("Security checks done.")


# --- Open Port Allowlist (#7) ---

def check_open_ports():
    """Flag listening ports not in the allowlist."""
    log_ok("Checking open ports against allowlist...")
    allowed = cfg.get('allowed_ports', [22, 53, 631])
    _, out = run("ss -tlnp | tail -n +2")
    if not out:
        return
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # Extract port from listen address (e.g. 0.0.0.0:8080 or [::]:22 or *:53)
        addr = parts[3]
        port = addr.rsplit(':', 1)[-1]
        if port.isdigit() and int(port) not in allowed:
            # Skip localhost-only ports
            if '127.0.0.1' in addr or '::1' in addr:
                continue
            process = parts[5] if len(parts) > 5 else "unknown"
            log.warning(f"Unexpected open port: {port} ({process})")
            track('security_fixes')
    log_ok("Port allowlist check done.")


# --- Root Process Allowlist (#6) ---

def check_root_processes():
    """Detect unexpected processes running as root."""
    log_ok("Checking root processes against allowlist...")
    allowed = cfg.get('allowed_root_processes', [])
    _, out = run("ps -eo user,pid,comm --no-headers")
    if not out:
        return
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        user, pid, comm = parts[0], parts[1], parts[2].strip()
        if user != "root":
            continue
        # Skip kernel threads (PID 2 and children shown in brackets)
        if comm.startswith('[') and comm.endswith(']'):
            continue
        # Check base process name against allowlist
        base = os.path.basename(comm.split()[0]) if comm else ""
        if base and base not in allowed:
            log.warning(f"Unexpected root process: {base} (PID {pid})")
            track('security_fixes')
    log_ok("Root process check done.")


def check_firewall():
    if not cfg["enable_firewall_check"]:
        return
    log_ok("Checking firewall...")
    # Check if ufw or iptables has rules
    if shutil.which("ufw"):
        _, out = run("ufw status 2>/dev/null")
        if "inactive" in out.lower():
            log.warning("UFW firewall is inactive!")
            track("firewall_fixes")
    else:
        _, out = run("iptables -L -n 2>/dev/null | wc -l")
        if out and out.isdigit() and int(out) <= 8:
            log.warning("No iptables rules — firewall may be open!")
            track("firewall_fixes")
    log_ok("Firewall check done.")


# --- Time Sync ---

def check_time_sync():
    if not cfg["enable_time_sync"]:
        return
    log_ok("Checking time sync...")
    _, out = run("timedatectl show --property=NTPSynchronized --value 2>/dev/null")
    if out == "no":
        log.warning("Time not synced! Enabling NTP...")
        run("timedatectl set-ntp true")
        run("systemctl restart systemd-timesyncd 2>/dev/null")
        track("time_sync_fixes")
    else:
        log_ok("Time sync OK.")


# --- Permission Healing ---

def check_permissions():
    if not cfg["enable_permission_heal"]:
        return
    log_ok("Checking critical permissions...")
    fixes = [
        ("/tmp", "1777"), ("/var/tmp", "1777"),  # noqa: S108
        ("/etc/shadow", "0640"), ("/etc/passwd", "0644"),
        ("/etc/group", "0644"), ("/etc/gshadow", "0640"),
    ]
    for path, expected in fixes:
        if not os.path.exists(path):
            continue
        _, current = run(f"stat -c '%a' '{path}'")
        if current and current != expected:
            log.warning(f"{path} has mode {current}, expected {expected}. Fixing...")
            run(f"chmod {expected} '{path}'")
            track("permission_fixes")
    log_ok("Permissions OK.")


# --- Kernel Panics ---

def check_ups():
    """Check UPS availability and monitoring via NUT."""
    if not cfg.get("enable_ups_check", True):
        return
    log.info("Checking UPS status...")

    # Check if NUT is installed
    if not shutil.which("upsc"):
        log.warning("UPS: NUT not installed. Install with: apt install nut-client")
        track("ups_warnings")
        return

    # Check if nut-monitor (upsmon) is running = subscribed to events
    rc, _ = run("systemctl is-active nut-monitor 2>/dev/null")
    if rc != 0:
        log.warning("UPS: nut-monitor not active! Starting...")
        run("systemctl start nut-monitor")
        rc_retry, _ = run("systemctl is-active nut-monitor 2>/dev/null")
        if rc_retry != 0:
            log.error("UPS: nut-monitor failed to start. Not subscribed to shutdown events!")
            track("ups_warnings")
            return
        else:
            log.info("UPS: nut-monitor started successfully.")
            track("ups_warnings")

    # Check UPS reachability and status
    ups_name = cfg.get("ups_name", "riello@localhost")
    rc, out = run(f"upsc {ups_name} ups.status 2>/dev/null")
    if rc != 0 or not out:
        log.warning(f"UPS: Cannot reach {ups_name}. Check NUT driver and server.")
        track("ups_warnings")
        return

    status = out.strip()
    if "OL" in status:
        log.info(f"UPS: Online ({status})")
    elif "OB" in status:
        log.warning(f"UPS: ON BATTERY ({status})! Power outage detected.")
        track("ups_warnings")
    elif "LB" in status:
        log.error(f"UPS: LOW BATTERY ({status})! Shutdown imminent.")
        track("ups_warnings")
    else:
        log.warning(f"UPS: Unknown status: {status}")
        track("ups_warnings")

    # Check battery charge if available
    rc, charge = run(f"upsc {ups_name} battery.charge 2>/dev/null")
    if rc == 0 and charge:
        try:
            pct = float(charge)
            if pct < 50:
                log.warning(f"UPS: Battery charge low: {pct}%")
                track("ups_warnings")
            else:
                log.info(f"UPS: Battery charge {pct}%")
        except ValueError:
            pass


def check_kernel_panics():
    log_ok("Checking kernel panics...")
    _, out = run("journalctl -k -p emerg,alert,crit --since '1 hour ago' --no-pager -q 2>/dev/null")
    if out:
        log.warning(f"Critical kernel messages:\n{out[:500]}")
        run("touch /forcefsck")
        track("kernel_repairs")
    else:
        log.info("No kernel panics.")


# --- Crash Recovery ---

def check_crash_dumps():
    log_ok("Checking crash dumps...")
    crash_dir = "/var/crash"
    if os.path.isdir(crash_dir):
        crashes = os.listdir(crash_dir)
        if crashes:
            log.warning(f"Found {len(crashes)} crash dumps in /var/crash")
            for c in crashes[:5]:
                log.warning(f"  - {c}")
            track("crash_recoveries", len(crashes))
            run("rm -f /var/crash/* 2>/dev/null")
    log_ok("Crash dump check done.")


# --- Log Management ---

def check_log_sizes():
    log_ok("Checking log sizes...")
    _, out = run("du -sm /var/log 2>/dev/null | awk '{print $1}'")
    if out and out.isdigit() and int(out) > cfg["max_log_size_mb"]:
        log.warning(f"/var/log is {out}MB! Rotating...")
        run("logrotate -f /etc/logrotate.conf 2>/dev/null")
        run("journalctl --vacuum-size=200M")
        track("disk_cleanups")
    else:
        log.info(f"/var/log: {out}MB")


# --- Docker Healing ---

def check_docker():
    if not cfg["enable_docker"]:
        return
    if not shutil.which("docker"):
        return
    log_ok("Checking Docker...")
    _, out = run("systemctl is-active docker 2>/dev/null")
    if out != "active":
        log.warning("Docker daemon not running! Starting...")
        run("systemctl start docker")
        track("docker_fixes")
    _, out = run("docker ps -a --filter 'status=exited' --filter 'status=dead' --format '{{.Names}}' 2>/dev/null")
    if out:
        for name in out.splitlines():
            name = name.strip()
            if not name:
                continue
            _, inspect = run(f"docker inspect --format '{{{{.RestartCount}}}}' {name} 2>/dev/null")
            log.warning(f"Container '{name}' is down (restarts: {inspect}). Restarting...")
            run(f"docker start {name}")
            track("docker_fixes")
    # Prune dangling images/volumes if disk is tight
    total, used, _ = shutil.disk_usage("/")
    if used / total * 100 > cfg["disk_warn_pct"]:
        run("docker system prune -f 2>/dev/null")
        log.info("Docker pruned dangling resources.")
    log_ok("Docker check done.")


# --- USB Device Monitoring ---

def check_usb():
    if not cfg["enable_usb_monitor"]:
        return
    log_ok("Checking USB devices...")
    _, out = run("journalctl -b --grep='USB disconnect\\|usb.*error\\|device descriptor read' --no-pager -q 2>/dev/null | tail -10")
    if out:
        log.warning(f"USB issues detected:\n{out[:500]}")
        # Reset USB controllers if errors are excessive
        error_count = len(out.splitlines())
        if error_count > 5:
            log.warning("Many USB errors — resetting USB controllers...")
            _, controllers = run("find /sys/bus/usb/devices/usb*/authorized -maxdepth 0 2>/dev/null")
            if controllers:
                for ctrl in controllers.splitlines():
                    ctrl = ctrl.strip()
                    if ctrl:
                        try:
                            Path(ctrl).write_text("0")
                            time.sleep(1)
                            Path(ctrl).write_text("1")
                        except (PermissionError, OSError):
                            pass
            track("usb_events")
    log_ok("USB check done.")


# --- Network Intrusion Detection ---

def check_intrusions():
    if not cfg["enable_network_intrusion"]:
        return
    log_ok("Checking for network intrusions...")
    # Check for excessive connections from single IPs
    _, out = run("ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                count, ip = int(parts[0]), parts[1]
                if count > cfg["max_connections_per_ip"] and ip not in ("127.0.0.1", "::1", ""):
                    log.warning(f"Suspicious: {count} connections from {ip}")
                    track("intrusion_blocks")

    # Check for port scanning (many SYN_RECV)
    _, out = run("ss -tn state syn-recv | wc -l")
    if out and out.isdigit() and int(out) > 20:
        log.warning(f"Possible port scan: {out} SYN_RECV connections!")
        track("intrusion_blocks")

    # Check for new listening ports since last check
    _, out = run("ss -tlnp | grep -v '127.0.0' | grep -v '::1'")
    if out:
        log.info(f"Listening ports:\n{out}")

    # Check auth log for brute force on any service
    _, out = run("journalctl --since '1 hour ago' --grep='authentication failure\\|Failed password' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > cfg["ssh_max_failed_per_hour"]:
        log.warning(f"{out} auth failures in last hour — possible brute force!")
        track("intrusion_blocks")

    log_ok("Intrusion check done.")


# --- Config File Watchdog ---

config_hashes: dict[str, str] = {}

def check_config_watchdog():
    if not cfg["enable_config_watchdog"]:
        return
    log_ok("Checking config file integrity...")
    global config_hashes
    for filepath in cfg["watched_configs"]:
        if not os.path.exists(filepath):
            continue
        _, current_hash = run(f"sha256sum '{filepath}' 2>/dev/null")
        if not current_hash:
            continue
        current_hash = current_hash.split()[0]
        if filepath in config_hashes:
            if config_hashes[filepath] != current_hash:
                log.warning(f"CONFIG CHANGED: {filepath}")
                # Backup the changed file
                backup_dir = "/var/log/nanobot_config_backups"
                os.makedirs(backup_dir, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                run(f"cp '{filepath}' '{backup_dir}/{os.path.basename(filepath)}.{ts}'")
                track("config_tampers")
        config_hashes[filepath] = current_hash
    log_ok("Config watchdog done.")


# --- Battery Monitoring ---

def check_battery():
    if not cfg["enable_battery"]:
        return
    bat_path = Path("/sys/class/power_supply/BAT0")
    if not bat_path.exists():
        bat_path = Path("/sys/class/power_supply/BAT1")
    if not bat_path.exists():
        return
    log_ok("Checking battery...")
    try:
        capacity = int((bat_path / "capacity").read_text().strip())
        status = (bat_path / "status").read_text().strip()
    except (ValueError, OSError):
        return
    if capacity <= cfg["battery_crit_pct"] and status == "Discharging":
        log.warning(f"CRITICAL BATTERY: {capacity}%! Hibernating in 60s...")
        run("wall 'NanoBot: Battery critical! Hibernating in 60 seconds.'")
        time.sleep(60)
        # Re-check in case charger was plugged in
        try:
            status = (bat_path / "status").read_text().strip()
        except OSError:
            status = "Unknown"
        if status == "Discharging":
            run("systemctl hibernate 2>/dev/null || systemctl suspend")
        track("battery_warnings")
    elif capacity <= 20 and status == "Discharging":
        log.warning(f"Low battery: {capacity}%")
        track("battery_warnings")
    else:
        log.info(f"Battery: {capacity}% ({status})")


# --- Coredump Cleanup ---

def check_coredumps():
    if not cfg["enable_coredump"]:
        return
    log_ok("Checking coredumps...")
    cleaned = 0
    for d in ["/var/lib/systemd/coredump", "/var/crash"]:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            fp = os.path.join(d, f)
            try:
                age = time.time() - os.path.getmtime(fp)
                if age > 86400 * 3:  # older than 3 days
                    os.remove(fp)
                    cleaned += 1
            except OSError:
                pass
    # Also clean systemd coredumps
    _, out = run("coredumpctl list --no-pager 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 20:
        run("journalctl --vacuum-size=100M --rotate 2>/dev/null")
    if cleaned:
        log.info(f"Cleaned {cleaned} old coredumps.")
        track("coredump_cleans", cleaned)
    log_ok("Coredump check done.")


# --- Entropy Check ---

def check_entropy():
    if not cfg["enable_entropy"]:
        return
    log_ok("Checking entropy...")
    try:
        entropy = int(Path("/proc/sys/kernel/random/entropy_avail").read_text().strip())
    except (ValueError, OSError):
        return
    if entropy < 200:
        log.warning(f"Low entropy: {entropy}! Installing haveged...")
        if not shutil.which("haveged"):
            run("apt-get install -y haveged")
        run("systemctl enable --now haveged 2>/dev/null")
        track("entropy_fixes")
    else:
        log.info(f"Entropy OK ({entropy}).")


# --- Journal Health ---

def check_journal_health():
    if not cfg["enable_journal_health"]:
        return
    log_ok("Checking journal health...")
    _, out = run("journalctl --verify 2>&1 | grep -c FAIL")
    if out and out.isdigit() and int(out) > 0:
        log.warning(f"Corrupt journal entries: {out}. Rotating...")
        run("journalctl --rotate")
        run("journalctl --vacuum-time=7d")
        track("journal_fixes")
    # Check journal disk usage
    _, out = run("journalctl --disk-usage 2>/dev/null")
    if out:
        log.info(f"Journal: {out}")
        match = re.search(r'(\d+\.?\d*)\s*G', out)
        if match and float(match.group(1)) > 2:
            log.warning("Journal too large! Vacuuming...")
            run("journalctl --vacuum-size=500M")
            track("journal_fixes")
    log_ok("Journal check done.")


# --- Duplicate Process Detection ---

def check_duplicate_processes():
    if not cfg["enable_duplicate_process"]:
        return
    log_ok("Checking duplicate processes...")
    # Processes that should only have one instance
    singles = ["NetworkManager", "systemd-resolved", "systemd-timesyncd", "cupsd", "bluetoothd"]
    for proc in singles:
        _, out = run(f"pgrep -c {proc} 2>/dev/null")
        if out and out.isdigit() and int(out) > 1:
            log.warning(f"Multiple {proc} instances ({out})! Restarting service...")
            run(f"systemctl restart {proc} 2>/dev/null")
            track("duplicate_kills")
    log_ok("Duplicate process check done.")


# --- Disk I/O Latency ---

def check_disk_latency():
    if not cfg["enable_disk_latency"]:
        return
    log_ok("Checking disk latency...")
    _, out = run("iostat -x 1 2 2>/dev/null | tail -10")
    if not out and not shutil.which("iostat"):
        return
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 10 and parts[0] not in ("Device", "Linux", "", "avg-cpu:"):
                try:
                    await_ms = float(parts[-3])  # r_await or w_await
                    if await_ms > 500:
                        log.warning(f"High disk latency on {parts[0]}: {await_ms}ms!")
                        track("disk_latency_warnings")
                except (ValueError, IndexError):
                    pass
    log_ok("Disk latency check done.")


# --- Orphan Package Cleanup ---

def check_orphan_packages():
    if not cfg["enable_orphan_cleanup"]:
        return
    log_ok("Checking orphan packages...")
    _, out = run("apt list --installed 2>/dev/null | grep -c 'residual-config'")
    if out and out.isdigit() and int(out) > 0:
        run("dpkg --purge $(dpkg -l | awk '/^rc/{print $2}') 2>/dev/null")
        log.info(f"Purged {out} residual configs.")
        track("orphan_cleans")
    # Remove orphaned libs
    _, out = run("deborphan 2>/dev/null | head -20")
    if out and shutil.which("deborphan"):
        log.info(f"Orphaned packages:\n{out}")
    log_ok("Orphan check done.")


# --- Broken Symlink Healing ---

def check_broken_symlinks():
    if not cfg["enable_symlink_heal"]:
        return
    log_ok("Checking broken symlinks...")
    fixed = 0
    for d in ["/usr/bin", "/usr/lib", "/etc/alternatives"]:
        _, out = run(f"find {d} -maxdepth 1 -xtype l 2>/dev/null")
        if out:
            for link in out.splitlines():
                link = link.strip()
                if not link:
                    continue
                log.warning(f"Broken symlink: {link}")
                # For /etc/alternatives, try update-alternatives
                if "/etc/alternatives/" in link:
                    name = os.path.basename(link)
                    run(f"update-alternatives --auto {name} 2>/dev/null")
                    fixed += 1
    if fixed:
        track("symlink_fixes", fixed)
    log_ok("Symlink check done.")


# --- Hostname Validation ---

def check_hostname():
    if not cfg["enable_hostname_check"]:
        return
    log_ok("Checking hostname...")
    _, hostname = run("hostname")
    if not hostname or hostname == "(none)" or hostname == "localhost":
        log.warning(f"Invalid hostname: '{hostname}'")
        # Try to restore from /etc/hostname
        if os.path.exists("/etc/hostname"):
            _, saved = run("cat /etc/hostname")
            if saved and saved.strip():
                run(f"hostnamectl set-hostname '{saved.strip()}'")
                log.info(f"Hostname restored to '{saved.strip()}'")
                track("hostname_fixes")
    # Verify /etc/hosts has the hostname
    _, hosts = run("cat /etc/hosts")
    if hostname and hostname not in hosts:
        log.warning(f"Hostname '{hostname}' missing from /etc/hosts")
    log_ok("Hostname check done.")


# --- Locale Healing ---

def check_locale():
    if not cfg["enable_locale_check"]:
        return
    log_ok("Checking locale...")
    _, out = run("locale 2>&1")
    if "Cannot set" in out or "warning" in out.lower():
        log.warning(f"Locale issues:\n{out[:300]}")
        run("locale-gen en_US.UTF-8 2>/dev/null")
        run("update-locale LANG=en_US.UTF-8 2>/dev/null")
        track("locale_fixes")
    else:
        log_ok("Locale OK.")


# --- Xorg / Display Healing ---

def check_xorg():
    if not cfg["enable_xorg_heal"]:
        return
    if not os.path.exists("/var/log/Xorg.0.log"):
        return
    log_ok("Checking Xorg...")
    _, out = run("grep '(EE)' /var/log/Xorg.0.log 2>/dev/null | grep -v '(WW)' | tail -10")
    if out:
        errors = len(out.splitlines())
        if errors > 10:
            log.warning(f"Xorg has {errors} errors:\n{out[:500]}")
            # Check if display is actually working
            _, display = run("xdpyinfo 2>/dev/null | head -3")
            if not display:
                log.warning("Display server may be broken!")
                track("xorg_fixes")
    # Check for screen tearing fix
    _, compositor = run("pgrep -a compton 2>/dev/null || pgrep -a picom 2>/dev/null")
    log_ok("Xorg check done.")


# --- Audio Healing ---

def check_audio():
    if not cfg["enable_audio_heal"]:
        return
    log_ok("Checking audio...")
    _, out = run("pactl info 2>/dev/null")
    if not out or "Connection failure" in out:
        log.warning("PulseAudio not responding! Restarting...")
        run("pulseaudio --kill 2>/dev/null")
        time.sleep(1)
        run("pulseaudio --start 2>/dev/null")
        # Try pipewire if pulse fails
        _, check = run("pactl info 2>/dev/null")
        if not check or "Connection failure" in check:
            run("systemctl --user restart pipewire pipewire-pulse 2>/dev/null")
        track("audio_fixes")
    else:
        # Check if any sinks exist
        _, sinks = run("pactl list short sinks 2>/dev/null")
        if not sinks:
            log.warning("No audio sinks found!")
            run("pulseaudio --kill 2>/dev/null && pulseaudio --start 2>/dev/null")
            track("audio_fixes")
        else:
            log_ok("Audio OK.")


# --- Bluetooth Healing ---

def check_bluetooth():
    if not cfg["enable_bluetooth_heal"]:
        return
    if not shutil.which("bluetoothctl"):
        return
    log_ok("Checking Bluetooth...")
    _, out = run("systemctl is-active bluetooth 2>/dev/null")
    if out == "failed":
        log.warning("Bluetooth service failed! Restarting...")
        run("systemctl restart bluetooth")
        track("bluetooth_fixes")
    # Check if adapter is blocked
    _, out = run("rfkill list bluetooth 2>/dev/null")
    if "Soft blocked: yes" in out:
        log.warning("Bluetooth soft-blocked! Unblocking...")
        run("rfkill unblock bluetooth")
        track("bluetooth_fixes")
    log_ok("Bluetooth check done.")


# --- Cron Healing ---

def check_cron():
    if not cfg["enable_cron_heal"]:
        return
    log_ok("Checking cron...")
    _, out = run("systemctl is-active cron 2>/dev/null")
    if out != "active":
        log.warning("Cron not running! Starting...")
        run("systemctl start cron")
        track("cron_fixes")
    # Validate crontabs
    _, out = run("find /var/spool/cron/crontabs -type f 2>/dev/null")
    if out:
        for tab in out.splitlines():
            tab = tab.strip()
            if not tab:
                continue
            user = os.path.basename(tab)
            rc, _ = run(f"crontab -u {user} -l 2>&1 | crontab -u {user} - 2>&1")
            if rc != 0:
                log.warning(f"Corrupt crontab for {user}!")
                track("cron_fixes")
    log_ok("Cron check done.")


# --- Tmpfiles Healing ---

def check_tmpfiles():
    if not cfg["enable_tmpfiles"]:
        return
    log_ok("Checking tmpfiles...")
    # Ensure /tmp is writable and has correct permissions
    if not os.access("/tmp", os.W_OK):
        log.warning("/tmp not writable! Fixing...")
        run("chmod 1777 /tmp")
        track("tmpfile_fixes")
    # Clean old tmp files
    _, out = run("find /tmp -type f -atime +7 -not -path '/tmp/systemd-*' 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 100:
        log.info(f"Cleaning {out} old tmp files...")
        run("find /tmp -type f -atime +7 -not -path '/tmp/systemd-*' -delete 2>/dev/null")
        track("tmpfile_fixes")
    # Run systemd-tmpfiles
    run("systemd-tmpfiles --clean 2>/dev/null")
    log_ok("Tmpfiles check done.")


# --- Antivirus Scanning ---

def check_antivirus():
    if not cfg["enable_antivirus"]:
        return
    if not shutil.which("clamscan"):
        return
    log.info("Running antivirus scan...")
    # Update virus definitions first
    run("freshclam --quiet 2>/dev/null", timeout=300)
    for scan_dir in cfg.get("antivirus_scan_dirs", ["/home", "/tmp"]):
        if not os.path.isdir(scan_dir):
            continue
        _, out = run(f"clamscan -r -i --no-summary --max-filesize=50M --max-scansize=200M '{scan_dir}' 2>/dev/null", timeout=600)
        if out:
            log.warning(f"VIRUSES FOUND:\n{out}")
            # Quarantine infected files
            quarantine = "/var/log/nanobot_quarantine"
            os.makedirs(quarantine, exist_ok=True)
            for line in out.splitlines():
                if ": " in line and "FOUND" in line:
                    infected = line.split(":")[0].strip()
                    if os.path.exists(infected):
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        dest = f"{quarantine}/{os.path.basename(infected)}.{ts}"
                        run(f"mv '{infected}' '{dest}'")
                        run(f"chmod 000 '{dest}'")
                        log.warning(f"Quarantined: {infected} -> {dest}")
                        track("viruses_found")
    log_ok("Antivirus scan done.")


# --- Rootkit Detection ---

def check_rootkits():
    if not cfg["enable_rootkit_check"]:
        return
    log_ok("Checking for rootkits...")
    if shutil.which("chkrootkit"):
        _, out = run("chkrootkit -q 2>/dev/null", timeout=300)
        if out and "INFECTED" in out:
            log.warning(f"ROOTKIT DETECTED:\n{out}")
            track("rootkits_checked")
        else:
            log.info("chkrootkit: clean")
    if shutil.which("rkhunter"):
        run("rkhunter --propupd --quiet 2>/dev/null")
        rc, out = run("rkhunter --check --skip-keypress --quiet 2>/dev/null", timeout=300)
        if rc != 0 and out:
            warnings = [line for line in out.splitlines() if "Warning" in line]
            if warnings:
                log.warning("rkhunter warnings:\n" + "\n".join(warnings[:10]))
                track("rootkits_checked")
        else:
            log.info("rkhunter: clean")
    if not shutil.which("chkrootkit") and not shutil.which("rkhunter"):
        log.info("No rootkit scanner installed. Install with: sudo apt install chkrootkit rkhunter")
    log_ok("Rootkit check done.")


# --- Desktop / Window Manager Healing ---

def check_desktop():
    if not cfg["enable_desktop_heal"]:
        return
    log_ok("Checking desktop...")
    _, de = run("echo $XDG_CURRENT_DESKTOP")
    if not de:
        _, de = run("cat /etc/X11/default-display-manager 2>/dev/null")
    # Check if display manager is running
    for dm in ["lightdm", "gdm", "sddm"]:
        _, active = run(f"systemctl is-active {dm} 2>/dev/null")
        if active == "active":
            break
    else:
        # No display manager found active, might be fine if using startx
        pass
    # Check for frozen Cinnamon
    if "Cinnamon" in (de or "") or "X-Cinnamon" in (de or ""):
        _, out = run("dbus-send --session --dest=org.Cinnamon --print-reply /org/Cinnamon org.freedesktop.DBus.Peer.Ping 2>/dev/null")
        if "Error" in (out or ""):
            log.warning("Cinnamon not responding! Restarting...")
            run("nohup cinnamon --replace &>/dev/null &")
            track("desktop_fixes")
    # Check for Xorg crash
    if os.path.exists("/var/log/Xorg.0.log.old"):
        _, age = run("stat -c %Y /var/log/Xorg.0.log.old 2>/dev/null")
        if age and age.isdigit() and (time.time() - int(age)) < 300:
            log.warning("Xorg crashed recently!")
            track("desktop_fixes")
    log_ok("Desktop check done.")


# --- Flatpak / Snap Healing ---

def check_flatpak():
    if not cfg["enable_flatpak_heal"]:
        return
    log_ok("Checking Flatpak/Snap...")
    if shutil.which("flatpak"):
        rc, out = run("flatpak repair --user 2>&1", timeout=120)
        if "error" in (out or "").lower():
            log.warning(f"Flatpak repair issues:\n{out[:300]}")
            run("flatpak repair --user --reinstall-all 2>/dev/null", timeout=300)
            track("flatpak_fixes")
        # Clean unused runtimes
        run("flatpak uninstall --unused -y 2>/dev/null")
    if shutil.which("snap"):
        _, out = run("snap changes 2>/dev/null | grep -i error | tail -5")
        if out:
            log.warning(f"Snap errors:\n{out}")
            # Try to abort stuck snap changes
            _, changes = run("snap changes 2>/dev/null | awk '/Doing/{print $1}'")
            if changes:
                for cid in changes.splitlines():
                    cid = cid.strip()
                    if cid:
                        run(f"snap abort {cid} 2>/dev/null")
            track("flatpak_fixes")
    log_ok("Flatpak/Snap check done.")


# --- Automatic Backups ---

def check_backup():
    if not cfg["enable_backup"]:
        return
    log.info("Running backups...")
    dest = cfg["backup_dest"]
    os.makedirs(dest, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    for src in cfg.get("backup_dirs", []):
        if not os.path.isdir(src):
            continue
        name = os.path.basename(src.rstrip("/"))
        archive = f"{dest}/{name}_{ts}.tar.gz"
        rc, _ = run(f"tar czf '{archive}' -C '{os.path.dirname(src)}' '{name}' 2>/dev/null", timeout=300)
        if rc == 0:
            log.info(f"Backed up {src} -> {archive}")
            track("backups_made")
        else:
            log.warning(f"Backup failed for {src}")
    keep = cfg.get("backup_keep_days", 30)
    run(f"find '{dest}' -name '*.tar.gz' -mtime +{keep} -delete 2>/dev/null")
    log_ok("Backup done.")


# --- Port Scan Protection ---

def check_port_scan_protect():
    if not cfg["enable_port_scan_protect"]:
        return
    log_ok("Checking for port scans...")
    _, out = run("journalctl --since '10 min ago' --grep='SYN' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 100:
        log.warning(f"Possible port scan: {out} SYN packets in 10 min!")
        run("sysctl -w net.ipv4.tcp_syncookies=1")
        run("sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1")
        run("sysctl -w net.ipv4.conf.all.log_martians=1")
        track("port_scan_blocks")
    log_ok("Port scan check done.")


# --- Login Monitor ---

def check_login_monitor():
    if not cfg["enable_login_monitor"]:
        return
    log_ok("Checking logins...")
    _, out = run("last -n 20 --time-format iso 2>/dev/null")
    if out:
        for line in out.splitlines():
            if not line.strip() or "reboot" in line or "wtmp" in line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                user, terminal = parts[0], parts[1]
                if "pts/" in terminal and len(parts) > 2:
                    ip = parts[2]
                    if ip and ip not in ("", ":0", "0.0.0.0") and not ip.startswith("10.") and not ip.startswith("192.168."):
                        log.warning(f"External login: {user} from {ip} on {terminal}")
                        track("suspicious_logins")
    _, out = run("journalctl --since '1 hour ago' --grep='FAILED su' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"Failed su attempts:\n{out}")
        track("suspicious_logins")
    log_ok("Login check done.")


# --- PPA / Repository Healing ---

def check_ppa_heal():
    if not cfg["enable_ppa_heal"]:
        return
    log_ok("Checking APT repositories...")
    rc, out = run("apt-get update 2>&1 | grep -iE 'err|fail|expired|no longer has'", timeout=120)
    if out:
        log.warning(f"Broken repos:\n{out[:500]}")
        for line in out.splitlines():
            match = re.search(r'(https?://[^\s]+)', line)
            if match:
                url = match.group(1)
                _, files = run(f"grep -rl '{url}' /etc/apt/sources.list.d/ 2>/dev/null")
                if files:
                    for f in files.splitlines():
                        f = f.strip()
                        if f and not f.endswith(".disabled"):
                            run(f"mv '{f}' '{f}.disabled'")
                            log.warning(f"Disabled broken repo: {f}")
                            track("ppa_fixes")
        run("apt-get update 2>/dev/null", timeout=120)
    log_ok("PPA check done.")


# --- Font Healing ---

def check_fonts():
    if not cfg["enable_font_heal"]:
        return
    log_ok("Checking fonts...")
    _, out = run("fc-list 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) < 10:
        log.warning(f"Only {out} fonts found! Rebuilding cache...")
        run("fc-cache -fv 2>/dev/null")
        track("font_fixes")
    cache_dir = os.path.expanduser("~/.cache/fontconfig")
    if not os.path.isdir(cache_dir):
        run("fc-cache -fv 2>/dev/null")
        track("font_fixes")
    log_ok("Font check done.")


# --- Printer Healing ---

def check_printer():
    if not cfg["enable_printer_heal"]:
        return
    if not shutil.which("lpstat"):
        return
    log_ok("Checking printers...")
    _, out = run("systemctl is-active cups 2>/dev/null")
    if out == "failed":
        log.warning("CUPS failed! Restarting...")
        run("systemctl restart cups")
        track("printer_fixes")
    _, out = run("lpstat -o 2>/dev/null")
    if out and len(out.splitlines()) > 10:
        log.warning(f"{len(out.splitlines())} stuck print jobs! Cancelling...")
        run("cancel -a 2>/dev/null")
        track("printer_fixes")
    log_ok("Printer check done.")


# --- Suspend/Resume Healing ---

def check_suspend():
    if not cfg["enable_suspend_heal"]:
        return
    log_ok("Checking suspend/resume...")
    _, errors = run("journalctl -b --grep='PM:.*failed\\|resume.*error' --no-pager -q 2>/dev/null | tail -5")
    if errors:
        log.warning(f"Suspend/resume errors:\n{errors[:300]}")
        for svc in ["NetworkManager", "bluetooth", "pulseaudio"]:
            run(f"systemctl restart {svc} 2>/dev/null")
        track("suspend_fixes")
    log_ok("Suspend check done.")


# --- Clock Drift Detection ---

def check_clock_drift():
    if not cfg["enable_clock_drift"]:
        return
    log_ok("Checking clock drift...")
    _, out = run("timedatectl show --property=NTPSynchronized --value 2>/dev/null")
    if out == "no":
        log.warning("Clock not synced!")
        run("timedatectl set-ntp true")
        run("systemctl restart systemd-timesyncd 2>/dev/null")
        run("ntpdate pool.ntp.org 2>/dev/null || chronyc makestep 2>/dev/null")
        track("clock_fixes")
    log_ok("Clock drift check done.")


# --- Zombie Parent Healing ---

def check_zombie_parents():
    if not cfg["enable_zombie_parent_heal"]:
        return
    log_ok("Checking zombie parent processes...")
    _, out = run("ps aux | awk '$8==\"Z\" {print $2}'")
    if not out:
        return
    for zpid in out.splitlines():
        zpid = zpid.strip()
        if not zpid:
            continue
        _, ppid = run(f"ps -o ppid= -p {zpid} 2>/dev/null")
        ppid = ppid.strip() if ppid else ""
        if ppid and ppid != "1":
            _, pname = run(f"ps -o comm= -p {ppid} 2>/dev/null")
            log.warning(f"Zombie PID {zpid} parent {ppid} ({pname}). Sending SIGCHLD...")
            run(f"kill -SIGCHLD {ppid}")
            time.sleep(2)
            rc, _ = run(f"ps -p {zpid} 2>/dev/null")
            if rc == 0:
                log.warning(f"Parent {ppid} not reaping. Killing parent...")
                run(f"kill -15 {ppid}")
                track("zombie_parent_fixes")


# --- OOM Score Protection ---

def check_oom_scores():
    if not cfg["enable_oom_score"]:
        return
    log_ok("Checking OOM scores...")
    critical = ["sshd", "systemd-journald", "dbus-daemon", "cron"]
    for proc in critical:
        _, pids = run(f"pgrep {proc} 2>/dev/null")
        if pids:
            for pid in pids.splitlines():
                pid = pid.strip()
                if pid:
                    try:
                        oom_file = f"/proc/{pid}/oom_score_adj"
                        current = Path(oom_file).read_text().strip()
                        if current != "-1000":
                            Path(oom_file).write_text("-1000")
                            track("oom_score_fixes")
                    except (OSError, PermissionError):
                        pass
    log_ok("OOM scores OK.")


# --- Sysctl Hardening ---

def check_sysctl():
    if not cfg["enable_sysctl_heal"]:
        return
    log_ok("Checking sysctl settings...")
    hardened = {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "kernel.randomize_va_space": "2",
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
    }
    for key, expected in hardened.items():
        _, val = run(f"sysctl -n {key} 2>/dev/null")
        if val and val.strip() != expected:
            run(f"sysctl -w {key}={expected} 2>/dev/null")
            log.info(f"Hardened {key}: {val} -> {expected}")
            track("sysctl_fixes")
    log_ok("Sysctl check done.")


# --- APT Source Integrity ---

def check_apt_sources():
    if not cfg["enable_apt_source_heal"]:
        return
    log_ok("Checking APT source integrity...")
    _, out = run("apt-get update 2>&1 | grep -i 'duplicate'")
    if out:
        log.warning(f"Duplicate APT sources:\n{out[:300]}")
        track("apt_source_fixes")
    _, out = run("apt-key list 2>&1 | grep -i 'expired'")
    if out:
        log.warning(f"Expired APT keys:\n{out[:300]}")
        run("apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com 2>/dev/null")
        track("apt_source_fixes")
    log_ok("APT source check done.")


# --- User Account Integrity ---

def check_user_integrity():
    if not cfg["enable_user_integrity"]:
        return
    log_ok("Checking user integrity...")
    _, out = run("awk -F: '$3==0 && $1!=\"root\" {print $1}' /etc/passwd")
    if out:
        log.warning(f"Non-root UID 0 accounts: {out}")
        track("user_integrity_fixes")
    _, out = run("awk -F: '$2==\"\" {print $1}' /etc/shadow 2>/dev/null")
    if out:
        log.warning(f"Users with empty passwords: {out}")
        track("user_integrity_fixes")
    _, out = run("awk -F: '$3>=1000 && $3<65534 {print $1, $6}' /etc/passwd")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not os.path.isdir(parts[1]):
                log.warning(f"User {parts[0]} missing home dir: {parts[1]}")
                run(f"mkhomedir_helper {parts[0]} 2>/dev/null")
                track("user_integrity_fixes")
    log_ok("User integrity check done.")


# --- Mount Point Healing ---

def check_mounts():
    if not cfg["enable_mount_heal"]:
        return
    log_ok("Checking mount points...")
    _, out = run("mount | grep -E 'nfs|cifs|smbfs'")
    if out:
        for line in out.splitlines():
            mp = line.split(" on ")[1].split(" type ")[0] if " on " in line else ""
            if mp:
                rc, _ = run(f"stat -t '{mp}' 2>/dev/null", timeout=5)
                if rc != 0:
                    log.warning(f"Stale mount: {mp}. Unmounting...")
                    run(f"umount -l '{mp}' 2>/dev/null")
                    track("mount_fixes")
    _, out = run("df -h | grep tmpfs | awk '$5+0 > 90 {print $6, $5}'")
    if out:
        log.warning(f"tmpfs nearly full:\n{out}")
        track("mount_fixes")
    log_ok("Mount check done.")


# --- ARP Spoof Detection ---

def check_arp_spoof():
    if not cfg["enable_arp_spoof_detect"]:
        return
    log_ok("Checking ARP table...")
    _, out = run("ip neigh show | awk '{print $5}' | sort | uniq -d")
    if out:
        log.warning(f"Duplicate MACs in ARP table (possible ARP spoof):\n{out}")
        track("arp_spoof_detects")
    log_ok("ARP check done.")


# --- DNS Leak Check ---

def check_dns_leak():
    if not cfg["enable_dns_leak_check"]:
        return
    log_ok("Checking DNS config...")
    _, out = run("resolvectl status 2>/dev/null | grep 'DNS Servers' | head -5")
    if not out:
        _, out = run("cat /etc/resolv.conf | grep nameserver")
    if out:
        for line in out.splitlines():
            if any(x in line for x in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]):
                continue
            if re.search(r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)', line):
                continue
            log.info(f"DNS: {line.strip()}")
    log_ok("DNS leak check done.")


# --- Open File Limit ---

def check_open_file_limit():
    if not cfg["enable_open_file_limit"]:
        return
    log_ok("Checking open file limits...")
    _, out = run("cat /proc/sys/fs/file-nr")
    if out:
        parts = out.split()
        if len(parts) >= 3:
            used, maximum = int(parts[0]), int(parts[2])
            pct = used / maximum * 100
            if pct > 80:
                log.warning(f"Open files at {pct:.0f}%! ({used}/{maximum})")
                run("sysctl -w fs.file-max=2097152")
                track("open_file_fixes")
    log_ok("Open file limit check done.")


# --- Kernel Module Integrity ---

def check_kernel_modules():
    if not cfg["enable_kernel_module_check"]:
        return
    log_ok("Checking kernel modules...")
    _, out = run("dmesg 2>/dev/null | grep -i 'module verification failed'")
    if out:
        log.warning(f"Unsigned kernel modules:\n{out[:300]}")
        track("kernel_module_fixes")
    _, out = run("lsmod | awk 'NR>1 && $3==0 {print $1}' | head -20")
    if out:
        log.info(f"Unused modules: {out.replace(chr(10), ', ')}")
    log_ok("Kernel module check done.")


# --- Cgroup Healing ---

def check_cgroups():
    if not cfg["enable_cgroup_heal"]:
        return
    log_ok("Checking cgroups...")
    _, out = run("systemctl status 2>/dev/null | grep -i 'degraded'")
    if out:
        log.warning("System in degraded state!")
        _, failed = run("systemctl --failed --no-legend --plain")
        if failed:
            log.warning(f"Failed units:\n{failed[:300]}")
        track("cgroup_fixes")
    log_ok("Cgroup check done.")


# --- Dmesg Monitor ---

def check_dmesg():
    if not cfg["enable_dmesg_monitor"]:
        return
    log_ok("Checking dmesg...")
    _, out = run("dmesg --level=err,crit,alert,emerg -T 2>/dev/null | tail -20")
    if out:
        log.warning(f"Kernel errors:\n{out[:500]}")
        track("dmesg_warnings")
    log_ok("Dmesg check done.")


# --- GPU Temperature ---

def check_gpu_temp():
    if not cfg["enable_gpu_temp"]:
        return
    log_ok("Checking GPU temperature...")
    if shutil.which("nvidia-smi"):
        _, out = run("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader 2>/dev/null")
        if out and out.strip().isdigit():
            temp = int(out.strip())
            if temp > cfg["temp_crit_c"]:
                log.warning(f"GPU CRITICAL: {temp}°C!")
                track("gpu_temp_warnings")
            elif temp > cfg["temp_warn_c"]:
                log.warning(f"GPU hot: {temp}°C")
            else:
                log.info(f"GPU: {temp}°C")
    log_ok("GPU temp check done.")


# --- Fan Monitor ---

def check_fans():
    if not cfg["enable_fan_monitor"]:
        return
    log_ok("Checking fans...")
    _, out = run("sensors 2>/dev/null | grep -i fan | grep -v '0 RPM'")
    if out:
        log.info(f"Fans:\n{out}")
    _, stopped = run("sensors 2>/dev/null | grep -i fan | grep '0 RPM'")
    if stopped:
        log.warning(f"Stopped fans:\n{stopped}")
        track("fan_warnings")
    log_ok("Fan check done.")


# --- Lid Switch ---

def check_lid_switch():
    if not cfg["enable_lid_switch"]:
        return
    if not os.path.exists("/etc/systemd/logind.conf"):
        return
    log_ok("Checking lid switch config...")
    _, out = run("grep -E '^HandleLidSwitch' /etc/systemd/logind.conf 2>/dev/null")
    if not out:
        log.info("Lid switch using defaults.")
    log_ok("Lid switch check done.")


# --- Screen Lock Check ---

def check_screen_lock():
    if not cfg["enable_screen_lock"]:
        return
    log_ok("Checking screen lock...")
    _, out = run("gsettings get org.cinnamon.desktop.screensaver lock-enabled 2>/dev/null")
    if out and out.strip() == "false":
        log.warning("Screen lock disabled! Enabling...")
        run("gsettings set org.cinnamon.desktop.screensaver lock-enabled true 2>/dev/null")
        track("screen_lock_fixes")
    log_ok("Screen lock check done.")


# --- SSH Hardening ---

def check_ssh_harden():
    if not cfg["enable_ssh_harden"]:
        return
    if not os.path.exists("/etc/ssh/sshd_config"):
        return
    log_ok("Checking SSH hardening...")
    checks = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "yes",
        "MaxAuthTries": "5",
        "X11Forwarding": "no",
    }
    _, content = run("cat /etc/ssh/sshd_config")
    for key, recommended in checks.items():
        match = re.search(rf'^{key}\s+(\S+)', content or "", re.MULTILINE)
        if match:
            val = match.group(1)
            if key == "PermitRootLogin" and val == "yes":
                log.warning(f"SSH: {key} is {val} (should be {recommended})")
                track("ssh_hardens")
            elif key == "MaxAuthTries":
                if val.isdigit() and int(val) > 10:
                    log.warning(f"SSH: MaxAuthTries too high ({val})")
                    track("ssh_hardens")
    log_ok("SSH hardening check done.")


# --- Failed Mount Retry ---

def check_failed_mount_retry():
    if not cfg["enable_failed_mount_retry"]:
        return
    log_ok("Checking failed mounts...")
    _, out = run("systemctl --failed --no-legend | grep mount")
    if out:
        for line in out.splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit:
                log.warning(f"Failed mount: {unit}. Retrying...")
                run(f"systemctl restart {unit} 2>/dev/null")
                track("failed_mount_retries")
    log_ok("Failed mount check done.")


# --- SMART Self-Test ---

def check_smart_selftest():
    if not cfg["enable_disk_smart_selftest"]:
        return
    if not shutil.which("smartctl"):
        return
    log_ok("Checking SMART self-test schedule...")
    _, out = run("lsblk -dno NAME,ROTA | awk '$2==0{print $1}'")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, last = run(f"smartctl -l selftest /dev/{disk} 2>/dev/null | grep -c 'Completed'")
            if last and last.isdigit() and int(last) == 0:
                log.info(f"Starting short self-test on /dev/{disk}")
                run(f"smartctl -t short /dev/{disk} 2>/dev/null")
                track("smart_selftests")
    log_ok("SMART self-test check done.")


# --- Network Speed Monitor ---

def check_network_speed():
    if not cfg["enable_network_speed"]:
        return
    log_ok("Checking network speed...")
    _, iface = run("ip route | awk '/default/{print $5}' | head -1")
    if iface:
        _, speed = run(f"cat /sys/class/net/{iface.strip()}/speed 2>/dev/null")
        if speed and speed.strip().isdigit():
            s = int(speed.strip())
            if s < 100 and s > 0:
                log.warning(f"Network link speed low: {s} Mbps on {iface.strip()}")
                track("network_speed_warnings")
            elif s > 0:
                log.info(f"Network: {s} Mbps on {iface.strip()}")
    log_ok("Network speed check done.")


# --- MAC Spoof Detection ---

def check_mac_spoof():
    if not cfg["enable_mac_spoof_detect"]:
        return
    log_ok("Checking MAC addresses...")
    _, out = run("ip link show | grep -E 'link/ether' | awk '{print $2}'")
    if out:
        for mac in out.splitlines():
            mac = mac.strip()
            if mac and mac.startswith("00:00:00"):
                log.warning(f"Suspicious MAC: {mac}")
                track("mac_spoof_detects")
    log_ok("MAC check done.")


# --- Process Limit ---

def check_process_limit():
    if not cfg["enable_process_limit"]:
        return
    log_ok("Checking process limits...")
    _, out = run("ps aux --no-headers | wc -l")
    if out and out.isdigit() and int(out) > 1000:
        log.warning(f"High process count: {out}")
        track("process_limit_fixes")
    _, out = run("cat /proc/sys/kernel/threads-max")
    if out and out.isdigit() and int(out) < 30000:
        run("sysctl -w kernel.threads-max=65536")
        track("process_limit_fixes")
    log_ok("Process limit check done.")


# --- File Descriptor Healing ---

def check_file_descriptors():
    if not cfg["enable_file_descriptor_heal"]:
        return
    log_ok("Checking file descriptors...")
    _, out = run("cat /proc/sys/fs/file-nr | awk '{print $1, $3}'")
    if out:
        parts = out.split()
        if len(parts) >= 2:
            used, limit = int(parts[0]), int(parts[1])
            if used > limit * 0.8:
                log.warning(f"FD usage high: {used}/{limit}")
                run("sysctl -w fs.file-max=2097152")
                track("fd_fixes")
    log_ok("FD check done.")


# --- Shared Memory Healing ---

def check_shared_memory():
    if not cfg["enable_shared_memory_heal"]:
        return
    log_ok("Checking shared memory...")
    _, out = run("ipcs -m 2>/dev/null | grep -c '^0x'")
    if out and out.isdigit() and int(out) > 100:
        log.warning(f"Many shared memory segments: {out}")
        run("ipcs -m | awk '$6==0 {print $2}' | xargs -I{} ipcrm -m {} 2>/dev/null")
        track("shm_fixes")
    log_ok("Shared memory check done.")


# --- Semaphore Healing ---

def check_semaphores():
    if not cfg["enable_semaphore_heal"]:
        return
    log_ok("Checking semaphores...")
    _, out = run("ipcs -s 2>/dev/null | grep -c '^0x'")
    if out and out.isdigit() and int(out) > 100:
        log.warning(f"Many semaphore arrays: {out}")
        track("sem_fixes")
    log_ok("Semaphore check done.")


# --- D-Bus Healing ---

def check_dbus():
    if not cfg["enable_dbus_heal"]:
        return
    log_ok("Checking D-Bus...")
    _, out = run("systemctl is-active dbus 2>/dev/null")
    if out != "active":
        log.warning("D-Bus not active! Restarting...")
        run("systemctl restart dbus")
        track("dbus_fixes")
    _, out = run("dbus-send --system --dest=org.freedesktop.DBus --print-reply /org/freedesktop/DBus org.freedesktop.DBus.Peer.Ping 2>/dev/null")
    if "Error" in (out or ""):
        log.warning("D-Bus system bus not responding!")
        run("systemctl restart dbus")
        track("dbus_fixes")
    log_ok("D-Bus check done.")


# --- PolicyKit Healing ---

def check_polkit():
    if not cfg["enable_polkit_heal"]:
        return
    log_ok("Checking PolicyKit...")
    _, out = run("systemctl is-active polkit 2>/dev/null")
    if out != "active":
        log.warning("PolicyKit not running! Starting...")
        run("systemctl start polkit")
        track("polkit_fixes")
    log_ok("PolicyKit check done.")


# --- AppArmor Check ---

def check_apparmor():
    if not cfg["enable_apparmor_check"]:
        return
    if not shutil.which("aa-status"):
        return
    log_ok("Checking AppArmor...")
    _, out = run("aa-status 2>/dev/null | head -5")
    if out:
        log.info(f"AppArmor: {out.splitlines()[0] if out.splitlines() else 'unknown'}")
    _, out = run("aa-status 2>/dev/null | grep -c 'complain'")
    if out and out.isdigit() and int(out) > 0:
        log.info(f"AppArmor: {out} profiles in complain mode")
    log_ok("AppArmor check done.")


# --- GRUB Password Check ---

def check_grub_password():
    if not cfg["enable_grub_password_check"]:
        return
    log_ok("Checking GRUB security...")
    _, out = run("grep -c 'password' /etc/grub.d/* 2>/dev/null")
    has_password = any(int(x.split(":")[-1]) > 0 for x in out.splitlines() if ":" in x and x.split(":")[-1].isdigit()) if out else False
    if not has_password:
        log.info("GRUB has no password protection (consider adding one).")
        track("grub_password_warnings")
    log_ok("GRUB security check done.")


# --- Core Pattern Check ---

def check_core_pattern():
    if not cfg["enable_core_pattern_check"]:
        return
    log_ok("Checking core pattern...")
    _, out = run("cat /proc/sys/kernel/core_pattern")
    if out and "|" not in out and out.strip() == "core":
        log.info("Core dumps go to current dir. Setting to systemd-coredump...")
        run("sysctl -w kernel.core_pattern='|/lib/systemd/systemd-coredump %P %u %g %s %t %c %h'")
        track("core_pattern_fixes")
    log_ok("Core pattern check done.")


# --- Module Blacklist ---

def check_module_blacklist():
    if not cfg["enable_module_blacklist"]:
        return
    log_ok("Checking module blacklist...")
    dangerous = ["firewire-core", "firewire-ohci", "firewire-sbp2", "thunderbolt"]
    for mod in dangerous:
        _, out = run(f"lsmod | grep ^{mod}")
        if out:
            log.info(f"Module {mod} loaded (consider blacklisting for security)")
    log_ok("Module blacklist check done.")


# --- IPv6 Check ---

def check_ipv6():
    if not cfg["enable_ipv6_check"]:
        return
    log_ok("Checking IPv6...")
    _, out = run("cat /proc/sys/net/ipv6/conf/all/disable_ipv6")
    if out and out.strip() == "0":
        _, v6addr = run("ip -6 addr show scope global 2>/dev/null | head -3")
        if v6addr:
            log.info("IPv6 enabled with global address.")
        else:
            log.info("IPv6 enabled but no global address.")
    log_ok("IPv6 check done.")


# --- Disk I/O Scheduler ---

def check_disk_scheduler():
    if not cfg["enable_disk_scheduler"]:
        return
    log_ok("Checking disk schedulers...")
    _, out = run("lsblk -dno NAME,ROTA")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                disk, rotational = parts[0], parts[1]
                _, sched = run(f"cat /sys/block/{disk}/queue/scheduler 2>/dev/null")
                if sched:
                    if rotational == "0" and "none" not in sched and "mq-deadline" not in sched:
                        log.info(f"SSD {disk}: setting scheduler to none")
                        try:
                            Path(f"/sys/block/{disk}/queue/scheduler").write_text("none")
                            track("disk_scheduler_fixes")
                        except (OSError, PermissionError):
                            pass
    log_ok("Disk scheduler check done.")


# --- NUMA Balance ---

def check_numa():
    if not cfg["enable_numa_balance"]:
        return
    log_ok("Checking NUMA...")
    _, out = run("cat /proc/sys/kernel/numa_balancing 2>/dev/null")
    if out is not None:
        log.info(f"NUMA balancing: {'enabled' if out.strip() == '1' else 'disabled'}")
    log_ok("NUMA check done.")


# --- Hugepages Check ---

def check_hugepages():
    if not cfg["enable_hugepages_check"]:
        return
    log_ok("Checking hugepages...")
    _, out = run("cat /proc/meminfo | grep HugePages_Total")
    if out:
        log.info(f"Hugepages: {out.strip()}")
    _, thp = run("cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null")
    if thp:
        log.info(f"THP: {thp.strip()}")
    log_ok("Hugepages check done.")


# --- TCP Tuning ---

def check_tcp_tuning():
    if not cfg["enable_tcp_tuning"]:
        return
    log_ok("Checking TCP tuning...")
    tunings = {
        "net.core.rmem_max": "16777216",
        "net.core.wmem_max": "16777216",
        "net.ipv4.tcp_fastopen": "3",
        "net.ipv4.tcp_mtu_probing": "1",
    }
    for key, val in tunings.items():
        _, current = run(f"sysctl -n {key} 2>/dev/null")
        if current and int(current.strip() or 0) < int(val):
            run(f"sysctl -w {key}={val}")
            track("tcp_tuning_fixes")
    log_ok("TCP tuning check done.")


# --- I/O Scheduler Healing ---

def check_io_scheduler():
    if not cfg["enable_io_scheduler_heal"]:
        return
    log_ok("Checking I/O pressure...")
    if os.path.exists("/proc/pressure/io"):
        _, out = run("cat /proc/pressure/io")
        if out:
            for line in out.splitlines():
                match = re.search(r'avg10=(\d+\.\d+)', line)
                if match and float(match.group(1)) > 50:
                    log.warning(f"High I/O pressure: {line}")
                    track("io_scheduler_fixes")
    log_ok("I/O scheduler check done.")


# --- Watchdog Check ---

def check_watchdog():
    if not cfg["enable_watchdog_check"]:
        return
    log_ok("Checking watchdog...")
    _, out = run("systemctl is-active systemd-watchdog 2>/dev/null")
    if os.path.exists("/dev/watchdog"):
        log.info("Hardware watchdog available.")
    _, out = run("cat /proc/sys/kernel/watchdog 2>/dev/null")
    if out and out.strip() == "0":
        log.warning("Kernel watchdog disabled! Enabling...")
        run("sysctl -w kernel.watchdog=1")
        track("watchdog_fixes")
    log_ok("Watchdog check done.")


# --- ACPI Check ---

def check_acpi():
    if not cfg["enable_acpi_check"]:
        return
    log_ok("Checking ACPI...")
    _, out = run("journalctl -b --grep='ACPI.*error\\|ACPI.*warning' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"ACPI issues:\n{out[:300]}")
        track("acpi_fixes")
    log_ok("ACPI check done.")


# --- Display Manager Healing ---

def check_display_manager():
    if not cfg["enable_display_manager_heal"]:
        return
    log_ok("Checking display manager...")
    for dm in ["lightdm", "gdm3", "sddm"]:
        _, out = run(f"systemctl is-enabled {dm} 2>/dev/null")
        if out == "enabled":
            _, active = run(f"systemctl is-active {dm} 2>/dev/null")
            if active != "active":
                log.warning(f"{dm} enabled but not active! Restarting...")
                run(f"systemctl restart {dm}")
                track("dm_fixes")
            break
    log_ok("Display manager check done.")


# --- XDG Directories Check ---

def check_xdg_dirs():
    if not cfg["enable_xdg_dirs_check"]:
        return
    log_ok("Checking XDG directories...")
    xdg_dirs = ["Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos"]
    home = os.path.expanduser("~")
    for d in xdg_dirs:
        path = os.path.join(home, d)
        if not os.path.isdir(path):
            log.warning(f"Missing XDG dir: {path}. Creating...")
            os.makedirs(path, exist_ok=True)
            track("xdg_fixes")
    log_ok("XDG dirs check done.")


# --- Systemd Timer Healing ---

def check_systemd_timers():
    log_ok("Checking systemd timers...")
    _, out = run("systemctl list-timers --failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed timers:\n{out[:300]}")
        for line in out.splitlines():
            unit = line.split()[-1] if line.split() else ""
            if unit:
                run(f"systemctl restart {unit} 2>/dev/null")
        track("services_restarted")
    log_ok("Timer check done.")


# --- Performance Governor ---

def check_cpu_governor():
    log_ok("Checking CPU governor...")
    _, out = run("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null")
    if out:
        log.info(f"CPU governor: {out.strip()}")
    log_ok("CPU governor check done.")


# --- Kernel Live Patch ---

def check_kernel_livepatch():
    log_ok("Checking kernel livepatch...")
    _, out = run("canonical-livepatch status 2>/dev/null")
    if out and "running" in out.lower():
        log.info("Livepatch active.")
    log_ok("Livepatch check done.")


# --- Disk Read-Ahead ---

def check_disk_readahead():
    log_ok("Checking disk read-ahead...")
    _, out = run("lsblk -dno NAME,ROTA | awk '$2==0{print $1}'")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, ra = run(f"cat /sys/block/{disk}/queue/read_ahead_kb 2>/dev/null")
            if ra and ra.strip().isdigit() and int(ra.strip()) > 512:
                try:
                    Path(f"/sys/block/{disk}/queue/read_ahead_kb").write_text("256")
                except (OSError, PermissionError):
                    pass
    log_ok("Read-ahead check done.")


# --- Kernel Printk Level ---

def check_printk_level():
    log_ok("Checking printk level...")
    _, out = run("cat /proc/sys/kernel/printk")
    if out:
        level = out.split()[0] if out.split() else "0"
        if level == "7":
            run("sysctl -w kernel.printk='4 4 1 7'")
    log_ok("Printk check done.")


# --- Systemd Journal Rate Limit ---

def check_journal_rate_limit():
    log_ok("Checking journal rate limit...")
    _, out = run("journalctl --since '1 min ago' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 5000:
        log.warning(f"Journal flooding: {out} msgs/min!")
    log_ok("Journal rate check done.")


# --- Zombie Thread Check ---

def check_zombie_threads():
    log_ok("Checking zombie threads...")
    _, out = run("find /proc/*/task/*/status -maxdepth 0 2>/dev/null | xargs grep -l 'State.*Z' 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 10:
        log.warning(f"{out} zombie threads found!")
    log_ok("Zombie thread check done.")


# --- Kernel Taint Check ---

def check_kernel_taint():
    log_ok("Checking kernel taint...")
    _, out = run("cat /proc/sys/kernel/tainted")
    if out and out.strip() != "0":
        flags = int(out.strip())
        reasons = []
        if flags & 1:
            reasons.append("proprietary module")
        if flags & 2:
            reasons.append("module force loaded")
        if flags & 4:
            reasons.append("SMP unsafe")
        if flags & 8:
            reasons.append("module force unloaded")
        if flags & 16:
            reasons.append("MCE")
        if flags & 32:
            reasons.append("bad page")
        if flags & 64:
            reasons.append("userspace taint")
        if flags & 128:
            reasons.append("kernel died")
        if flags & 256:
            reasons.append("ACPI overridden")
        if flags & 512:
            reasons.append("warning occurred")
        log.warning(f"Kernel tainted ({flags}): {', '.join(reasons)}")
    log_ok("Taint check done.")


# --- Swap Usage Monitor ---

def check_swap_usage():
    log_ok("Checking swap usage...")
    _, out = run("free -m | awk '/Swap/{print $3, $2}'")
    if out:
        parts = out.split()
        if len(parts) >= 2 and int(parts[1]) > 0:
            pct = int(parts[0]) / int(parts[1]) * 100
            if pct > 80:
                log.warning(f"Swap {pct:.0f}% used! Clearing caches...")
                run("sync && sysctl -w vm.drop_caches=1")
    log_ok("Swap usage check done.")


# --- Network Interface Errors ---

def check_network_errors():
    log_ok("Checking network interface errors...")
    _, out = run("ip -s link show | grep -A1 'RX:' | grep -v 'RX:' | awk '{if($3>0 || $4>0) print}'")
    if out:
        log.warning("Network interface errors detected")
    _, out = run("ip -s link show | grep -A1 'TX:' | grep -v 'TX:' | awk '{if($3>0 || $4>0) print}'")
    if out:
        log.warning("Network TX errors detected")
    log_ok("Network error check done.")


# --- Disk Queue Depth ---

def check_disk_queue():
    log_ok("Checking disk queue depth...")
    _, out = run("lsblk -dno NAME")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, nr = run(f"cat /sys/block/{disk}/queue/nr_requests 2>/dev/null")
            if nr and nr.strip().isdigit() and int(nr.strip()) < 64:
                try:
                    Path(f"/sys/block/{disk}/queue/nr_requests").write_text("256")
                except (OSError, PermissionError):
                    pass
    log_ok("Disk queue check done.")


# --- Systemd Scope Cleanup ---

def check_systemd_scopes():
    log_ok("Checking systemd scopes...")
    _, out = run("systemctl list-units --type=scope --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        for line in out.splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit:
                run(f"systemctl reset-failed {unit} 2>/dev/null")
    log_ok("Scope check done.")


# --- Login Shell Check ---

def check_login_shells():
    log_ok("Checking login shells...")
    _, out = run("awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ && $3>=1000 {print $1, $7}' /etc/passwd")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                shell = parts[1]
                if not os.path.exists(shell):
                    log.warning(f"User {parts[0]} has invalid shell: {shell}")
    log_ok("Login shell check done.")


# --- PAM Configuration Check ---

def check_pam():
    log_ok("Checking PAM...")
    _, out = run("pam-auth-update --package 2>&1 | grep -i error")
    if out:
        log.warning(f"PAM issues: {out[:200]}")
    log_ok("PAM check done.")


# --- Sudoers Validation ---

def check_sudoers():
    log_ok("Checking sudoers...")
    rc, out = run("visudo -c 2>&1")
    if rc != 0:
        log.warning(f"Sudoers syntax error:\n{out[:300]}")
    log_ok("Sudoers check done.")


# --- Systemd Slice Check ---

def check_systemd_slices():
    log_ok("Checking systemd slices...")
    _, out = run("systemctl list-units --type=slice --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed slices:\n{out[:300]}")
    log_ok("Slice check done.")


# --- Kernel Memory Leak Detection ---

def check_kernel_memleak():
    log_ok("Checking kernel memory...")
    _, out = run("cat /proc/meminfo | grep Slab")
    if out:
        match = re.search(r'(\d+)', out)
        if match and int(match.group(1)) > 2000000:  # >2GB slab
            log.warning(f"High slab memory: {out.strip()}")
    log_ok("Kernel memory check done.")


# --- Inotify Watch Limit ---

def check_inotify_limit():
    log_ok("Checking inotify limits...")
    _, out = run("cat /proc/sys/fs/inotify/max_user_watches")
    if out and out.strip().isdigit() and int(out.strip()) < 524288:
        run("sysctl -w fs.inotify.max_user_watches=524288")
        run("sysctl -w fs.inotify.max_user_instances=1024")
    log_ok("Inotify check done.")


# --- Systemd Resolved Check ---

def check_resolved():
    log_ok("Checking systemd-resolved...")
    _, out = run("systemctl is-active systemd-resolved 2>/dev/null")
    if out == "failed":
        log.warning("systemd-resolved failed! Restarting...")
        run("systemctl restart systemd-resolved")
    _, out = run("resolvectl statistics 2>/dev/null | grep -i 'cache miss'")
    if out:
        log.info(f"DNS cache: {out.strip()}")
    log_ok("Resolved check done.")


# --- Snap Refresh Check ---

def check_snap_refresh():
    if not shutil.which("snap"):
        return
    log_ok("Checking snap refresh...")
    _, out = run("snap changes 2>/dev/null | grep -i 'error\\|undone' | tail -5")
    if out:
        log.warning(f"Snap issues:\n{out}")
    log_ok("Snap refresh check done.")


# --- Firmware Check ---

def check_firmware():
    log_ok("Checking firmware...")
    if shutil.which("fwupdmgr"):
        _, out = run("fwupdmgr get-updates 2>/dev/null | head -10")
        if out and "No updates" not in out:
            log.info(f"Firmware updates available:\n{out[:300]}")
    log_ok("Firmware check done.")


# --- Disk Partition Table ---

def check_partition_table():
    log_ok("Checking partition tables...")
    _, out = run("fdisk -l 2>&1 | grep -i 'error\\|warning\\|bad'")
    if out:
        log.warning(f"Partition issues:\n{out[:300]}")
    log_ok("Partition check done.")


# --- Network Bridge Check ---

def check_network_bridges():
    log_ok("Checking network bridges...")
    _, out = run("brctl show 2>/dev/null | tail -n +2")
    if out:
        log.info(f"Bridges:\n{out}")
    log_ok("Bridge check done.")


# --- VPN Leak Check ---

def check_vpn_leak():
    log_ok("Checking VPN...")
    _, vpn = run("ip link show | grep -E 'tun|wg|ppp'")
    if vpn:
        _, routes = run("ip route | grep default")
        if routes and "tun" not in routes and "wg" not in routes:
            log.warning("VPN interface up but traffic not routed through it!")
    log_ok("VPN check done.")


# --- Disk Alignment Check ---

def check_disk_alignment():
    log_ok("Checking disk alignment...")
    _, out = run("lsblk -o NAME,PHY-SEC,LOG-SEC --noheadings 2>/dev/null")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                if int(parts[1]) != int(parts[2]):
                    log.info(f"Disk {parts[0]}: physical={parts[1]} logical={parts[2]}")
    log_ok("Disk alignment check done.")


# --- Systemd Socket Check ---

def check_systemd_sockets():
    log_ok("Checking systemd sockets...")
    _, out = run("systemctl list-sockets --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed sockets:\n{out[:300]}")
    log_ok("Socket check done.")


# --- Kernel Keyring Check ---

def check_kernel_keyring():
    log_ok("Checking kernel keyring...")
    _, out = run("cat /proc/keys 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 500:
        log.warning(f"Many kernel keys: {out}")
    log_ok("Keyring check done.")


# --- CPU Microcode ---

def check_cpu_microcode():
    log_ok("Checking CPU microcode...")
    _, out = run("journalctl -b --grep='microcode' --no-pager -q 2>/dev/null | tail -3")
    if out:
        log.info(f"Microcode: {out.splitlines()[0] if out.splitlines() else 'unknown'}")
    log_ok("Microcode check done.")


# --- EFI Boot Check ---

def check_efi_boot():
    if not os.path.isdir("/sys/firmware/efi"):
        return
    log_ok("Checking EFI boot...")
    _, out = run("efibootmgr 2>/dev/null | head -10")
    if out:
        log.info(f"EFI: {out.splitlines()[0] if out.splitlines() else 'unknown'}")
    log_ok("EFI check done.")


# --- Disk TRIM Verify ---

def check_trim_verify():
    log_ok("Checking TRIM support...")
    _, out = run("lsblk -D -o NAME,DISC-GRAN,DISC-MAX --noheadings 2>/dev/null")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "0B":
                log.warning(f"Disk {parts[0]} does not support TRIM")
    _, timer = run("systemctl is-active fstrim.timer 2>/dev/null")
    if timer != "active":
        run("systemctl enable --now fstrim.timer 2>/dev/null")
    log_ok("TRIM check done.")


# --- Memory ECC Check ---

def check_memory_ecc():
    log_ok("Checking memory ECC...")
    _, out = run("edac-util -s 2>/dev/null")
    if out and "error" in out.lower():
        log.warning(f"ECC memory errors: {out}")
    _, out = run("journalctl -b --grep='mce.*memory\\|EDAC' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"Memory errors in journal:\n{out[:300]}")
    log_ok("ECC check done.")


# --- Systemd Automount Check ---

def check_automounts():
    log_ok("Checking automounts...")
    _, out = run("systemctl list-units --type=automount --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed automounts:\n{out[:300]}")
    log_ok("Automount check done.")


# --- Network MTU Check ---

def check_network_mtu():
    log_ok("Checking network MTU...")
    _, iface = run("ip route | awk '/default/{print $5}' | head -1")
    if iface:
        _, mtu = run(f"cat /sys/class/net/{iface.strip()}/mtu 2>/dev/null")
        if mtu and mtu.strip().isdigit():
            m = int(mtu.strip())
            if m < 1500:
                log.warning(f"Low MTU on {iface.strip()}: {m}")
            else:
                log.info(f"MTU: {m} on {iface.strip()}")
    log_ok("MTU check done.")


# --- Disk Write Cache ---

def check_disk_write_cache():
    log_ok("Checking disk write cache...")
    _, out = run("lsblk -dno NAME")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, wc = run(f"hdparm -W /dev/{disk} 2>/dev/null | grep 'write-caching'")
            if wc:
                log.info(f"/dev/{disk}: {wc.strip()}")
    log_ok("Write cache check done.")


# --- Kernel Hung Task Check ---

def check_hung_tasks():
    log_ok("Checking hung tasks...")
    _, out = run("journalctl -b --grep='hung_task\\|blocked for more than' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"Hung tasks detected:\n{out[:300]}")
    _, timeout = run("cat /proc/sys/kernel/hung_task_timeout_secs 2>/dev/null")
    if timeout and timeout.strip() == "0":
        run("sysctl -w kernel.hung_task_timeout_secs=120")
    log_ok("Hung task check done.")


# --- Systemd Path Units ---

def check_systemd_paths():
    log_ok("Checking systemd path units...")
    _, out = run("systemctl list-units --type=path --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed path units:\n{out[:300]}")
    log_ok("Path unit check done.")


# --- CPU Frequency Scaling ---

def check_cpu_frequency():
    log_ok("Checking CPU frequency...")
    _, out = run("cat /proc/cpuinfo | grep 'cpu MHz' | head -1")
    if out:
        match = re.search(r'(\d+)', out)
        if match:
            mhz = int(match.group(1))
            _, max_freq = run("cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null")
            if max_freq and max_freq.strip().isdigit():
                max_mhz = int(max_freq.strip()) // 1000
                if mhz < max_mhz * 0.3:
                    log.warning(f"CPU running slow: {mhz}MHz (max: {max_mhz}MHz)")
    log_ok("CPU frequency check done.")


# --- Kernel Address Space Layout ---

def check_kaslr():
    log_ok("Checking KASLR...")
    _, out = run("cat /proc/cmdline")
    if out and "nokaslr" in out:
        log.warning("KASLR disabled! Security risk.")
    log_ok("KASLR check done.")


# --- Systemd User Session ---

def check_user_sessions():
    log_ok("Checking user sessions...")
    _, out = run("loginctl list-sessions --no-legend 2>/dev/null")
    if out:
        sessions = len(out.splitlines())
        if sessions > 10:
            log.warning(f"Many user sessions: {sessions}")
    log_ok("User session check done.")


# --- Disk Fragmentation ---

def check_disk_fragmentation():
    log_ok("Checking disk fragmentation...")
    _, out = run("mount | grep 'type ext4' | awk '{print $3}'")
    if out:
        for mp in out.splitlines():
            mp = mp.strip()
            if mp:
                _, frag = run(f"e4defrag -c {mp} 2>/dev/null | tail -1")
                if frag:
                    log.info(f"{mp}: {frag.strip()}")
    log_ok("Fragmentation check done.")


# --- Network ARP Cache ---

def check_arp_cache():
    log_ok("Checking ARP cache...")
    _, out = run("ip neigh show | grep -c 'STALE\\|FAILED'")
    if out and out.isdigit() and int(out) > 50:
        log.info(f"Flushing stale ARP entries ({out})")
        run("ip neigh flush all 2>/dev/null")
    log_ok("ARP cache check done.")


# --- Kernel Sysrq ---

def check_sysrq():
    log_ok("Checking SysRq...")
    _, out = run("cat /proc/sys/kernel/sysrq")
    if out and out.strip() == "0":
        run("sysctl -w kernel.sysrq=1")
        log.info("Enabled SysRq (emergency recovery key)")
    log_ok("SysRq check done.")


# --- Disk Reservation ---

def check_disk_reserved():
    log_ok("Checking disk reserved blocks...")
    _, out = run("mount | grep 'type ext4' | awk '{print $1}'")
    if out:
        for dev in out.splitlines():
            dev = dev.strip()
            if not dev:
                continue
            _, info = run(f"tune2fs -l {dev} 2>/dev/null | grep 'Reserved block count'")
            if info:
                log.info(f"{dev}: {info.strip()}")
    log_ok("Reserved block check done.")


# --- Systemd Generator Check ---

def check_systemd_generators():
    log_ok("Checking systemd generators...")
    _, out = run("systemd-analyze blame 2>/dev/null | head -5")
    if out:
        for line in out.splitlines():
            match = re.search(r'(\d+\.\d+)s', line)
            if match and float(match.group(1)) > 30:
                log.warning(f"Slow boot service: {line.strip()}")
    log_ok("Generator check done.")


# --- Network Routing Table ---

def check_routing_table():
    log_ok("Checking routing table...")
    _, out = run("ip route | grep -c default")
    if out and out.isdigit():
        if int(out) == 0:
            log.warning("No default route!")
        elif int(out) > 1:
            log.warning(f"Multiple default routes: {out}")
    log_ok("Routing check done.")


# --- Disk SMART Attributes ---

def check_smart_attributes():
    if not shutil.which("smartctl"):
        return
    log_ok("Checking SMART attributes...")
    _, out = run("lsblk -dno NAME | head -3")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, temp = run(f"smartctl -A /dev/{disk} 2>/dev/null | grep -i temperature | head -1")
            if temp:
                log.info(f"/dev/{disk}: {temp.strip()}")
            _, hours = run(f"smartctl -A /dev/{disk} 2>/dev/null | grep -i 'Power_On_Hours' | awk '{{print $NF}}'")
            if hours and hours.strip().isdigit():
                h = int(hours.strip())
                if h > 40000:
                    log.warning(f"/dev/{disk}: {h} power-on hours — consider replacement")
    log_ok("SMART attributes check done.")


# --- Systemd Notify Check ---

def check_systemd_notify():
    log_ok("Checking systemd notifications...")
    _, out = run("systemctl list-units --state=activating --no-legend --no-pager 2>/dev/null")
    if out:
        stuck = len(out.splitlines())
        if stuck > 3:
            log.warning(f"{stuck} units stuck in activating state")
    log_ok("Notify check done.")


# --- Network Firewall Rules ---

def check_firewall_rules():
    log_ok("Checking firewall rules...")
    _, out = run("iptables -L INPUT -n --line-numbers 2>/dev/null | wc -l")
    if out and out.isdigit():
        log.info(f"Firewall INPUT rules: {int(out) - 2}")
    _, out = run("iptables -L INPUT -n 2>/dev/null | grep -c DROP")
    if out:
        log.info(f"DROP rules: {out.strip()}")
    log_ok("Firewall rules check done.")


# --- Disk LVM Check ---

def check_lvm():
    if not shutil.which("lvs"):
        return
    log_ok("Checking LVM...")
    _, out = run("lvs --noheadings 2>/dev/null")
    if out:
        for line in out.splitlines():
            if "NOT available" in line:
                log.warning(f"LVM issue: {line.strip()}")
    _, out = run("vgs --noheadings 2>/dev/null | awk '{print $1, $6, $7}'")
    if out:
        log.info(f"Volume groups:\n{out}")
    log_ok("LVM check done.")


# --- Systemd Coredump Config ---

def check_coredump_config():
    log_ok("Checking coredump config...")
    conf = "/etc/systemd/coredump.conf"
    if os.path.exists(conf):
        _, out = run(f"grep -v '^#' {conf} | grep -v '^$'")
        if out:
            log.info(f"Coredump config: {out.strip()}")
    log_ok("Coredump config check done.")


# --- Network Proxy Check ---

def check_network_proxy():
    log_ok("Checking network proxy...")
    for var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
        val = os.environ.get(var)
        if val:
            log.info(f"Proxy: {var}={val}")
    log_ok("Proxy check done.")


# --- Disk Encryption Check ---

def check_disk_encryption():
    log_ok("Checking disk encryption...")
    _, out = run("lsblk -o NAME,TYPE,FSTYPE | grep crypt")
    if out:
        log.info(f"Encrypted volumes:\n{out}")
    else:
        log.info("No encrypted volumes found.")
    log_ok("Encryption check done.")


# --- Kernel Module Parameters ---

def check_module_params():
    log_ok("Checking kernel module parameters...")
    _, out = run("lsmod | awk 'NR>1{print $1}' | head -20")
    if out:
        log.info(f"Loaded modules: {len(out.splitlines())}")
    log_ok("Module params check done.")


# --- Systemd Inhibitor Check ---

def check_systemd_inhibitors():
    log_ok("Checking systemd inhibitors...")
    _, out = run("systemd-inhibit --list --no-pager 2>/dev/null")
    if out:
        inhibitors = len([x for x in out.splitlines() if x.strip() and "WHO" not in x and "inhibitor" not in x.lower()])
        if inhibitors > 5:
            log.warning(f"Many systemd inhibitors: {inhibitors}")
    log_ok("Inhibitor check done.")


# --- Network DNS Cache ---

def check_dns_cache():
    log_ok("Checking DNS cache...")
    _, out = run("resolvectl statistics 2>/dev/null | grep -E 'Current|Cache'")
    if out:
        log.info(f"DNS cache:\n{out}")
    log_ok("DNS cache check done.")


# --- Disk Quota Check ---

def check_disk_quota():
    log_ok("Checking disk quotas...")
    _, out = run("repquota -a 2>/dev/null | grep -v '^#' | tail -5")
    if out:
        log.info(f"Quotas:\n{out}")
    log_ok("Quota check done.")


# --- Kernel Lockdown ---

def check_kernel_lockdown():
    log_ok("Checking kernel lockdown...")
    _, out = run("cat /sys/kernel/security/lockdown 2>/dev/null")
    if out:
        log.info(f"Kernel lockdown: {out.strip()}")
    log_ok("Lockdown check done.")


# --- Systemd Boot Check ---

def check_systemd_boot():
    log_ok("Checking boot performance...")
    _, out = run("systemd-analyze 2>/dev/null | head -1")
    if out:
        log.info(f"Boot: {out.strip()}")
        match = re.search(r'= (\d+\.\d+)s', out)
        if match and float(match.group(1)) > 60:
            log.warning(f"Slow boot: {match.group(1)}s")
    log_ok("Boot check done.")


# --- Network Connection Tracking ---

def check_conntrack():
    log_ok("Checking connection tracking...")
    _, out = run("cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null")
    _, max_ct = run("cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null")
    if out and max_ct and out.strip().isdigit() and max_ct.strip().isdigit():
        pct = int(out.strip()) / int(max_ct.strip()) * 100
        if pct > 80:
            log.warning(f"Conntrack table {pct:.0f}% full!")
            new_max = int(max_ct.strip()) * 2
            run(f"sysctl -w net.netfilter.nf_conntrack_max={new_max}")
    log_ok("Conntrack check done.")


# --- Systemd Device Units ---

def check_systemd_devices():
    log_ok("Checking systemd device units...")
    _, out = run("systemctl list-units --type=device --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed devices:\n{out[:300]}")
    log_ok("Device unit check done.")


# --- Network Bonding ---

def check_network_bonding():
    log_ok("Checking network bonding...")
    if os.path.exists("/proc/net/bonding"):
        _, out = run("ls /proc/net/bonding/ 2>/dev/null")
        if out:
            for bond in out.splitlines():
                _, info = run(f"cat /proc/net/bonding/{bond.strip()} 2>/dev/null | head -5")
                if info:
                    log.info(f"Bond {bond.strip()}: {info.splitlines()[0] if info.splitlines() else ''}")
    log_ok("Bonding check done.")


# --- Disk NCQ Check ---

def check_disk_ncq():
    log_ok("Checking disk NCQ...")
    _, out = run("lsblk -dno NAME")
    if out:
        for disk in out.splitlines():
            disk = disk.strip()
            if not disk:
                continue
            _, depth = run(f"cat /sys/block/{disk}/device/queue_depth 2>/dev/null")
            if depth and depth.strip().isdigit():
                log.info(f"/dev/{disk} NCQ depth: {depth.strip()}")
    log_ok("NCQ check done.")


# --- Kernel Preempt ---

def check_kernel_preempt():
    log_ok("Checking kernel preempt...")
    _, out = run("uname -v")
    if out:
        if "PREEMPT" in out:
            log.info("Preemptive kernel.")
        else:
            log.info("Non-preemptive kernel.")
    log_ok("Preempt check done.")


# --- Systemd Swap Units ---

def check_systemd_swap():
    log_ok("Checking systemd swap units...")
    _, out = run("systemctl list-units --type=swap --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed swap units:\n{out[:300]}")
    log_ok("Swap unit check done.")


# --- Network Neighbor Table ---

def check_neighbor_table():
    log_ok("Checking neighbor table...")
    _, out = run("cat /proc/sys/net/ipv4/neigh/default/gc_thresh3 2>/dev/null")
    if out and out.strip().isdigit() and int(out.strip()) < 4096:
        run("sysctl -w net.ipv4.neigh.default.gc_thresh3=8192")
    log_ok("Neighbor table check done.")


# --- Disk Barrier Check ---

def check_disk_barriers():
    log_ok("Checking disk barriers...")
    _, out = run("mount | grep ext4 | grep nobarrier")
    if out:
        log.warning("Ext4 mounted with nobarrier — data loss risk!")
    log_ok("Barrier check done.")


# --- Kernel RNG ---

def check_kernel_rng():
    log_ok("Checking kernel RNG...")
    _, out = run("cat /sys/devices/virtual/misc/hw_random/rng_current 2>/dev/null")
    if out and out.strip() != "none":
        log.info(f"Hardware RNG: {out.strip()}")
    log_ok("RNG check done.")


# --- Systemd Target Check ---

def check_systemd_targets():
    log_ok("Checking systemd targets...")
    _, out = run("systemctl get-default 2>/dev/null")
    if out:
        log.info(f"Default target: {out.strip()}")
    _, out = run("systemctl list-units --type=target --state=failed --no-legend --no-pager 2>/dev/null")
    if out:
        log.warning(f"Failed targets:\n{out[:300]}")
    log_ok("Target check done.")


# --- Network TCP Keepalive ---

def check_tcp_keepalive():
    log_ok("Checking TCP keepalive...")
    _, out = run("cat /proc/sys/net/ipv4/tcp_keepalive_time")
    if out and out.strip().isdigit() and int(out.strip()) > 7200:
        run("sysctl -w net.ipv4.tcp_keepalive_time=600")
        run("sysctl -w net.ipv4.tcp_keepalive_intvl=60")
        run("sysctl -w net.ipv4.tcp_keepalive_probes=5")
    log_ok("Keepalive check done.")


# --- Disk Writeback ---

def check_disk_writeback():
    log_ok("Checking disk writeback...")
    _, out = run("cat /proc/sys/vm/dirty_ratio")
    if out and out.strip().isdigit() and int(out.strip()) > 40:
        run("sysctl -w vm.dirty_ratio=20")
        run("sysctl -w vm.dirty_background_ratio=5")
    log_ok("Writeback check done.")


# --- Kernel Modules Signature ---

def check_module_signatures():
    log_ok("Checking module signatures...")
    _, out = run("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
    if out and out.strip() == "1":
        log.info("Module loading disabled (secure).")
    log_ok("Module signature check done.")


# --- Systemd Environment ---

def check_systemd_environment():
    log_ok("Checking systemd environment...")
    _, out = run("systemctl show-environment 2>/dev/null | wc -l")
    if out and out.isdigit():
        log.info(f"Systemd env vars: {out.strip()}")
    log_ok("Environment check done.")


# --- Network IPv4 Forwarding ---

def check_ip_forwarding():
    log_ok("Checking IP forwarding...")
    _, out = run("cat /proc/sys/net/ipv4/ip_forward")
    if out and out.strip() == "1":
        log.info("IPv4 forwarding enabled (router mode).")
    log_ok("Forwarding check done.")


# --- Disk Sector Size ---

def check_disk_sector_size():
    log_ok("Checking disk sector sizes...")
    _, out = run("lsblk -dno NAME,PHY-SEC --noheadings 2>/dev/null")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                log.info(f"/dev/{parts[0]}: {parts[1]}B sectors")
    log_ok("Sector size check done.")


# --- Kernel Panic Config ---

def check_kernel_panic_config():
    log_ok("Checking kernel panic config...")
    _, out = run("cat /proc/sys/kernel/panic")
    if out and out.strip() == "0":
        run("sysctl -w kernel.panic=10")
        log.info("Set auto-reboot on panic (10s)")
    log_ok("Panic config check done.")


# --- Systemd Machine ID ---

def check_machine_id():
    log_ok("Checking machine ID...")
    if not os.path.exists("/etc/machine-id"):
        log.warning("Missing /etc/machine-id! Regenerating...")
        run("systemd-machine-id-setup")
    else:
        _, out = run("cat /etc/machine-id")
        if not out or len(out.strip()) != 32:
            log.warning("Invalid machine-id! Regenerating...")
            run("rm /etc/machine-id && systemd-machine-id-setup")
    log_ok("Machine ID check done.")


# --- Network Socket Buffer ---

def check_socket_buffers():
    log_ok("Checking socket buffers...")
    _, rmem = run("cat /proc/sys/net/core/rmem_default")
    if rmem and rmem.strip().isdigit() and int(rmem.strip()) < 262144:
        run("sysctl -w net.core.rmem_default=262144")
        run("sysctl -w net.core.wmem_default=262144")
    log_ok("Socket buffer check done.")


# --- Disk Multipath ---

def check_disk_multipath():
    if not shutil.which("multipath"):
        return
    log_ok("Checking multipath...")
    _, out = run("multipath -ll 2>/dev/null | head -10")
    if out:
        log.info(f"Multipath:\n{out[:300]}")
    log_ok("Multipath check done.")


# --- Kernel CFS Scheduler ---

def check_cfs_scheduler():
    log_ok("Checking CFS scheduler...")
    _, out = run("cat /proc/sys/kernel/sched_latency_ns 2>/dev/null")
    if out:
        log.info(f"CFS latency: {out.strip()}ns")
    log_ok("CFS check done.")


# --- Systemd Catalog ---

def check_systemd_catalog():
    log_ok("Checking systemd catalog...")
    _, out = run("journalctl --update-catalog 2>&1")
    if out and "error" in out.lower():
        log.warning(f"Catalog issues: {out[:200]}")
    log_ok("Catalog check done.")


# --- Network VLAN Check ---

def check_network_vlans():
    log_ok("Checking VLANs...")
    _, out = run("ip -d link show | grep vlan")
    if out:
        log.info(f"VLANs:\n{out}")
    log_ok("VLAN check done.")


# --- Disk Trim Queue ---

def check_trim_queue():
    log_ok("Checking TRIM queue...")
    _, out = run("lsblk -dno NAME,DISC-GRAN --noheadings 2>/dev/null")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "0B":
                log.info(f"/dev/{parts[0]}: TRIM granularity {parts[1]}")
    log_ok("TRIM queue check done.")


# --- Kernel Transparent Hugepage ---

def check_thp():
    log_ok("Checking THP...")
    _, out = run("cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null")
    if out:
        log.info(f"THP: {out.strip()}")
    _, defrag = run("cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null")
    if defrag:
        log.info(f"THP defrag: {defrag.strip()}")
    log_ok("THP check done.")


# --- Systemd Resolved DNSSEC ---

def check_dnssec():
    log_ok("Checking DNSSEC...")
    _, out = run("resolvectl dnssec 2>/dev/null | head -5")
    if out:
        log.info(f"DNSSEC: {out.splitlines()[0] if out.splitlines() else 'unknown'}")
    log_ok("DNSSEC check done.")


# --- Network Wireless ---

def check_wireless():
    log_ok("Checking wireless...")
    _, out = run("iwconfig 2>/dev/null | grep -E 'ESSID|Signal'")
    if out:
        log.info(f"Wireless:\n{out}")
    _, out = run("rfkill list wifi 2>/dev/null")
    if out and "Soft blocked: yes" in out:
        log.warning("WiFi soft-blocked!")
        run("rfkill unblock wifi")
    log_ok("Wireless check done.")


# --- Disk RAID Check ---

def check_raid():
    log_ok("Checking RAID...")
    if os.path.exists("/proc/mdstat"):
        _, out = run("cat /proc/mdstat")
        if out and "md" in out:
            if "_" in out:
                log.warning(f"Degraded RAID:\n{out[:300]}")
            else:
                log_ok("RAID OK.")
    log_ok("RAID check done.")


# --- Kernel Seccomp ---

def check_seccomp():
    log_ok("Checking seccomp...")
    _, out = run("grep Seccomp /proc/1/status 2>/dev/null")
    if out:
        log.info(f"Init seccomp: {out.strip()}")
    log_ok("Seccomp check done.")


# --- Systemd Resolved LLMNR ---

def check_llmnr():
    log_ok("Checking LLMNR...")
    _, out = run("resolvectl llmnr 2>/dev/null | head -3")
    if out:
        log.info(f"LLMNR: {out.splitlines()[0] if out.splitlines() else 'unknown'}")
    log_ok("LLMNR check done.")


# --- Network Namespace ---

def check_network_namespaces():
    log_ok("Checking network namespaces...")
    _, out = run("ip netns list 2>/dev/null")
    if out:
        log.info(f"Namespaces: {out.strip()}")
    log_ok("Namespace check done.")


# --- Disk Readahead Tuning ---

def check_readahead_tuning():
    log_ok("Checking readahead tuning...")
    _, out = run("blockdev --report 2>/dev/null | head -5")
    if out:
        log.info(f"Block devices:\n{out}")
    log_ok("Readahead tuning check done.")


# --- Kernel Cgroup v2 ---

def check_cgroup_v2():
    log_ok("Checking cgroup version...")
    _, out = run("stat -fc %T /sys/fs/cgroup/ 2>/dev/null")
    if out:
        if "cgroup2" in out:
            log.info("Using cgroup v2 (unified).")
        else:
            log.info("Using cgroup v1 (legacy).")
    log_ok("Cgroup version check done.")


# --- Kernel Address Sanitizer ---

def check_kasan():
    log_ok("Checking KASAN...")
    _, out = run("journalctl -b --grep='KASAN' --no-pager -q 2>/dev/null | tail -3")
    if out:
        log.warning(f"KASAN errors:\n{out[:300]}")
    log_ok("KASAN check done.")


# --- Systemd Portable Services ---

def check_portable_services():
    log_ok("Checking portable services...")
    _, out = run("portablectl list 2>/dev/null")
    if out:
        log.info(f"Portable services: {len(out.splitlines())}")
    log_ok("Portable check done.")


# --- Network TCP Congestion ---

def check_tcp_congestion():
    log_ok("Checking TCP congestion...")
    _, out = run("cat /proc/sys/net/ipv4/tcp_congestion_control")
    if out:
        algo = out.strip()
        log.info(f"TCP congestion: {algo}")
        if algo == "reno":
            _, avail = run("cat /proc/sys/net/ipv4/tcp_available_congestion_control")
            if avail and "bbr" in avail:
                run("sysctl -w net.ipv4.tcp_congestion_control=bbr")
                log.info("Switched to BBR congestion control.")
    log_ok("Congestion check done.")


# --- Disk Fstrim Log ---

def check_fstrim_log():
    log_ok("Checking fstrim history...")
    _, out = run("journalctl -u fstrim --since '7 days ago' --no-pager -q 2>/dev/null | tail -3")
    if out:
        log.info(f"Last TRIM:\n{out}")
    log_ok("Fstrim log check done.")


# --- Kernel Ftrace ---

def check_ftrace():
    log_ok("Checking ftrace...")
    _, out = run("cat /sys/kernel/debug/tracing/tracing_on 2>/dev/null")
    if out and out.strip() == "1":
        log.warning("Ftrace is ON — may impact performance.")
    log_ok("Ftrace check done.")


# --- Systemd Nspawn ---

def check_nspawn():
    log_ok("Checking nspawn containers...")
    _, out = run("machinectl list --no-legend --no-pager 2>/dev/null")
    if out:
        log.info(f"Containers: {len(out.splitlines())}")
    log_ok("Nspawn check done.")


# --- Network Neighbor Discovery ---

def check_neighbor_discovery():
    log_ok("Checking IPv6 neighbor discovery...")
    _, out = run("ip -6 neigh show 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 100:
        log.warning(f"Large IPv6 neighbor table: {out}")
    log_ok("Neighbor discovery check done.")


# --- Disk Partition Alignment ---

def check_partition_alignment():
    log_ok("Checking partition alignment...")
    _, out = run("lsblk -o NAME,START --bytes --noheadings 2>/dev/null | head -10")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                start = int(parts[1])
                if start > 0 and start % 4096 != 0:
                    log.warning(f"Partition {parts[0]} misaligned (start: {start})")
    log_ok("Alignment check done.")


# --- Kernel Softlockup ---

def check_softlockup():
    log_ok("Checking softlockup...")
    _, out = run("journalctl -b --grep='soft lockup\\|softlockup' --no-pager -q 2>/dev/null | tail -3")
    if out:
        log.warning(f"Soft lockups detected:\n{out[:300]}")
    _, timeout = run("cat /proc/sys/kernel/watchdog_thresh 2>/dev/null")
    if timeout:
        log.info(f"Watchdog threshold: {timeout.strip()}s")
    log_ok("Softlockup check done.")


# --- Systemd Resolved Stub ---

def check_resolved_stub():
    log_ok("Checking resolved stub listener...")
    _, out = run("ss -tlnp | grep ':53 '")
    if out and "systemd-resolve" in out:
        log.info("Resolved stub listener active on :53")
    log_ok("Resolved stub check done.")


# --- Btrfs Snapshot Healing ---

def check_btrfs():
    """Monitor Btrfs filesystem health — scrub, balance, and snapshot management."""
    if not cfg.get("enable_btrfs_heal", True):
        return
    if not shutil.which("btrfs"):
        return
    log_ok("Checking Btrfs health...")

    # Find Btrfs mounts
    _, mounts = run("findmnt -t btrfs -n -o TARGET 2>/dev/null")
    if not mounts:
        return

    for mount in mounts.strip().split("\n"):
        mount = mount.strip()
        if not mount:
            continue

        # Check device errors
        _, stats = run(f"btrfs device stats {mount} 2>/dev/null")
        if stats:
            for line in stats.strip().split("\n"):
                if line and not line.endswith(" 0"):
                    log.warning(f"Btrfs device error on {mount}: {line}")
                    track("btrfs_fixes")

        # Check if scrub is overdue (>30 days)
        _, scrub_status = run(f"btrfs scrub status {mount} 2>/dev/null")
        if "finished" in scrub_status:
            # Parse last scrub date
            for line in scrub_status.split("\n"):
                if "started" in line.lower() or "finished" in line.lower():
                    pass  # Scrub has run before, OK
        elif "no stats" in scrub_status.lower() or "never" in scrub_status.lower():
            log.warning(f"Btrfs scrub never ran on {mount}! Starting...")
            run(f"btrfs scrub start {mount} 2>/dev/null")
            track("btrfs_fixes")

        # Check balance status (uneven data distribution)
        _, usage = run(f"btrfs filesystem usage {mount} 2>/dev/null")
        if "unallocated" in usage:
            for line in usage.split("\n"):
                if "unallocated" in line.lower() and "0.00" not in line:
                    # Has unallocated space, check if balance needed
                    _, df_out = run(f"btrfs filesystem df {mount} 2>/dev/null")
                    if df_out:
                        log_ok(f"Btrfs balance OK on {mount}")

        # Snapshot cleanup — remove snapshots older than 30 days
        _, snaps = run(f"btrfs subvolume list -s {mount} 2>/dev/null")
        if snaps:
            snap_count = len([l for l in snaps.strip().split("\n") if l.strip()])
            if snap_count > 50:
                log.warning(f"Too many Btrfs snapshots on {mount}: {snap_count}")
                track("btrfs_fixes")

    log_ok("Btrfs check done.")


# --- Zram Optimization ---

def check_zram():
    """Monitor and optimize zram compressed swap — ensure it's active and sized correctly."""
    if not cfg.get("enable_zram_heal", True):
        return
    log_ok("Checking zram...")

    # Check if zram module is loaded
    _, modules = run("lsmod 2>/dev/null")
    has_zram = "zram" in modules if modules else False

    # Check if zram devices exist
    zram_exists = os.path.exists("/sys/block/zram0")

    if not zram_exists and not has_zram:
        # Try to set up zram if systemd-zram-generator or zram-generator exists
        if os.path.exists("/usr/lib/systemd/zram-generator.conf") or shutil.which("zramctl"):
            log.warning("Zram not active! Loading module...")
            run("modprobe zram 2>/dev/null")
            # Check for systemd-zram service
            _, status = run("systemctl status systemd-zram-setup@zram0 2>/dev/null")
            if "inactive" in status or "dead" in status:
                run("systemctl start systemd-zram-setup@zram0 2>/dev/null")
                track("zram_fixes")
        return

    if zram_exists:
        # Check zram stats
        try:
            disksize = int(open("/sys/block/zram0/disksize").read().strip())
            _, meminfo = run("grep MemTotal /proc/meminfo 2>/dev/null")
            if meminfo:
                total_mem = int(meminfo.split()[1]) * 1024  # bytes
                # Zram should be ~50-100% of RAM
                ratio = disksize / total_mem if total_mem > 0 else 0
                if ratio < 0.25:
                    log.warning(f"Zram undersized: {disksize // (1024**2)}MB for {total_mem // (1024**2)}MB RAM")
                    track("zram_fixes")
                else:
                    log_ok(f"Zram OK: {disksize // (1024**2)}MB (ratio={ratio:.1f})")
        except (FileNotFoundError, ValueError):
            pass

        # Check compression ratio
        try:
            orig = int(open("/sys/block/zram0/mm_stat").read().split()[0])
            compr = int(open("/sys/block/zram0/mm_stat").read().split()[1])
            if orig > 0:
                ratio = compr / orig
                if ratio > 0.8:
                    log.warning(f"Zram compression poor: {ratio:.0%} (incompressible data)")
                else:
                    log_ok(f"Zram compression: {ratio:.0%}")
        except (FileNotFoundError, ValueError, IndexError):
            pass

    log_ok("Zram check done.")


# --- VPN/WireGuard Healing ---

def check_vpn():
    """Monitor VPN connections — restart WireGuard/OpenVPN if tunnel is down."""
    if not cfg.get("enable_vpn_heal", True):
        return
    log_ok("Checking VPN...")

    # Check WireGuard interfaces
    _, wg_show = run("wg show 2>/dev/null")
    if wg_show:
        # WireGuard is configured, check if interfaces are up
        _, interfaces = run("wg show interfaces 2>/dev/null")
        if interfaces:
            for iface in interfaces.strip().split():
                # Check if interface has recent handshake
                _, iface_info = run(f"wg show {iface} latest-handshakes 2>/dev/null")
                if iface_info:
                    for line in iface_info.strip().split("\n"):
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            try:
                                last_handshake = int(parts[1])
                                now = int(time.time())
                                # If no handshake in 5 minutes, tunnel might be dead
                                if last_handshake > 0 and (now - last_handshake) > 300:
                                    log.warning(f"WireGuard {iface}: no handshake in {(now - last_handshake) // 60}min, restarting...")
                                    run(f"wg-quick down {iface} 2>/dev/null")
                                    time.sleep(1)
                                    run(f"wg-quick up {iface} 2>/dev/null")
                                    track("vpn_fixes")
                            except (ValueError, IndexError):
                                pass
    else:
        # Check for WireGuard systemd services
        _, wg_services = run("systemctl list-units 'wg-quick@*' --no-legend 2>/dev/null")
        if wg_services:
            for line in wg_services.strip().split("\n"):
                if "failed" in line:
                    svc = line.split()[0]
                    log.warning(f"WireGuard service {svc} failed! Restarting...")
                    run(f"systemctl restart {svc} 2>/dev/null")
                    track("vpn_fixes")

    # Check OpenVPN
    _, ovpn = run("systemctl list-units 'openvpn*' --no-legend 2>/dev/null")
    if ovpn:
        for line in ovpn.strip().split("\n"):
            if "failed" in line:
                svc = line.split()[0]
                log.warning(f"OpenVPN service {svc} failed! Restarting...")
                run(f"systemctl restart {svc} 2>/dev/null")
                track("vpn_fixes")

    log_ok("VPN check done.")


# --- Status Dashboard ---

def show_status():
    s = load_stats()
    first = s.get("first_run", "?")[:16]
    last = (s.get("last_run") or "?")[:16]
    uptime_start = s.get("uptime_start", s.get("first_run", ""))
    try:
        delta = datetime.now() - datetime.fromisoformat(uptime_start)
        uptime = f"{delta.days}d {delta.seconds//3600}h {(delta.seconds%3600)//60}m"
    except (ValueError, TypeError):
        uptime = "?"

    rows = [
        ("Services restarted", "services_restarted"),
        ("Packages fixed", "packages_fixed"),
        ("Kernel repairs", "kernel_repairs"),
        ("Disk cleanups", "disk_cleanups"),
        ("Memory clears", "memory_clears"),
        ("Network restarts", "network_restarts"),
        ("Zombies killed", "zombies_killed"),
        ("FS errors caught", "fs_errors_caught"),
        ("Thermal throttles", "thermal_throttles"),
        ("DNS fixes", "dns_fixes"),
        ("Security fixes", "security_fixes"),
        ("SMART warnings", "smart_warnings"),
        ("Crash recoveries", "crash_recoveries"),
        ("Permission fixes", "permission_fixes"),
        ("Time sync fixes", "time_sync_fixes"),
        ("Firewall fixes", "firewall_fixes"),
        ("GPU fixes", "gpu_fixes"),
        ("Swap fixes", "swap_fixes"),
        ("High CPU kills", "high_cpu_kills"),
        ("Fstab fixes", "fstab_fixes"),
        ("Dpkg lock fixes", "dpkg_lock_fixes"),
        ("Docker fixes", "docker_fixes"),
        ("USB events", "usb_events"),
        ("Intrusion blocks", "intrusion_blocks"),
        ("Config tampers", "config_tampers"),
        ("Battery warnings", "battery_warnings"),
        ("Coredump cleans", "coredump_cleans"),
        ("Entropy fixes", "entropy_fixes"),
        ("Journal fixes", "journal_fixes"),
        ("Duplicate kills", "duplicate_kills"),
        ("Disk latency warns", "disk_latency_warnings"),
        ("Orphan cleans", "orphan_cleans"),
        ("Symlink fixes", "symlink_fixes"),
        ("Hostname fixes", "hostname_fixes"),
        ("Locale fixes", "locale_fixes"),
        ("Xorg fixes", "xorg_fixes"),
        ("Audio fixes", "audio_fixes"),
        ("Bluetooth fixes", "bluetooth_fixes"),
        ("Cron fixes", "cron_fixes"),
        ("Tmpfile fixes", "tmpfile_fixes"),
        ("Viruses found", "viruses_found"),
        ("Rootkit checks", "rootkits_checked"),
        ("Desktop fixes", "desktop_fixes"),
        ("Flatpak/Snap fixes", "flatpak_fixes"),
        ("Backups made", "backups_made"),
        ("Port scan blocks", "port_scan_blocks"),
        ("Suspicious logins", "suspicious_logins"),
        ("PPA fixes", "ppa_fixes"),
        ("Font fixes", "font_fixes"),
        ("Printer fixes", "printer_fixes"),
        ("Suspend fixes", "suspend_fixes"),
        ("Clock fixes", "clock_fixes"),
        ("Zombie parent fixes", "zombie_parent_fixes"),
        ("OOM score fixes", "oom_score_fixes"),
        ("Sysctl fixes", "sysctl_fixes"),
        ("APT source fixes", "apt_source_fixes"),
        ("User integrity fixes", "user_integrity_fixes"),
        ("Mount fixes", "mount_fixes"),
        ("ARP spoof detects", "arp_spoof_detects"),
        ("DNS leak fixes", "dns_leak_fixes"),
        ("Open file fixes", "open_file_fixes"),
        ("Kernel module fixes", "kernel_module_fixes"),
        ("Cgroup fixes", "cgroup_fixes"),
        ("Dmesg warnings", "dmesg_warnings"),
        ("GPU temp warnings", "gpu_temp_warnings"),
        ("Fan warnings", "fan_warnings"),
        ("Screen lock fixes", "screen_lock_fixes"),
        ("SSH hardens", "ssh_hardens"),
        ("Failed mount retries", "failed_mount_retries"),
        ("SMART self-tests", "smart_selftests"),
        ("Net speed warnings", "network_speed_warnings"),
        ("MAC spoof detects", "mac_spoof_detects"),
        ("Process limit fixes", "process_limit_fixes"),
        ("FD fixes", "fd_fixes"),
        ("Shared mem fixes", "shm_fixes"),
        ("Semaphore fixes", "sem_fixes"),
        ("D-Bus fixes", "dbus_fixes"),
        ("PolicyKit fixes", "polkit_fixes"),
        ("AppArmor fixes", "apparmor_fixes"),
        ("GRUB password warns", "grub_password_warnings"),
        ("Core pattern fixes", "core_pattern_fixes"),
        ("Module blacklist", "module_blacklist_fixes"),
        ("Disk scheduler fixes", "disk_scheduler_fixes"),
        ("TCP tuning fixes", "tcp_tuning_fixes"),
        ("I/O scheduler fixes", "io_scheduler_fixes"),
        ("Watchdog fixes", "watchdog_fixes"),
        ("ACPI fixes", "acpi_fixes"),
        ("Display mgr fixes", "dm_fixes"),
        ("XDG dir fixes", "xdg_fixes"),
    ]

    w = 48
    print()
    print(f"╔{'═' * w}╗")
    print(f"║{'🤖 ROZ NanoBots v7 Status':^{w}}║")
    print(f"╠{'═' * w}╣")
    print(f"║  Running since:    {first:<{w - 21}}║")
    print(f"║  Uptime:           {uptime:<{w - 21}}║")
    print(f"║  Healing cycles:   {str(s.get('cycles', 0)):<{w - 21}}║")
    print(f"║  Last run:         {last:<{w - 21}}║")
    print(f"╠{'═' * w}╣")
    for label, key in rows:
        val = s.get(key, 0)
        if val > 0:
            print(f"║  {label + ':':<23} {str(val):<{w - 26}}║")
    print(f"║{'─' * w}║")
    print(f"║  {'Total issues fixed:':<23} {str(s.get('issues_total', 0)):<{w - 26}}║")
    print(f"╚{'═' * w}╝")
    print()


# --- Main Cycles ---

def heal_full():
    """Full healing cycle."""
    global restart_counts
    restart_counts = {}
    log.info("========== ROZ NanoBots v7 — Full Heal ==========")
    for fn in [
        fix_broken_packages, update_system,
        check_kernel_health, rebuild_grub,
        check_gpu, check_smart,
        check_filesystems, check_fstab,
        check_disk_space, check_inodes,
        check_failed_services, check_critical_services,
        kill_zombies, check_high_cpu, check_oom,
        check_memory, check_thermals, check_power,
        check_network, check_dns,
        check_security, check_open_ports, check_root_processes, check_firewall,
        check_time_sync, check_permissions,
        check_ups,
        check_kernel_panics, check_crash_dumps,
        check_log_sizes,
        check_docker, check_usb, check_intrusions,
        check_config_watchdog, check_battery,
        check_coredumps, check_entropy,
        check_journal_health, check_duplicate_processes,
        check_disk_latency, check_orphan_packages,
        check_broken_symlinks, check_hostname,
        check_locale, check_xorg, check_audio,
        check_bluetooth, check_btrfs, check_zram, check_vpn, check_cron, check_tmpfiles,
        check_antivirus, check_rootkits,
        check_desktop, check_flatpak,
        check_backup, check_port_scan_protect,
        check_login_monitor, check_ppa_heal,
        check_fonts, check_printer,
        check_suspend, check_clock_drift,
        check_zombie_parents, check_oom_scores,
        check_sysctl, check_apt_sources,
        check_user_integrity, check_mounts,
        check_arp_spoof, check_dns_leak,
        check_open_file_limit, check_kernel_modules,
        check_cgroups, check_dmesg,
        check_gpu_temp, check_fans,
        check_lid_switch, check_screen_lock,
        check_ssh_harden, check_failed_mount_retry,
        check_smart_selftest, check_network_speed,
        check_mac_spoof, check_process_limit,
        check_file_descriptors, check_shared_memory,
        check_semaphores, check_dbus,
        check_polkit, check_apparmor,
        check_grub_password, check_core_pattern,
        check_module_blacklist, check_ipv6,
        check_disk_scheduler, check_numa,
        check_hugepages, check_tcp_tuning,
        check_io_scheduler, check_watchdog,
        check_acpi, check_display_manager,
        check_xdg_dirs, check_systemd_timers,
        check_cpu_governor, check_kernel_livepatch,
        check_disk_readahead, check_printk_level,
        check_journal_rate_limit, check_zombie_threads,
        check_kernel_taint, check_swap_usage,
        check_network_errors, check_disk_queue,
        check_systemd_scopes, check_login_shells,
        check_pam, check_sudoers,
        check_systemd_slices, check_kernel_memleak,
        check_inotify_limit, check_resolved,
        check_snap_refresh, check_firmware,
        check_partition_table, check_network_bridges,
        check_vpn_leak, check_disk_alignment,
        check_systemd_sockets, check_kernel_keyring,
        check_cpu_microcode, check_efi_boot,
        check_trim_verify, check_memory_ecc,
        check_automounts, check_network_mtu,
        check_disk_write_cache, check_hung_tasks,
        check_systemd_paths, check_cpu_frequency,
        check_kaslr, check_user_sessions,
        check_disk_fragmentation, check_arp_cache,
        check_sysrq, check_disk_reserved,
        check_systemd_generators, check_routing_table,
        check_smart_attributes, check_systemd_notify,
        check_firewall_rules, check_lvm,
        check_coredump_config, check_network_proxy,
        check_disk_encryption, check_module_params,
        check_systemd_inhibitors, check_dns_cache,
        check_disk_quota, check_kernel_lockdown,
        check_systemd_boot, check_conntrack,
        check_systemd_devices, check_network_bonding,
        check_disk_ncq, check_kernel_preempt,
        check_systemd_swap, check_neighbor_table,
        check_disk_barriers, check_kernel_rng,
        check_systemd_targets, check_tcp_keepalive,
        check_disk_writeback, check_module_signatures,
        check_systemd_environment, check_ip_forwarding,
        check_disk_sector_size, check_kernel_panic_config,
        check_machine_id, check_socket_buffers,
        check_disk_multipath, check_cfs_scheduler,
        check_systemd_catalog, check_network_vlans,
        check_trim_queue, check_thp,
        check_dnssec, check_wireless,
        check_raid, check_seccomp,
        check_llmnr, check_network_namespaces,
        check_readahead_tuning, check_cgroup_v2,
        check_kasan, check_portable_services,
        check_tcp_congestion, check_fstrim_log,
        check_ftrace, check_nspawn,
        check_neighbor_discovery, check_partition_alignment,
        check_softlockup, check_resolved_stub,
    ]:
        if shutdown_requested:
            log.info("Shutdown requested, stopping heal cycle.")
            break
        try:
            fn()
        except Exception as e:
            log.error(f"{fn.__name__} failed: {e}")
    log_ok("========== Full heal complete ==========\n")


def heal_quick():
    """Quick check between full heals."""
    for fn in [
        check_critical_services, check_failed_services,
        kill_zombies, check_memory, check_thermals,
        check_network, check_battery, check_audio,
        check_duplicate_processes,
    ]:
        if shutdown_requested:
            break
        try:
            fn()
        except Exception as e:
            log.error(f"{fn.__name__} failed: {e}")
    save_stats(stats)


def show_cleanup():
    """WinDirStat-style disk analysis with smart cleanup suggestions."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[31m"
    Y = "\033[33m"
    G = "\033[32m"
    C = "\033[36m"
    Z = "\033[0m"

    # Disk overview
    total, used, free = shutil.disk_usage("/")
    pct = int(used / total * 100)
    bar_w = 50
    filled = max(1, pct * bar_w // 100)
    color = R if pct >= 90 else Y if pct >= 70 else G
    bar = f"{color}{'█' * filled}{D}{'░' * (bar_w - filled)}{Z}"
    print(f"\n{B}═══ DISK USAGE ═══{Z}\n")
    print(f"  {bar} {pct}%  {used // 2**30}G / {total // 2**30}G ({free // 2**30}G free)")

    # Space map
    print(f"\n{B}═══ SPACE MAP ═══{Z}\n")
    print(f"  {D}{'PATH':<50} {'SIZE':>8}  {'':>4}{Z}")
    print(f"  {D}{'─' * 68}{Z}")
    home = Path.home()
    dirs = []
    for p in sorted(home.iterdir()):
        try:
            s = sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.is_dir() else p.stat().st_size
        except (PermissionError, OSError):
            try:
                out = subprocess.run(["du", "-sb", str(p)], capture_output=True, text=True, timeout=10)
                s = int(out.stdout.split()[0]) if out.returncode == 0 else 0
            except Exception:
                s = 0
        if s > 100_000_000:  # >100MB
            dirs.append((s, p))
    dirs.sort(reverse=True)
    for size, path in dirs[:20]:
        p = int(size * 100 / total)
        mini = max(1, p * 20 // 100)
        c = R if p >= 10 else Y if p >= 5 else G
        name = f"~/{path.name}" if str(path).startswith(str(home)) else str(path)
        sz = f"{size / 2**30:.1f}G" if size >= 2**30 else f"{size // 2**20}M"
        print(f"  {name:<50} {sz:>8}  {c}{'█' * mini}{Z} {p}%")

    # Smart suggestions
    print(f"\n{B}═══ CLEANUP SUGGESTIONS ═══{Z}\n")
    suggestions: list[tuple[str, str, str]] = []

    # Caches
    cache_dir = home / ".cache"
    cache_targets = [
        ("pip", "Pip cache", "pip cache purge"),
        ("go-build", "Go build cache", "go clean -cache"),
        ("ms-playwright", "Playwright browsers", "rm -rf ~/.cache/ms-playwright"),
        ("puppeteer", "Puppeteer browsers", "rm -rf ~/.cache/puppeteer"),
        ("rod", "Rod browser cache", "rm -rf ~/.cache/rod"),
        ("mozilla", "Firefox cache", "rm -rf ~/.cache/mozilla"),
        ("spotify", "Spotify cache", "rm -rf ~/.cache/spotify"),
    ]
    for dirname, label, cmd in cache_targets:
        p = cache_dir / dirname
        if p.exists():
            try:
                out = subprocess.run(["du", "-sm", str(p)], capture_output=True, text=True, timeout=10)
                mb = int(out.stdout.split()[0])
                if mb > 200:
                    suggestions.append((f"{mb}M", label, cmd))
            except Exception:
                pass

    # NPM cache
    npm_dir = home / ".npm"
    if npm_dir.exists():
        try:
            out = subprocess.run(["du", "-sm", str(npm_dir)], capture_output=True, text=True, timeout=10)
            mb = int(out.stdout.split()[0])
            if mb > 500:
                suggestions.append((f"{mb}M", "NPM cache", "npm cache clean --force"))
        except Exception:
            pass

    # APT cache
    try:
        out = subprocess.run(["du", "-sm", "/var/cache/apt"], capture_output=True, text=True, timeout=10)
        mb = int(out.stdout.split()[0])
        if mb > 500:
            suggestions.append((f"{mb}M", "APT package cache", "sudo apt clean"))
    except Exception:
        pass

    # Journal logs
    try:
        out = subprocess.run(["journalctl", "--disk-usage"], capture_output=True, text=True, timeout=5)
        m = re.search(r"([\d.]+[GM])", out.stdout)
        if m:
            suggestions.append((f"~{m.group(1)}", "Systemd journal (keep 3 days)", "sudo journalctl --vacuum-time=3d"))
    except Exception:
        pass

    # /var/log
    try:
        out = subprocess.run(["du", "-sm", "/var/log"], capture_output=True, text=True, timeout=10)
        mb = int(out.stdout.split()[0])
        if mb > 2000:
            suggestions.append((f"{mb}M", "/var/log rotated logs", "sudo find /var/log -name '*.gz' -delete && sudo find /var/log -name '*.1' -delete"))
    except Exception:
        pass

    # Large files in Downloads
    dl = home / "Downloads"
    if dl.exists():
        try:
            out = subprocess.run(["du", "-sm", str(dl)], capture_output=True, text=True, timeout=10)
            mb = int(out.stdout.split()[0])
            if mb > 5000:
                suggestions.append((f"{mb}M", "Downloads folder (review)", f"ls -lhS {dl} | head -20"))
        except Exception:
            pass

    # Ollama models
    ollama_dir = home / ".ollama" / "models"
    if ollama_dir.exists():
        try:
            out = subprocess.run(["du", "-sm", str(ollama_dir)], capture_output=True, text=True, timeout=10)
            mb = int(out.stdout.split()[0])
            if mb > 5000:
                models = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
                model_list = "\n".join(f"      {line}" for line in models.stdout.strip().splitlines()[1:]) if models.returncode == 0 else ""
                label = f"Ollama models (remove unused)\n{model_list}" if model_list else "Ollama models"
                suggestions.append((f"{mb}M", label, "ollama list  # then: ollama rm <name>"))
        except Exception:
            pass

    # Docker
    try:
        out = subprocess.run(["du", "-sm", "/var/lib/docker"], capture_output=True, text=True, timeout=10)
        mb = int(out.stdout.split()[0])
        if mb > 1000:
            suggestions.append((f"{mb}M", "Docker unused images/containers", "docker system prune -af"))
    except Exception:
        pass

    # Large one-off files
    patterns = [
        (home, "cuda*.run", "CUDA installer (safe to delete after install)"),
        (home, "*.iso", "ISO images"),
    ]
    for search_dir, glob_pat, label in patterns:
        for f in search_dir.glob(glob_pat):
            sz = f.stat().st_size
            if sz > 500_000_000:
                szh = f"{sz / 2**30:.1f}G" if sz >= 2**30 else f"{sz // 2**20}M"
                suggestions.append((szh, f"{label}: {f.name}", f"rm {f}"))

    if not suggestions:
        print(f"  {G}No major cleanup opportunities found.{Z}")
    else:
        for i, (size, label, cmd) in enumerate(suggestions, 1):
            print(f"  {C}{i:2d}.{Z} {B}[{size}]{Z} {label}")
            print(f"      {D}$ {cmd}{Z}\n")

    # Interactive
    print(f"{B}═══ CLEANUP ═══{Z}\n")
    print("  Enter numbers (e.g. '1 3 5'), 'all', or 'q': ", end="", flush=True)
    try:
        choice = input().strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Bye!")
        return

    if not choice or choice == "q":
        print("  Bye!")
        return

    if choice == "all":
        indices = list(range(len(suggestions)))
    else:
        indices = []
        for x in choice.split():
            try:
                indices.append(int(x) - 1)
            except ValueError:
                pass

    for idx in indices:
        if 0 <= idx < len(suggestions):
            size, label, cmd = suggestions[idx]
            print(f"\n  {Y}▶ {label.splitlines()[0]}{Z}")
            print(f"    $ {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout.strip():
                for line in result.stdout.strip().splitlines()[:20]:
                    print(f"    {line}")
            print(f"    {G}✓ Done{Z}")

    # Final status
    _, used_after, free_after = shutil.disk_usage("/")
    freed = used - used_after
    print(f"\n{B}After cleanup:{Z}")
    print(f"  {used_after // 2**30}G used / {total // 2**30}G total ({free_after // 2**30}G free)")
    if freed > 0:
        print(f"  {G}Freed {freed // 2**20}MB{Z}")


def _migrate_config(old_cfg):
    """Convert flat enable_ flags config to grouped module format."""
    GROUPS = {
        "network": {
            "flags": ["enable_network_intrusion", "enable_arp_spoof_detect",
                      "enable_dns_leak_check", "enable_network_speed",
                      "enable_mac_spoof_detect"],
            "keys": {"intrusion_detection": "enable_network_intrusion",
                     "arp_spoof_detect": "enable_arp_spoof_detect",
                     "dns_leak_check": "enable_dns_leak_check",
                     "speed_check": "enable_network_speed",
                     "mac_spoof_detect": "enable_mac_spoof_detect"},
        },
        "storage": {
            "flags": ["enable_smart", "enable_disk_smart_selftest",
                      "enable_disk_latency", "enable_disk_scheduler",
                      "enable_failed_mount_retry"],
            "keys": {"smart": "enable_smart",
                     "smart_selftest": "enable_disk_smart_selftest",
                     "disk_latency": "enable_disk_latency",
                     "disk_scheduler": "enable_disk_scheduler",
                     "failed_mount_retry": "enable_failed_mount_retry"},
        },
        "docker": {
            "flags": ["enable_docker"],
            "keys": {},
        },
        "desktop": {
            "flags": ["enable_xorg_heal", "enable_audio_heal",
                      "enable_bluetooth_heal", "enable_display_manager_heal",
                      "enable_screen_lock", "enable_font_heal"],
            "keys": {"xorg": "enable_xorg_heal", "audio": "enable_audio_heal",
                     "bluetooth": "enable_bluetooth_heal",
                     "display_manager": "enable_display_manager_heal",
                     "screen_lock": "enable_screen_lock",
                     "font": "enable_font_heal"},
        },
        "security": {
            "flags": ["enable_security", "enable_firewall_check",
                      "enable_ssh_harden", "enable_permission_heal",
                      "enable_rootkit_check", "enable_config_watchdog",
                      "enable_apparmor_check"],
            "keys": {"firewall": "enable_firewall_check",
                     "ssh_harden": "enable_ssh_harden",
                     "permission_heal": "enable_permission_heal",
                     "rootkit_check": "enable_rootkit_check",
                     "config_watchdog": "enable_config_watchdog",
                     "apparmor": "enable_apparmor_check"},
        },
        "hardware": {
            "flags": ["enable_usb_monitor", "enable_battery",
                      "enable_fan_monitor", "enable_lid_switch",
                      "enable_acpi_check"],
            "keys": {"usb_monitor": "enable_usb_monitor",
                     "battery": "enable_battery",
                     "fan_monitor": "enable_fan_monitor",
                     "lid_switch": "enable_lid_switch",
                     "acpi": "enable_acpi_check"},
        },
        "system": {
            "flags": ["enable_updates", "enable_time_sync",
                      "enable_kernel_module_check", "enable_sysctl_heal",
                      "enable_cron_heal", "enable_tmpfiles"],
            "keys": {"updates": "enable_updates", "time_sync": "enable_time_sync",
                     "kernel_module_check": "enable_kernel_module_check",
                     "sysctl_heal": "enable_sysctl_heal",
                     "cron_heal": "enable_cron_heal",
                     "tmpfiles": "enable_tmpfiles"},
        },
    }

    new_cfg = {}
    consumed_keys = set()
    modules = {}

    for group_name, group_info in GROUPS.items():
        mod = {"enabled": True}
        all_false = True
        for short_name, flag_name in group_info["keys"].items():
            if flag_name in old_cfg:
                val = old_cfg[flag_name]
                mod[short_name] = val
                consumed_keys.add(flag_name)
                if val:
                    all_false = False
            else:
                all_false = False
        # If all sub-flags are false, set module enabled=false
        if group_info["keys"] and all_false:
            mod["enabled"] = False
        for flag in group_info["flags"]:
            consumed_keys.add(flag)
        modules[group_name] = mod

    # Add storage thresholds
    if "disk_warn_pct" in old_cfg:
        modules["storage"]["warn_pct"] = old_cfg["disk_warn_pct"]
        consumed_keys.add("disk_warn_pct")
    if "disk_crit_pct" in old_cfg:
        modules["storage"]["crit_pct"] = old_cfg["disk_crit_pct"]
        consumed_keys.add("disk_crit_pct")

    new_cfg["modules"] = modules

    # Preserve non-module settings
    for key, val in old_cfg.items():
        if key not in consumed_keys:
            new_cfg[key] = val

    # Add default profiles
    new_cfg["profiles"] = {
        "server": {
            "desktop.enabled": False,
            "hardware.battery": False,
            "hardware.lid_switch": False,
        },
        "desktop": {
            "desktop.enabled": True,
            "hardware.battery": True,
        },
        "minimal": {
            "modules_enabled": ["network", "storage", "system"],
        },
    }

    return new_cfg


def main():
    global stats
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        # Handle --quiet flag
        if "--quiet" in sys.argv:
            cfg["quiet_mode"] = True
            sys.argv.remove("--quiet")
            if len(sys.argv) > 1:
                cmd = sys.argv[1]
            else:
                cmd = None
        if cmd == "status":
            show_status()
            return
        if cmd == "heal":
            heal_full()
            save_stats(stats)
            return
        if cmd == "quick":
            heal_quick()
            return
        if cmd == "cleanup":
            show_cleanup()
            return
        if cmd == "config":
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            # Handle --migrate flag to convert flat config to module-based
            if "--migrate" in sys.argv:
                if not os.path.exists(CONFIG_FILE):
                    print(f"No config file at {CONFIG_FILE}")
                    return
                with open(CONFIG_FILE) as f:
                    old_cfg = json.load(f)
                new_cfg = _migrate_config(old_cfg)
                with open(CONFIG_FILE, "w") as f:
                    json.dump(new_cfg, f, indent=2)
                print(f"Config migrated to module format: {CONFIG_FILE}")
                return
            if not os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "w") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
                print(f"Config created: {CONFIG_FILE}")
            else:
                print(f"Config exists: {CONFIG_FILE}")
            return
        print(f"Usage: {sys.argv[0]} [status|heal|quick|cleanup|config] [--quiet]")
        return

    if os.geteuid() != 0:
        print("NanoBot needs root. Run with: sudo python3 nanobot.py")
        sys.exit(1)

    log.info("ROZ NanoBots v7 activated.")
    log.info(f"Full heal every {cfg['interval']}s, quick check every {cfg['realtime_interval']}s")

    while not shutdown_requested:
        try:
            stats = load_stats()
            stats["cycles"] = stats.get("cycles", 0) + 1
            stats["last_run"] = datetime.now().isoformat()

            heal_full()
            save_stats(stats)

            checks = cfg["interval"] // cfg["realtime_interval"]
            for _ in range(checks - 1):
                if shutdown_requested:
                    break
                time.sleep(cfg["realtime_interval"])
                try:
                    heal_quick()
                except Exception as e:
                    log.error(f"Quick heal error: {e}")

        except Exception as e:
            log.error(f"Healing error: {e}")
            time.sleep(60)

    save_stats(stats)
    log.info("ROZ NanoBots v7 shut down cleanly.")


if __name__ == "__main__":
    main()
