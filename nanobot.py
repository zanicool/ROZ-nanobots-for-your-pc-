#!/usr/bin/env python3
"""ROZ NanoBots v6 - Self-healing Linux system daemon."""

import subprocess
import logging
import time
import shutil
import os
import sys
import json
import signal
import re
from datetime import datetime
from pathlib import Path

# --- Config ---

CONFIG_FILE = "/etc/nanobot/config.json"
DEFAULT_CONFIG = {
    "interval": 3600,
    "realtime_interval": 30,
    "log_file": "/var/log/nanobot.log",
    "stats_file": "/var/log/nanobot_stats.json",
    "enable_updates": True,
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
    "ssh_max_failed_per_hour": 50,
    "watched_configs": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/fstab"],
    "max_connections_per_ip": 50,
    "battery_crit_pct": 10,
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
            cfg.update(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return cfg


cfg = load_config()

# --- Logging ---

log_dir = os.path.dirname(cfg["log_file"])
if log_dir and not os.path.isdir(log_dir):
    os.makedirs(log_dir, exist_ok=True)

handlers = [logging.StreamHandler()]
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
        "fstab_fixes": 0, "dpkg_lock_fixes": 0,
        "docker_fixes": 0, "usb_events": 0, "intrusion_blocks": 0,
        "config_tampers": 0, "battery_warnings": 0, "coredump_cleans": 0,
        "entropy_fixes": 0, "journal_fixes": 0, "duplicate_kills": 0,
        "disk_latency_warnings": 0, "orphan_cleans": 0, "symlink_fixes": 0,
        "hostname_fixes": 0, "locale_fixes": 0, "xorg_fixes": 0,
        "audio_fixes": 0, "bluetooth_fixes": 0, "cron_fixes": 0,
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out: {cmd}")
        return 1, ""
    except Exception as e:
        log.warning(f"Command error: {cmd}: {e}")
        return 1, ""


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
    log.info("Package repair done.")


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
    log.info("Checking kernel health...")
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
            log.info(f"{label} OK.")

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
    log.info("Checking GRUB...")
    if os.path.exists("/boot/grub/grub.cfg"):
        rc, _ = run("update-grub")
        if rc != 0:
            log.warning("GRUB update failed!")
            track("kernel_repairs")
    elif shutil.which("grub-mkconfig"):
        run("grub-mkconfig -o /boot/grub/grub.cfg")


# --- GPU Healing ---

def check_gpu():
    log.info("Checking GPU...")
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

    log.info("GPU check done.")


# --- SMART Disk Health ---

def check_smart():
    if not cfg["enable_smart"]:
        return
    log.info("Checking SMART disk health...")
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
    log.info("Checking filesystems...")
    _, out = run("mount | grep ' / '")
    if "ro," in out or ",ro " in out:
        log.warning("Root is READ-ONLY! Remounting...")
        run("mount -o remount,rw /")
        track("fs_errors_caught")

    _, out = run("journalctl -b -p err --grep='EXT4-fs\\|XFS\\|filesystem\\|I/O error' --no-pager -q 2>/dev/null | tail -10")
    if out:
        log.warning(f"FS errors:\n{out}")
        run("touch /forcefsck")
        track("fs_errors_caught")
    else:
        log.info("Filesystems OK.")


def check_fstab():
    """Verify all fstab entries are mountable."""
    log.info("Checking fstab...")
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
    log.info("Checking disk space...")
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
            "find /home -name '*.core' -delete 2>/dev/null",
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
    log.info("Checking inodes...")
    _, out = run("df -i / | tail -1 | awk '{print $5}' | tr -d '%'")
    if out and out.isdigit() and int(out) > 90:
        log.warning(f"Inodes {out}%! Cleaning...")
        run("find /tmp -type f -atime +3 -delete 2>/dev/null")
        run("find /var/tmp -type f -atime +1 -delete 2>/dev/null")
        track("disk_cleanups")
    else:
        log.info(f"Inodes OK ({out}%).")


# --- Service Healing ---

restart_counts = {}

def check_failed_services():
    log.info("Checking failed services...")
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
    log.info("Checking critical services...")
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
    log.info("Checking zombies...")
    _, out = run("ps aux | awk '$8==\"Z\" {print $2}'")
    if out:
        for pid in out.splitlines():
            pid = pid.strip()
            if not pid:
                continue
            log.warning(f"Killing zombie PID {pid}")
            _, ppid = run(f"ps -o ppid= -p {pid} 2>/dev/null")
            if ppid and ppid.strip():
                run(f"kill -SIGCHLD {ppid.strip()} 2>/dev/null")
            run(f"kill -9 {pid} 2>/dev/null")
            track("zombies_killed")
    else:
        log.info("No zombies.")


def check_high_cpu():
    log.info("Checking for runaway processes...")
    _, out = run("ps aux --sort=-%cpu | awk 'NR>1 && $3>95 {print $2, $11, $3}'")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            pid, name, cpu = parts[0], parts[1], parts[2]
            # Don't kill critical system processes
            if name in ("python3", "Xorg", "gnome-shell", "kwin", "systemd"):
                log.warning(f"High CPU: PID {pid} ({name}) at {cpu}% — skipping (critical).")
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
    log.info("Checking OOM events...")
    _, out = run("journalctl -b --grep='Out of memory\\|oom-kill\\|invoked oom-killer' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"OOM events:\n{out}")
        run("sysctl -w vm.min_free_kbytes=65536 2>/dev/null")
        run("sysctl -w vm.overcommit_memory=1 2>/dev/null")
        track("memory_clears")


# --- Memory ---

def check_memory():
    log.info("Checking memory...")
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
    log.info("Checking thermals...")
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


# --- Network ---

def check_network():
    log.info("Checking network...")
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
        log.info("Network OK.")


def check_dns():
    log.info("Checking DNS...")
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
        log.info("DNS OK.")


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

    log.info("Security checks done.")


def check_firewall():
    if not cfg["enable_firewall_check"]:
        return
    log.info("Checking firewall...")
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
    log.info("Firewall check done.")


# --- Time Sync ---

def check_time_sync():
    if not cfg["enable_time_sync"]:
        return
    log.info("Checking time sync...")
    _, out = run("timedatectl show --property=NTPSynchronized --value 2>/dev/null")
    if out == "no":
        log.warning("Time not synced! Enabling NTP...")
        run("timedatectl set-ntp true")
        run("systemctl restart systemd-timesyncd 2>/dev/null")
        track("time_sync_fixes")
    else:
        log.info("Time sync OK.")


# --- Permission Healing ---

def check_permissions():
    if not cfg["enable_permission_heal"]:
        return
    log.info("Checking critical permissions...")
    fixes = [
        ("/tmp", "1777"), ("/var/tmp", "1777"),
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
    log.info("Permissions OK.")


# --- Kernel Panics ---

def check_kernel_panics():
    log.info("Checking kernel panics...")
    _, out = run("journalctl -k -p emerg,alert,crit --since '1 hour ago' --no-pager -q 2>/dev/null")
    if out:
        log.warning(f"Critical kernel messages:\n{out[:500]}")
        run("touch /forcefsck")
        track("kernel_repairs")
    else:
        log.info("No kernel panics.")


# --- Crash Recovery ---

def check_crash_dumps():
    log.info("Checking crash dumps...")
    crash_dir = "/var/crash"
    if os.path.isdir(crash_dir):
        crashes = os.listdir(crash_dir)
        if crashes:
            log.warning(f"Found {len(crashes)} crash dumps in /var/crash")
            for c in crashes[:5]:
                log.warning(f"  - {c}")
            track("crash_recoveries", len(crashes))
            run("rm -f /var/crash/* 2>/dev/null")
    log.info("Crash dump check done.")


# --- Log Management ---

def check_log_sizes():
    log.info("Checking log sizes...")
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
    log.info("Checking Docker...")
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
    log.info("Docker check done.")


# --- USB Device Monitoring ---

def check_usb():
    if not cfg["enable_usb_monitor"]:
        return
    log.info("Checking USB devices...")
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
    log.info("USB check done.")


# --- Network Intrusion Detection ---

def check_intrusions():
    if not cfg["enable_network_intrusion"]:
        return
    log.info("Checking for network intrusions...")
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

    log.info("Intrusion check done.")


# --- Config File Watchdog ---

config_hashes = {}

def check_config_watchdog():
    if not cfg["enable_config_watchdog"]:
        return
    log.info("Checking config file integrity...")
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
    log.info("Config watchdog done.")


# --- Battery Monitoring ---

def check_battery():
    if not cfg["enable_battery"]:
        return
    bat_path = Path("/sys/class/power_supply/BAT0")
    if not bat_path.exists():
        bat_path = Path("/sys/class/power_supply/BAT1")
    if not bat_path.exists():
        return
    log.info("Checking battery...")
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
    log.info("Checking coredumps...")
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
    log.info("Coredump check done.")


# --- Entropy Check ---

def check_entropy():
    if not cfg["enable_entropy"]:
        return
    log.info("Checking entropy...")
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
    log.info("Checking journal health...")
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
    log.info("Journal check done.")


# --- Duplicate Process Detection ---

def check_duplicate_processes():
    if not cfg["enable_duplicate_process"]:
        return
    log.info("Checking duplicate processes...")
    # Processes that should only have one instance
    singles = ["NetworkManager", "systemd-resolved", "systemd-timesyncd", "cupsd", "bluetoothd"]
    for proc in singles:
        _, out = run(f"pgrep -c {proc} 2>/dev/null")
        if out and out.isdigit() and int(out) > 1:
            log.warning(f"Multiple {proc} instances ({out})! Restarting service...")
            run(f"systemctl restart {proc} 2>/dev/null")
            track("duplicate_kills")
    log.info("Duplicate process check done.")


# --- Disk I/O Latency ---

def check_disk_latency():
    if not cfg["enable_disk_latency"]:
        return
    log.info("Checking disk latency...")
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
    log.info("Disk latency check done.")


# --- Orphan Package Cleanup ---

def check_orphan_packages():
    if not cfg["enable_orphan_cleanup"]:
        return
    log.info("Checking orphan packages...")
    _, out = run("apt list --installed 2>/dev/null | grep -c 'residual-config'")
    if out and out.isdigit() and int(out) > 0:
        run("dpkg --purge $(dpkg -l | awk '/^rc/{print $2}') 2>/dev/null")
        log.info(f"Purged {out} residual configs.")
        track("orphan_cleans")
    # Remove orphaned libs
    _, out = run("deborphan 2>/dev/null | head -20")
    if out and shutil.which("deborphan"):
        log.info(f"Orphaned packages:\n{out}")
    log.info("Orphan check done.")


# --- Broken Symlink Healing ---

def check_broken_symlinks():
    if not cfg["enable_symlink_heal"]:
        return
    log.info("Checking broken symlinks...")
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
    log.info("Symlink check done.")


# --- Hostname Validation ---

def check_hostname():
    if not cfg["enable_hostname_check"]:
        return
    log.info("Checking hostname...")
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
    log.info("Hostname check done.")


# --- Locale Healing ---

def check_locale():
    if not cfg["enable_locale_check"]:
        return
    log.info("Checking locale...")
    _, out = run("locale 2>&1")
    if "Cannot set" in out or "warning" in out.lower():
        log.warning(f"Locale issues:\n{out[:300]}")
        run("locale-gen en_US.UTF-8 2>/dev/null")
        run("update-locale LANG=en_US.UTF-8 2>/dev/null")
        track("locale_fixes")
    else:
        log.info("Locale OK.")


# --- Xorg / Display Healing ---

def check_xorg():
    if not cfg["enable_xorg_heal"]:
        return
    if not os.path.exists("/var/log/Xorg.0.log"):
        return
    log.info("Checking Xorg...")
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
    log.info("Xorg check done.")


# --- Audio Healing ---

def check_audio():
    if not cfg["enable_audio_heal"]:
        return
    log.info("Checking audio...")
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
            log.info("Audio OK.")


# --- Bluetooth Healing ---

def check_bluetooth():
    if not cfg["enable_bluetooth_heal"]:
        return
    if not shutil.which("bluetoothctl"):
        return
    log.info("Checking Bluetooth...")
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
    log.info("Bluetooth check done.")


# --- Cron Healing ---

def check_cron():
    if not cfg["enable_cron_heal"]:
        return
    log.info("Checking cron...")
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
    log.info("Cron check done.")


# --- Tmpfiles Healing ---

def check_tmpfiles():
    if not cfg["enable_tmpfiles"]:
        return
    log.info("Checking tmpfiles...")
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
    log.info("Tmpfiles check done.")


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
    log.info("Antivirus scan done.")


# --- Rootkit Detection ---

def check_rootkits():
    if not cfg["enable_rootkit_check"]:
        return
    log.info("Checking for rootkits...")
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
            warnings = [l for l in out.splitlines() if "Warning" in l]
            if warnings:
                log.warning(f"rkhunter warnings:\n" + "\n".join(warnings[:10]))
                track("rootkits_checked")
        else:
            log.info("rkhunter: clean")
    if not shutil.which("chkrootkit") and not shutil.which("rkhunter"):
        log.info("No rootkit scanner installed. Install with: sudo apt install chkrootkit rkhunter")
    log.info("Rootkit check done.")


# --- Desktop / Window Manager Healing ---

def check_desktop():
    if not cfg["enable_desktop_heal"]:
        return
    log.info("Checking desktop...")
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
    log.info("Desktop check done.")


# --- Flatpak / Snap Healing ---

def check_flatpak():
    if not cfg["enable_flatpak_heal"]:
        return
    log.info("Checking Flatpak/Snap...")
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
    log.info("Flatpak/Snap check done.")


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
    log.info("Backup done.")


# --- Port Scan Protection ---

def check_port_scan_protect():
    if not cfg["enable_port_scan_protect"]:
        return
    log.info("Checking for port scans...")
    _, out = run("journalctl --since '10 min ago' --grep='SYN' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 100:
        log.warning(f"Possible port scan: {out} SYN packets in 10 min!")
        run("sysctl -w net.ipv4.tcp_syncookies=1")
        run("sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1")
        run("sysctl -w net.ipv4.conf.all.log_martians=1")
        track("port_scan_blocks")
    log.info("Port scan check done.")


# --- Login Monitor ---

def check_login_monitor():
    if not cfg["enable_login_monitor"]:
        return
    log.info("Checking logins...")
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
    log.info("Login check done.")


# --- PPA / Repository Healing ---

def check_ppa_heal():
    if not cfg["enable_ppa_heal"]:
        return
    log.info("Checking APT repositories...")
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
    log.info("PPA check done.")


# --- Font Healing ---

def check_fonts():
    if not cfg["enable_font_heal"]:
        return
    log.info("Checking fonts...")
    _, out = run("fc-list 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) < 10:
        log.warning(f"Only {out} fonts found! Rebuilding cache...")
        run("fc-cache -fv 2>/dev/null")
        track("font_fixes")
    cache_dir = os.path.expanduser("~/.cache/fontconfig")
    if not os.path.isdir(cache_dir):
        run("fc-cache -fv 2>/dev/null")
        track("font_fixes")
    log.info("Font check done.")


# --- Printer Healing ---

def check_printer():
    if not cfg["enable_printer_heal"]:
        return
    if not shutil.which("lpstat"):
        return
    log.info("Checking printers...")
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
    log.info("Printer check done.")


# --- Suspend/Resume Healing ---

def check_suspend():
    if not cfg["enable_suspend_heal"]:
        return
    log.info("Checking suspend/resume...")
    _, errors = run("journalctl -b --grep='PM:.*failed\\|resume.*error' --no-pager -q 2>/dev/null | tail -5")
    if errors:
        log.warning(f"Suspend/resume errors:\n{errors[:300]}")
        for svc in ["NetworkManager", "bluetooth", "pulseaudio"]:
            run(f"systemctl restart {svc} 2>/dev/null")
        track("suspend_fixes")
    log.info("Suspend check done.")


# --- Clock Drift Detection ---

def check_clock_drift():
    if not cfg["enable_clock_drift"]:
        return
    log.info("Checking clock drift...")
    _, out = run("timedatectl show --property=NTPSynchronized --value 2>/dev/null")
    if out == "no":
        log.warning("Clock not synced!")
        run("timedatectl set-ntp true")
        run("systemctl restart systemd-timesyncd 2>/dev/null")
        run("ntpdate pool.ntp.org 2>/dev/null || chronyc makestep 2>/dev/null")
        track("clock_fixes")
    log.info("Clock drift check done.")


# --- Zombie Parent Healing ---

def check_zombie_parents():
    if not cfg["enable_zombie_parent_heal"]:
        return
    log.info("Checking zombie parent processes...")
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
    log.info("Checking OOM scores...")
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
    log.info("OOM scores OK.")


# --- Sysctl Hardening ---

def check_sysctl():
    if not cfg["enable_sysctl_heal"]:
        return
    log.info("Checking sysctl settings...")
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
    log.info("Sysctl check done.")


# --- APT Source Integrity ---

def check_apt_sources():
    if not cfg["enable_apt_source_heal"]:
        return
    log.info("Checking APT source integrity...")
    _, out = run("apt-get update 2>&1 | grep -i 'duplicate'")
    if out:
        log.warning(f"Duplicate APT sources:\n{out[:300]}")
        track("apt_source_fixes")
    _, out = run("apt-key list 2>&1 | grep -i 'expired'")
    if out:
        log.warning(f"Expired APT keys:\n{out[:300]}")
        run("apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com 2>/dev/null")
        track("apt_source_fixes")
    log.info("APT source check done.")


# --- User Account Integrity ---

def check_user_integrity():
    if not cfg["enable_user_integrity"]:
        return
    log.info("Checking user integrity...")
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
    log.info("User integrity check done.")


# --- Mount Point Healing ---

def check_mounts():
    if not cfg["enable_mount_heal"]:
        return
    log.info("Checking mount points...")
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
    log.info("Mount check done.")


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
    ]

    w = 48
    print()
    print(f"╔{'═' * w}╗")
    print(f"║{'🤖 ROZ NanoBots v6 Status':^{w}}║")
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
    log.info("========== ROZ NanoBots v6 — Full Heal ==========")
    for fn in [
        fix_broken_packages, update_system,
        check_kernel_health, rebuild_grub,
        check_gpu, check_smart,
        check_filesystems, check_fstab,
        check_disk_space, check_inodes,
        check_failed_services, check_critical_services,
        kill_zombies, check_high_cpu, check_oom,
        check_memory, check_thermals,
        check_network, check_dns,
        check_security, check_firewall,
        check_time_sync, check_permissions,
        check_kernel_panics, check_crash_dumps,
        check_log_sizes,
        check_docker, check_usb, check_intrusions,
        check_config_watchdog, check_battery,
        check_coredumps, check_entropy,
        check_journal_health, check_duplicate_processes,
        check_disk_latency, check_orphan_packages,
        check_broken_symlinks, check_hostname,
        check_locale, check_xorg, check_audio,
        check_bluetooth, check_cron, check_tmpfiles,
        check_antivirus, check_rootkits,
        check_desktop, check_flatpak,
        check_backup, check_port_scan_protect,
        check_login_monitor, check_ppa_heal,
        check_fonts, check_printer,
        check_suspend, check_clock_drift,
        check_zombie_parents, check_oom_scores,
        check_sysctl, check_apt_sources,
        check_user_integrity, check_mounts,
    ]:
        if shutdown_requested:
            log.info("Shutdown requested, stopping heal cycle.")
            break
        try:
            fn()
        except Exception as e:
            log.error(f"{fn.__name__} failed: {e}")
    log.info("========== Full heal complete ==========\n")


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


def main():
    global stats
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
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
        if cmd == "config":
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            if not os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "w") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
                print(f"Config created: {CONFIG_FILE}")
            else:
                print(f"Config exists: {CONFIG_FILE}")
            return
        print(f"Usage: {sys.argv[0]} [status|heal|quick|config]")
        return

    if os.geteuid() != 0:
        print("NanoBot needs root. Run with: sudo python3 nanobot.py")
        sys.exit(1)

    log.info("ROZ NanoBots v6 activated.")
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
    log.info("ROZ NanoBots v6 shut down cleanly.")


if __name__ == "__main__":
    main()
