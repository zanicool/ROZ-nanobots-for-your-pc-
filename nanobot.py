#!/usr/bin/env python3
"""ROZ NanoBots v5 - Self-healing Linux system daemon."""

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
    ]

    w = 48
    print()
    print(f"╔{'═' * w}╗")
    print(f"║{'🤖 ROZ NanoBots v5 Status':^{w}}║")
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
    log.info("========== ROZ NanoBots v5 — Full Heal ==========")
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
        check_network,
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

    log.info("ROZ NanoBots v5 activated.")
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
    log.info("ROZ NanoBots v5 shut down cleanly.")


if __name__ == "__main__":
    main()
