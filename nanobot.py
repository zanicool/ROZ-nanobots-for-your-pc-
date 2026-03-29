#!/usr/bin/env python3
"""ROZ NanoBots v4 - Self-healing Linux system daemon."""

import subprocess
import logging
import time
import shutil
import os
import sys
import json
import socket
import signal
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
}


def load_config():
    cfg = DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE) as f:
            cfg.update(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return cfg


cfg = load_config()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NanoBot] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(cfg["log_file"]) if os.access(os.path.dirname(cfg["log_file"]), os.W_OK)
        else logging.StreamHandler()
    ]
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
    except PermissionError:
        pass


stats = load_stats()


def track(key, count=1):
    stats[key] = stats.get(key, 0) + count
    stats["issues_total"] = stats.get("issues_total", 0) + count


def run(cmd, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    if check and r.returncode != 0:
        log.warning(f"Command failed: {cmd}\n{r.stderr.strip()}")
    return r.returncode, r.stdout.strip()


# --- Package Healing ---

def fix_broken_packages():
    log.info("Fixing broken packages...")
    rc1, _ = run("sudo dpkg --configure -a")
    rc2, _ = run("sudo apt-get install -f -y")
    run("sudo apt-get autoremove -y")
    if rc1 != 0 or rc2 != 0:
        track("packages_fixed")
    log.info("Package repair done.")


def update_system():
    if not cfg["enable_updates"]:
        return
    log.info("Updating system...")
    run("sudo apt-get update -y")
    run("sudo apt-get upgrade -y")
    run("sudo apt-get dist-upgrade -y")
    log.info("System updated.")


# --- Kernel Healing ---

def check_kernel_health():
    log.info("Checking kernel health...")
    _, current = run("uname -r")
    repaired = False

    for path, rebuild_cmd, label in [
        (f"/boot/vmlinuz-{current}", f"sudo apt-get install --reinstall -y linux-image-{current}", "Kernel image"),
        (f"/boot/initrd.img-{current}", f"sudo update-initramfs -c -k {current}", "Initramfs"),
    ]:
        if not os.path.exists(path):
            log.warning(f"{label} MISSING! Repairing...")
            run(rebuild_cmd)
            repaired = True
        else:
            log.info(f"{label} OK.")

    mod_dir = f"/lib/modules/{current}"
    if not os.path.isdir(mod_dir):
        log.warning(f"Modules MISSING! Reinstalling...")
        run(f"sudo apt-get install --reinstall -y linux-modules-{current}")
        repaired = True

    run(f"sudo depmod -a {current}")

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
        rc, _ = run("sudo update-grub")
        if rc != 0:
            log.warning("GRUB update failed!")
            track("kernel_repairs")


# --- SMART Disk Health ---

def check_smart():
    if not cfg["enable_smart"]:
        return
    log.info("Checking SMART disk health...")
    rc, _ = run("which smartctl")
    if rc != 0:
        log.info("smartmontools not installed, skipping.")
        return

    _, out = run("lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'")
    if not out:
        return

    for disk in out.splitlines():
        _, smart = run(f"sudo smartctl -H /dev/{disk} 2>/dev/null")
        if "PASSED" in smart:
            log.info(f"/dev/{disk}: SMART OK")
        elif "FAILED" in smart:
            log.warning(f"/dev/{disk}: SMART FAILING! Disk may die soon!")
            track("smart_warnings")
        # Check reallocated sectors
        _, sectors = run(f"sudo smartctl -A /dev/{disk} 2>/dev/null | grep -i reallocated")
        if sectors:
            parts = sectors.split()
            for i, p in enumerate(parts):
                if p.isdigit() and int(p) > 0 and i == len(parts) - 1:
                    log.warning(f"/dev/{disk}: {p} reallocated sectors!")
                    track("smart_warnings")


# --- Filesystem Healing ---

def check_filesystems():
    log.info("Checking filesystems...")
    _, out = run("mount | grep ' / '")
    if "ro," in out or ",ro " in out:
        log.warning("Root is READ-ONLY! Remounting...")
        run("sudo mount -o remount,rw /")
        track("fs_errors_caught")

    _, out = run("journalctl -b -p err --grep='EXT4-fs\\|XFS\\|filesystem\\|I/O error' --no-pager -q 2>/dev/null | tail -10")
    if out:
        log.warning(f"FS errors:\n{out}")
        run("sudo touch /forcefsck")
        track("fs_errors_caught")
    else:
        log.info("Filesystems OK.")


def check_disk_space():
    log.info("Checking disk space...")
    total, used, free = shutil.disk_usage("/")
    pct = used / total * 100
    if pct > cfg["disk_crit_pct"]:
        log.warning(f"Disk {pct:.1f}% full! Emergency cleanup...")
        run("sudo apt-get autoclean -y")
        run("sudo journalctl --vacuum-time=2d")
        run("sudo find /tmp -type f -atime +3 -delete 2>/dev/null")
        run("sudo find /var/tmp -type f -atime +3 -delete 2>/dev/null")
        run("sudo find /var/log -name '*.gz' -delete 2>/dev/null")
        run("sudo find /var/crash -type f -delete 2>/dev/null")
        track("disk_cleanups")
    elif pct > cfg["disk_warn_pct"]:
        log.warning(f"Disk {pct:.1f}% — light cleanup.")
        run("sudo apt-get autoclean -y")
        track("disk_cleanups")
    else:
        log.info(f"Disk OK ({pct:.1f}%).")


def check_inodes():
    log.info("Checking inodes...")
    _, out = run("df -i / | tail -1 | awk '{print $5}' | tr -d '%'")
    if out and out.isdigit() and int(out) > 90:
        log.warning(f"Inodes {out}%! Cleaning...")
        run("sudo find /tmp -type f -atime +3 -delete 2>/dev/null")
        track("disk_cleanups")
    else:
        log.info(f"Inodes OK ({out}%).")


# --- Service Healing ---

def check_failed_services():
    log.info("Checking failed services...")
    _, out = run("systemctl --failed --no-legend --no-pager --plain")
    if out:
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            log.warning(f"Restarting: {unit}")
            run(f"sudo systemctl restart {unit}")
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
            run(f"sudo systemctl restart {svc}")
            track("services_restarted")
        else:
            log.info(f"{svc}: active")


# --- Process Healing ---

def kill_zombies():
    log.info("Checking zombies...")
    _, out = run("ps aux | awk '$8==\"Z\" {print $2}'")
    if out:
        for pid in out.splitlines():
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
            log.warning(f"High CPU: PID {parts[0]} ({parts[1]}) at {parts[2]}%")


def check_oom():
    log.info("Checking OOM events...")
    _, out = run("journalctl -b --grep='Out of memory\\|oom-kill\\|invoked oom-killer' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"OOM events:\n{out}")
        run("sudo sysctl -w vm.min_free_kbytes=65536 2>/dev/null")
        track("memory_clears")


# --- Memory ---

def check_memory():
    log.info("Checking memory...")
    _, out = run("free -m | awk '/Mem:/{print $7}'")
    if out and out.isdigit() and int(out) < cfg["mem_crit_mb"]:
        log.warning(f"Low memory ({out}MB)! Clearing caches...")
        run("sudo sync && sudo sysctl -w vm.drop_caches=3")
        track("memory_clears")
    else:
        log.info(f"Memory OK ({out}MB available).")

    _, out = run("swapon --show --noheadings")
    if not out:
        log.warning("No swap! Enabling...")
        run("sudo swapon -a 2>/dev/null")


# --- Thermal ---

def check_thermals():
    log.info("Checking thermals...")
    for zone in Path("/sys/class/thermal/").glob("thermal_zone*/temp"):
        try:
            t = int(zone.read_text().strip()) / 1000
        except (ValueError, PermissionError):
            continue
        name = zone.parent.name
        if t > cfg["temp_crit_c"]:
            log.warning(f"{name}: {t}°C CRITICAL!")
            track("thermal_throttles")
        elif t > cfg["temp_warn_c"]:
            log.warning(f"{name}: {t}°C hot!")
        else:
            log.info(f"{name}: {t}°C")
        return
    log.info("No thermal sensors.")


# --- Network ---

def check_network():
    log.info("Checking network...")
    rc, _ = run("ping -c 1 -W 3 8.8.8.8")
    if rc != 0:
        # Try secondary
        rc, _ = run("ping -c 1 -W 3 1.1.1.1")
    if rc != 0:
        log.warning("Network down! Restarting...")
        run("sudo systemctl restart NetworkManager 2>/dev/null")
        run("sudo systemctl restart systemd-networkd 2>/dev/null")
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
        log.warning("DNS broken! Fixing...")
        run("sudo systemctl restart systemd-resolved 2>/dev/null")
        time.sleep(2)
        rc, _ = run("host -W 3 google.com 2>/dev/null")
        if rc != 0:
            # Nuclear option: write known-good nameserver
            run("echo 'nameserver 8.8.8.8\nnameserver 1.1.1.1' | sudo tee /etc/resolv.conf")
        track("dns_fixes")
    else:
        log.info("DNS OK.")


# --- Security ---

def check_security():
    if not cfg["enable_security"]:
        return
    log.info("Running security checks...")

    # Check for failed SSH logins
    _, out = run("journalctl -u ssh --since '1 hour ago' --grep='Failed password' --no-pager -q 2>/dev/null | wc -l")
    if out and out.isdigit() and int(out) > 20:
        log.warning(f"{out} failed SSH attempts in last hour! Possible brute force.")
        track("security_fixes")

    # Check for world-writable files in critical dirs
    _, out = run("find /etc -maxdepth 1 -perm -o+w -type f 2>/dev/null")
    if out:
        log.warning(f"World-writable files in /etc:\n{out}")
        for f in out.splitlines():
            run(f"sudo chmod o-w {f}")
        track("security_fixes")

    # Check root SSH login
    _, out = run("grep -i '^PermitRootLogin yes' /etc/ssh/sshd_config 2>/dev/null")
    if out:
        log.warning("Root SSH login is enabled! Consider disabling.")

    # Check for unauthorized SUID binaries
    _, out = run("find /tmp /var/tmp -perm -4000 -type f 2>/dev/null")
    if out:
        log.warning(f"SUID files in temp dirs:\n{out}")
        for f in out.splitlines():
            run(f"sudo chmod u-s {f}")
        track("security_fixes")

    log.info("Security checks done.")


# --- Kernel Panics ---

def check_kernel_panics():
    log.info("Checking kernel panics...")
    _, out = run("journalctl -k -p emerg,alert,crit --since '1 hour ago' --no-pager -q")
    if out:
        log.warning(f"Critical kernel messages:\n{out[:500]}")
        run("sudo touch /forcefsck")
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
            run("sudo rm -f /var/crash/* 2>/dev/null")
    log.info("Crash dump check done.")


# --- Log Management ---

def check_log_sizes():
    log.info("Checking log sizes...")
    _, out = run("du -sm /var/log 2>/dev/null | awk '{print $1}'")
    if out and out.isdigit() and int(out) > cfg["max_log_size_mb"]:
        log.warning(f"/var/log is {out}MB! Rotating...")
        run("sudo logrotate -f /etc/logrotate.conf 2>/dev/null")
        run("sudo journalctl --vacuum-size=200M")
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

    print()
    print("╔════════════════════════════════════════════╗")
    print("║         🤖 ROZ NanoBots v4 Status          ║")
    print("╠════════════════════════════════════════════╣")
    print(f"║  Running since:    {first}")
    print(f"║  Uptime:           {uptime}")
    print(f"║  Healing cycles:   {s.get('cycles',0)}")
    print(f"║  Last run:         {last}")
    print("╠════════════════════════════════════════════╣")
    print(f"║  Services restarted:  {s.get('services_restarted',0)}")
    print(f"║  Packages fixed:      {s.get('packages_fixed',0)}")
    print(f"║  Kernel repairs:      {s.get('kernel_repairs',0)}")
    print(f"║  Disk cleanups:       {s.get('disk_cleanups',0)}")
    print(f"║  Memory clears:       {s.get('memory_clears',0)}")
    print(f"║  Network restarts:    {s.get('network_restarts',0)}")
    print(f"║  Zombies killed:      {s.get('zombies_killed',0)}")
    print(f"║  FS errors caught:    {s.get('fs_errors_caught',0)}")
    print(f"║  Thermal throttles:   {s.get('thermal_throttles',0)}")
    print(f"║  DNS fixes:           {s.get('dns_fixes',0)}")
    print(f"║  Security fixes:      {s.get('security_fixes',0)}")
    print(f"║  SMART warnings:      {s.get('smart_warnings',0)}")
    print(f"║  Crash recoveries:    {s.get('crash_recoveries',0)}")
    print(f"║  ──────────────────────────────────────")
    print(f"║  Total issues fixed:  {s.get('issues_total',0)}")
    print("╚════════════════════════════════════════════╝")
    print()


# --- Main Cycles ---

def heal_full():
    """Full healing cycle — runs every INTERVAL."""
    log.info("========== ROZ NanoBots v4 — Full Heal ==========")
    fix_broken_packages()
    update_system()
    check_kernel_health()
    rebuild_grub()
    check_smart()
    check_filesystems()
    check_disk_space()
    check_inodes()
    check_failed_services()
    check_critical_services()
    kill_zombies()
    check_high_cpu()
    check_oom()
    check_memory()
    check_thermals()
    check_network()
    check_dns()
    check_security()
    check_kernel_panics()
    check_crash_dumps()
    check_log_sizes()
    log.info("========== Full heal complete ==========\n")


def heal_quick():
    """Quick check — runs every REALTIME_INTERVAL between full heals."""
    check_critical_services()
    check_failed_services()
    kill_zombies()
    check_memory()
    check_network()


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "status":
            show_status()
            return
        if sys.argv[1] == "heal":
            heal_full()
            return
        if sys.argv[1] == "quick":
            heal_quick()
            return

    if os.geteuid() != 0:
        print("NanoBot needs root. Run with: sudo python3 nanobot.py")
        sys.exit(1)

    global stats
    log.info("ROZ NanoBots v4 activated.")
    log.info(f"Full heal every {cfg['interval']}s, quick check every {cfg['realtime_interval']}s")

    while True:
        try:
            stats = load_stats()
            stats["cycles"] = stats.get("cycles", 0) + 1
            stats["last_run"] = datetime.now().isoformat()

            heal_full()
            save_stats(stats)

            # Quick checks between full heals
            checks = cfg["interval"] // cfg["realtime_interval"]
            for _ in range(checks - 1):
                time.sleep(cfg["realtime_interval"])
                try:
                    heal_quick()
                except Exception as e:
                    log.error(f"Quick heal error: {e}")

        except Exception as e:
            log.error(f"Healing error: {e}")
            time.sleep(60)


if __name__ == "__main__":
    main()
