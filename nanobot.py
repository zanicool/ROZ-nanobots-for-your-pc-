#!/usr/bin/env python3
"""NanoBot v3 - Self-healing Linux system daemon."""

import subprocess
import logging
import time
import shutil
import os
import sys
import json
from datetime import datetime

LOG_FILE = "/var/log/nanobot.log"
STATS_FILE = "/var/log/nanobot_stats.json"
INTERVAL = 3600

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NanoBot] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE) if os.access(os.path.dirname(LOG_FILE), os.W_OK)
        else logging.StreamHandler()
    ]
)
log = logging.getLogger("nanobot")


# --- Stats Tracker ---

def load_stats():
    default = {
        "first_run": datetime.now().isoformat(),
        "cycles": 0,
        "services_restarted": 0,
        "packages_fixed": 0,
        "kernel_repairs": 0,
        "disk_cleanups": 0,
        "memory_clears": 0,
        "network_restarts": 0,
        "zombies_killed": 0,
        "fs_errors_caught": 0,
        "thermal_throttles": 0,
        "dns_fixes": 0,
        "issues_total": 0,
        "last_run": None,
    }
    try:
        with open(STATS_FILE) as f:
            return {**default, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_stats(stats):
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(stats, f, indent=2)
    except PermissionError:
        pass


stats = load_stats()


def track(key, count=1):
    stats[key] = stats.get(key, 0) + count
    stats["issues_total"] = stats.get("issues_total", 0) + count


def run(cmd, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        log.warning(f"Command failed: {cmd}\n{r.stderr.strip()}")
    return r.returncode, r.stdout.strip()


# --- Package & Driver Healing ---

def fix_broken_packages():
    log.info("Fixing broken packages...")
    rc1, _ = run("sudo dpkg --configure -a")
    rc2, _ = run("sudo apt-get install -f -y")
    run("sudo apt-get autoremove -y")
    if rc1 != 0 or rc2 != 0:
        track("packages_fixed")
    log.info("Package repair done.")


def update_system():
    log.info("Updating system...")
    run("sudo apt-get update -y")
    run("sudo apt-get upgrade -y")
    run("sudo apt-get dist-upgrade -y")
    log.info("System updated.")


# --- Kernel Healing ---

def check_kernel_health():
    log.info("Checking kernel health...")
    _, current = run("uname -r")
    log.info(f"Running kernel: {current}")

    repaired = False

    # Verify kernel image
    kernel_img = f"/boot/vmlinuz-{current}"
    if not os.path.exists(kernel_img):
        log.warning(f"Kernel image MISSING: {kernel_img}")
        run(f"sudo apt-get install --reinstall -y linux-image-{current}")
        repaired = True

    # Verify initramfs
    initrd = f"/boot/initrd.img-{current}"
    if not os.path.exists(initrd):
        log.warning(f"Initramfs MISSING: {initrd}")
        run(f"sudo update-initramfs -c -k {current}")
        repaired = True

    # Check taint
    _, taint = run("cat /proc/sys/kernel/tainted")
    if taint and taint != "0":
        log.warning(f"Kernel tainted (flags={taint}).")

    # Check dmesg errors
    _, out = run("dmesg --level=err,crit,alert,emerg --notime 2>/dev/null | tail -20")
    if out:
        log.warning(f"Kernel errors:\n{out}")

    if repaired:
        track("kernel_repairs")


def fix_kernel_modules():
    log.info("Checking kernel modules...")
    _, current = run("uname -r")
    mod_dir = f"/lib/modules/{current}"

    if not os.path.isdir(mod_dir):
        log.warning(f"Modules MISSING: {mod_dir}")
        run(f"sudo apt-get install --reinstall -y linux-modules-{current}")
        track("kernel_repairs")

    run(f"sudo depmod -a {current}")
    log.info("Module deps rebuilt.")


def rebuild_grub():
    log.info("Checking GRUB...")
    if os.path.exists("/boot/grub/grub.cfg"):
        rc, _ = run("sudo update-grub")
        if rc != 0:
            log.warning("GRUB update failed!")
            track("kernel_repairs")
        else:
            log.info("GRUB OK.")


def remove_old_kernels():
    log.info("Cleaning old kernels...")
    _, current = run("uname -r")
    _, out = run("dpkg --list 'linux-image-*' | grep '^ii' | awk '{print $2}'")
    if out:
        for pkg in out.splitlines():
            if current in pkg or "generic" == pkg.split("-")[-1]:
                continue
            if "linux-image-" in pkg and current not in pkg:
                log.info(f"Removing: {pkg}")
                run(f"sudo apt-get purge -y {pkg}")


# --- Filesystem Healing ---

def check_filesystems():
    log.info("Checking filesystems...")
    _, out = run("mount | grep ' / '")

    if "ro," in out or ",ro " in out:
        log.warning("Root is READ-ONLY! Remounting...")
        run("sudo mount -o remount,rw /")
        track("fs_errors_caught")

    _, out = run("journalctl -b -p err --grep='EXT4-fs\\|XFS\\|filesystem' --no-pager -q 2>/dev/null | tail -10")
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
    if pct > 90:
        log.warning(f"Disk {pct:.1f}% full! Emergency cleanup...")
        run("sudo apt-get autoclean -y")
        run("sudo journalctl --vacuum-time=2d")
        run("sudo find /tmp -type f -atime +7 -delete 2>/dev/null")
        run("sudo find /var/tmp -type f -atime +7 -delete 2>/dev/null")
        run("sudo find /var/log -name '*.gz' -delete 2>/dev/null")
        track("disk_cleanups")
    elif pct > 80:
        log.warning(f"Disk {pct:.1f}% — light cleanup.")
        run("sudo apt-get autoclean -y")
        track("disk_cleanups")
    else:
        log.info(f"Disk OK ({pct:.1f}%).")


def check_inodes():
    log.info("Checking inodes...")
    _, out = run("df -i / | tail -1 | awk '{print $5}' | tr -d '%'")
    if out and int(out) > 90:
        log.warning(f"Inodes {out}% used! Cleaning temp files...")
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
    for svc in ["systemd-journald", "systemd-logind", "dbus", "cron"]:
        _, out = run(f"systemctl is-active {svc}")
        if out != "active":
            log.warning(f"{svc} is {out}! Restarting...")
            run(f"sudo systemctl restart {svc}")
            track("services_restarted")
        else:
            log.info(f"{svc}: active")


# --- Process Healing ---

def kill_zombies():
    log.info("Checking for zombie processes...")
    _, out = run("ps aux | awk '$8==\"Z\" {print $2}'")
    if out:
        for pid in out.splitlines():
            log.warning(f"Killing zombie PID {pid}")
            run(f"kill -9 {pid} 2>/dev/null")
            # Also try to signal the parent
            _, ppid = run(f"ps -o ppid= -p {pid} 2>/dev/null")
            if ppid and ppid.strip():
                run(f"kill -SIGCHLD {ppid.strip()} 2>/dev/null")
            track("zombies_killed")
    else:
        log.info("No zombies.")


def check_oom():
    log.info("Checking for OOM events...")
    _, out = run("journalctl -b --grep='Out of memory\\|oom-kill\\|invoked oom-killer' --no-pager -q 2>/dev/null | tail -5")
    if out:
        log.warning(f"OOM events this boot:\n{out}")
        # Increase vm.min_free_kbytes to prevent future OOM
        run("sudo sysctl -w vm.min_free_kbytes=65536 2>/dev/null")
        track("memory_clears")


# --- Memory & Swap ---

def check_memory():
    log.info("Checking memory...")
    _, out = run("free -m | awk '/Mem:/{print $7}'")
    if out and int(out) < 200:
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
    log.info("Checking CPU temperature...")
    for zone in ["/sys/class/thermal/thermal_zone0/temp",
                 "/sys/class/thermal/thermal_zone1/temp"]:
        if os.path.exists(zone):
            _, temp = run(f"cat {zone}")
            if temp:
                t = int(temp) / 1000
                if t > 90:
                    log.warning(f"CPU {t}°C! CRITICAL — throttling likely.")
                    track("thermal_throttles")
                elif t > 80:
                    log.warning(f"CPU {t}°C — running hot.")
                else:
                    log.info(f"CPU temp: {t}°C")
                return
    log.info("No thermal sensors found.")


# --- Network ---

def check_network():
    log.info("Checking network...")
    rc, _ = run("ping -c 1 -W 3 8.8.8.8")
    if rc != 0:
        log.warning("Network down! Restarting...")
        run("sudo systemctl restart NetworkManager 2>/dev/null")
        run("sudo systemctl restart systemd-networkd 2>/dev/null")
        track("network_restarts")
    else:
        log.info("Network OK.")


def check_dns():
    log.info("Checking DNS...")
    rc, _ = run("host -W 3 google.com 2>/dev/null")
    if rc != 0:
        log.warning("DNS broken! Trying fixes...")
        run("sudo systemctl restart systemd-resolved 2>/dev/null")
        # Fallback: write a known-good nameserver
        _, resolv = run("cat /etc/resolv.conf")
        if "nameserver" not in resolv:
            run("echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf")
        track("dns_fixes")
    else:
        log.info("DNS OK.")


# --- Kernel Panics ---

def check_kernel_panics():
    log.info("Checking for kernel panics...")
    _, out = run("journalctl -k -p emerg,alert,crit --since '1 hour ago' --no-pager -q")
    if out:
        log.warning(f"Critical kernel messages:\n{out[:500]}")
        run("sudo touch /forcefsck")
        track("kernel_repairs")
    else:
        log.info("No kernel panics.")


# --- Log Rotation ---

def check_log_sizes():
    log.info("Checking log sizes...")
    _, out = run("du -sm /var/log 2>/dev/null | awk '{print $1}'")
    if out and int(out) > 1000:
        log.warning(f"/var/log is {out}MB! Rotating...")
        run("sudo logrotate -f /etc/logrotate.conf 2>/dev/null")
        run("sudo journalctl --vacuum-size=200M")
        track("disk_cleanups")
    else:
        log.info(f"/var/log: {out}MB")


# --- Status Dashboard ---

def show_status():
    s = load_stats()
    print("\n╔══════════════════════════════════════╗")
    print("║        🤖 NanoBot v3 Status          ║")
    print("╠══════════════════════════════════════╣")
    print(f"║  Running since:  {s.get('first_run','?')[:16]}")
    print(f"║  Healing cycles: {s.get('cycles',0)}")
    print(f"║  Last run:       {(s.get('last_run') or '?')[:16]}")
    print("╠══════════════════════════════════════╣")
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
    print(f"║  ─────────────────────────────────")
    print(f"║  Total issues fixed:  {s.get('issues_total',0)}")
    print("╚══════════════════════════════════════╝\n")


# --- Main ---

def heal():
    global stats
    stats = load_stats()
    log.info("========== NanoBot v3 healing cycle ==========")
    stats["cycles"] = stats.get("cycles", 0) + 1
    stats["last_run"] = datetime.now().isoformat()

    fix_broken_packages()
    update_system()
    check_kernel_health()
    fix_kernel_modules()
    rebuild_grub()
    remove_old_kernels()
    check_filesystems()
    check_disk_space()
    check_inodes()
    check_failed_services()
    check_critical_services()
    kill_zombies()
    check_oom()
    check_memory()
    check_thermals()
    check_network()
    check_dns()
    check_kernel_panics()
    check_log_sizes()

    save_stats(stats)
    log.info("========== Healing cycle complete ==========\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        show_status()
        return

    if os.geteuid() != 0:
        print("NanoBot needs root. Run with: sudo python3 nanobot.py")
        sys.exit(1)

    log.info("NanoBot v3 activated. Interval: %ds", INTERVAL)
    while True:
        try:
            heal()
        except Exception as e:
            log.error(f"Healing error: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
