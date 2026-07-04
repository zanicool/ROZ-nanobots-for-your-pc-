#!/usr/bin/env python3
"""ROZ NanoBots v5 - Self-healing macOS system daemon."""

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime

# --- Config ---

CONFIG_FILE = os.path.expanduser("~/.config/nanobot/config.json")
DEFAULT_CONFIG = {
    "interval": 3600,
    "realtime_interval": 60,
    "log_file": os.path.expanduser("~/Library/Logs/nanobot.log"),
    "stats_file": os.path.expanduser("~/.config/nanobot/stats.json"),
    "enable_network_heal": True,
    "enable_dns_heal": True,
    "enable_disk_check": True,
    "enable_security_check": True,
    "enable_ups_check": True,
    "ups_name": "riello@pepper.local",
    "disk_warn_pct": 80,
    "disk_crit_pct": 90,
    "temp_warn_c": 80,
    "temp_crit_c": 95,
    "watched_services": [],
    "critical_services": [],
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
        "cycles": 0,
        "network_restarts": 0,
        "dns_fixes": 0,
        "disk_warnings": 0,
        "security_issues": 0,
        "ups_warnings": 0,
        "thermal_throttles": 0,
        "issues_total": 0,
        "last_run": None,
        "uptime_start": datetime.now().isoformat(),
    }
    try:
        with open(cfg["stats_file"]) as f:
            return {**default, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_stats(stats):
    os.makedirs(os.path.dirname(cfg["stats_file"]), exist_ok=True)
    try:
        with open(cfg["stats_file"], "w") as f:
            json.dump(stats, f, indent=2)
    except (PermissionError, OSError):
        pass


stats = load_stats()


def track(key, count=1):
    stats[key] = stats.get(key, 0) + count
    stats["issues_total"] = stats.get("issues_total", 0) + count


def run(cmd, timeout=60):
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


# --- Network ---


def check_network():
    """Check internet connectivity, attempt heal via DNS flush."""
    if not cfg["enable_network_heal"]:
        return
    log.info("Checking network...")
    targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    reachable = False
    for t in targets:
        rc, _ = run(f"ping -c 1 -W 3 {t}")
        if rc == 0:
            reachable = True
            break
    if not reachable:
        log.warning("Network down! Attempting fix...")
        run("sudo dscacheutil -flushcache")
        run("sudo killall -HUP mDNSResponder")
        # Try toggling Wi-Fi
        _, wifi_device = run(
            "networksetup -listallhardwareports | awk '/Wi-Fi/{getline; print $2}'"
        )
        if wifi_device:
            run(f"networksetup -setairportpower {wifi_device} off")
            time.sleep(2)
            run(f"networksetup -setairportpower {wifi_device} on")
            time.sleep(5)
        rc, _ = run("ping -c 1 -W 3 8.8.8.8")
        if rc != 0:
            log.warning("Network still down after fix attempt!")
        track("network_restarts")
    else:
        log.info("Network OK.")


def check_dns():
    """Check DNS resolution."""
    if not cfg["enable_dns_heal"]:
        return
    log.info("Checking DNS...")
    rc, _ = run("host -W 3 google.com 2>/dev/null")
    if rc != 0:
        log.warning("DNS broken! Flushing cache...")
        run("sudo dscacheutil -flushcache")
        run("sudo killall -HUP mDNSResponder")
        time.sleep(2)
        rc, _ = run("host -W 3 google.com 2>/dev/null")
        if rc != 0:
            log.warning("DNS still broken after flush!")
            track("dns_fixes")
        else:
            log.info("DNS fixed after flush.")
            track("dns_fixes")
    else:
        log.info("DNS OK.")


# --- Disk Space ---


def check_disk_space():
    """Check disk usage on all mounted volumes."""
    if not cfg["enable_disk_check"]:
        return
    log.info("Checking disk space...")
    _, out = run("df -P -h / /System/Volumes/Data 2>/dev/null")
    if not out:
        return
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            usage = int(parts[4].replace("%", ""))
        except ValueError:
            continue
        mount = parts[5]
        if usage >= cfg["disk_crit_pct"]:
            log.warning(f"CRITICAL: {mount} is {usage}% full!")
            track("disk_warnings")
        elif usage >= cfg["disk_warn_pct"]:
            log.warning(f"WARNING: {mount} is {usage}% full")
            track("disk_warnings")
    log.info("Disk check done.")


# --- Thermals ---


def check_thermals():
    """Check CPU temperature via powermetrics or smckit."""
    log.info("Checking thermals...")
    # macOS doesn't expose temps easily without sudo powermetrics
    rc, out = run(
        "sudo powermetrics --samplers smc -i 1 -n 1 2>/dev/null "
        "| grep -i 'die temp\\|CPU temp' | head -1"
    )
    if rc == 0 and out:
        try:
            temp = float("".join(c for c in out.split(":")[-1] if c.isdigit() or c == "."))
            if temp >= cfg["temp_crit_c"]:
                log.warning(f"CRITICAL temperature: {temp}C!")
                track("thermal_throttles")
            elif temp >= cfg["temp_warn_c"]:
                log.warning(f"High temperature: {temp}C")
                track("thermal_throttles")
            else:
                log.info(f"Temperature OK ({temp}C)")
        except (ValueError, IndexError):
            pass
    else:
        log.info("Temperature: could not read (needs sudo)")


# --- Security ---


def check_security():
    """Basic macOS security posture checks."""
    if not cfg["enable_security_check"]:
        return
    log.info("Checking security posture...")

    # SIP (System Integrity Protection)
    rc, out = run("csrutil status")
    if "enabled" not in out.lower():
        log.warning("SIP is DISABLED!")
        track("security_issues")

    # Gatekeeper
    rc, out = run("spctl --status")
    if "enabled" not in out.lower():
        log.warning("Gatekeeper is DISABLED!")
        track("security_issues")

    # FileVault (disk encryption)
    rc, out = run("fdesetup status")
    if "on" not in out.lower():
        log.warning("FileVault is OFF - disk not encrypted!")
        track("security_issues")

    # Firewall
    rc, out = run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    if "enabled" not in out.lower():
        log.warning("Firewall is DISABLED!")
        track("security_issues")

    # Check for processes from /tmp
    _, out = run("ps aux | awk '$11 ~ /\\/tmp\\// {print $2, $11}'")
    if out:
        log.warning(f"Processes running from /tmp: {out}")
        track("security_issues")

    log.info("Security check done.")


# --- UPS ---


def check_ups():
    """Check UPS availability via NUT (if reachable)."""
    if not cfg["enable_ups_check"]:
        return
    log.info("Checking UPS status...")

    if not shutil.which("upsc"):
        return

    ups_name = cfg.get("ups_name", "riello@pepper.local")
    rc, out = run(f"upsc {ups_name} ups.status 2>/dev/null")
    if rc != 0 or not out:
        log.warning(f"UPS: Cannot reach {ups_name}")
        track("ups_warnings")
        return

    status = out.strip()
    if "OL" in status:
        log.info(f"UPS: Online ({status})")
    elif "OB" in status:
        log.warning(f"UPS: ON BATTERY ({status})!")
        track("ups_warnings")
    elif "LB" in status:
        log.warning(f"UPS: LOW BATTERY ({status})!")
        track("ups_warnings")


# --- Brew ---


def check_brew_health():
    """Check if Homebrew is healthy."""
    log.info("Checking Homebrew...")
    if not shutil.which("brew"):
        log.info("Homebrew not installed, skipping.")
        return
    rc, out = run("brew doctor 2>&1 | head -5")
    if rc != 0:
        log.warning(f"Brew doctor found issues: {out}")
    else:
        log.info("Homebrew OK.")


# --- High CPU ---


def check_high_cpu():
    """Check for processes using excessive CPU."""
    log.info("Checking CPU usage...")
    _, out = run("ps aux | awk 'NR>1 && $3 > 80 {print $2, $3, $11}' | head -5")
    if out:
        log.warning(f"High CPU processes:\n{out}")
    else:
        log.info("CPU usage normal.")


# --- Memory ---


def check_memory():
    """Check memory pressure."""
    log.info("Checking memory...")
    rc, out = run(
        "memory_pressure 2>/dev/null | grep 'System-wide memory free percentage'"
    )
    if rc == 0 and out:
        try:
            pct = int("".join(c for c in out.split(":")[-1] if c.isdigit()))
            if pct < 10:
                log.warning(f"Memory critically low: {pct}% free!")
            elif pct < 20:
                log.warning(f"Memory low: {pct}% free")
            else:
                log.info(f"Memory OK ({pct}% free)")
        except (ValueError, IndexError):
            pass


# --- Heal Cycles ---


def heal_full():
    """Full healing cycle."""
    log.info("========== ROZ NanoBots v5 (macOS) - Full Heal ==========")
    for fn in [
        check_network,
        check_dns,
        check_disk_space,
        check_thermals,
        check_security,
        check_ups,
        check_brew_health,
        check_high_cpu,
        check_memory,
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
    for fn in [check_network, check_high_cpu, check_memory]:
        if shutdown_requested:
            break
        try:
            fn()
        except Exception as e:
            log.error(f"{fn.__name__} failed: {e}")
    save_stats(stats)


def show_status():
    """Display current stats."""
    s = load_stats()
    print("\n╔══════════════════════════════════════╗")
    print("║   🤖 ROZ NanoBots v5 (macOS)         ║")
    print("╠══════════════════════════════════════╣")
    print(f"║  Running since: {s.get('uptime_start', '?')[:19]}")
    print(f"║  Cycles:        {s.get('cycles', 0)}")
    print(f"║  Issues fixed:  {s.get('issues_total', 0)}")
    print(f"║  Last run:      {s.get('last_run', 'never')[:19]}")
    print("╠══════════════════════════════════════╣")
    print(f"║  Network fixes: {s.get('network_restarts', 0)}")
    print(f"║  DNS fixes:     {s.get('dns_fixes', 0)}")
    print(f"║  Disk warnings: {s.get('disk_warnings', 0)}")
    print(f"║  Security:      {s.get('security_issues', 0)}")
    print(f"║  UPS warnings:  {s.get('ups_warnings', 0)}")
    print(f"║  Thermal:       {s.get('thermal_throttles', 0)}")
    print("╚══════════════════════════════════════╝\n")


def handle_cli():
    """Handle CLI subcommands. Returns True if handled."""
    if len(sys.argv) <= 1:
        return False
    cmd = sys.argv[1]
    if cmd == "status":
        show_status()
    elif cmd == "heal":
        heal_full()
        save_stats(stats)
    elif cmd == "quick":
        heal_quick()
    elif cmd == "config":
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"Config created: {CONFIG_FILE}")
        else:
            print(f"Config exists: {CONFIG_FILE}")
    else:
        print(f"Usage: {sys.argv[0]} [status|heal|quick|config]")
    return True


def daemon_loop():
    """Main daemon loop."""
    global stats, shutdown_requested
    log.info("ROZ NanoBots v5 (macOS) activated.")
    log.info(
        f"Full heal every {cfg['interval']}s, "
        f"quick check every {cfg['realtime_interval']}s"
    )

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
    log.info("ROZ NanoBots v5 (macOS) shut down cleanly.")


def main():
    global stats
    if handle_cli():
        return
    daemon_loop()


if __name__ == "__main__":
    main()
