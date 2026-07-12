#!/usr/bin/env python3
"""ROZ NanoBots - SBOM/CMDB/CVE Monitoring Module.

Provides network inventory discovery, Software Bill of Materials generation,
CVE vulnerability scanning with EPSS scoring, and firmware version monitoring.

Can be imported by nanobot.py or run standalone:
    python3 nanobot_sbom.py devices   # list discovered devices
    python3 nanobot_sbom.py scan      # run full scan cycle
    python3 nanobot_sbom.py status    # show module health
"""

import csv
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration (12-factor: environment variables with sane defaults)
# ---------------------------------------------------------------------------

NANOBOT_CONFIG = os.environ.get("NANOBOT_CONFIG", "/etc/nanobot/config.json")
NANOBOT_DATA_DIR = os.environ.get("NANOBOT_DATA_DIR", "/etc/nanobot/data")
NANOBOT_DEVICES_DIR = os.environ.get("NANOBOT_DEVICES_DIR", "/etc/nanobot/devices")
NANOBOT_NETWORKS_DIR = os.environ.get("NANOBOT_NETWORKS_DIR", "/etc/nanobot/networks")
NANOBOT_SECRETS_FILE = os.environ.get("NANOBOT_SECRETS_FILE", "/etc/nanobot/secrets.conf")

MAX_SUBPROCESS_TIMEOUT = 300
SBOM_RETENTION_DAYS = 7
EVENT_RETENTION_DAYS = 90
GONE_THRESHOLD_HOURS = 24
GRYPE_DB_MAX_AGE_HOURS = 48
EPSS_THRESHOLD = 0.1
CVSS_THRESHOLD = 7.0
NEW_CVE_WINDOW_DAYS = 7

# ---------------------------------------------------------------------------
# Logging (matches nanobot.py format)
# ---------------------------------------------------------------------------

log = logging.getLogger("nanobot.sbom")

if not log.handlers and __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [NanoBot:SBOM] %(message)s",
        handlers=[logging.StreamHandler()],
    )

# ---------------------------------------------------------------------------
# Helper: subprocess runner (standalone-compatible copy of nanobot.run)
# ---------------------------------------------------------------------------


def run(cmd: Any, timeout: int = MAX_SUBPROCESS_TIMEOUT) -> Tuple[int, str]:
    """Run a command safely. Returns (returncode, stdout).

    Accepts a string (run via bash -c) or a list of args.
    """
    try:
        if isinstance(cmd, str):
            cmd = ["bash", "-c", cmd]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out ({timeout}s): {cmd}")
        return 1, ""
    except Exception as e:
        log.warning(f"Command error: {cmd}: {e}")
        return 1, ""


def _which(binary: str) -> Optional[str]:
    """Check if a binary is available on PATH."""
    return shutil.which(binary)


def _ensure_dir(path: str) -> Path:
    """Ensure directory exists, return Path object."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _now_iso() -> str:
    """Return current UTC time as ISO string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _file_age_hours(path: str) -> float:
    """Return age of file in hours, or infinity if missing."""
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) / 3600.0
    except OSError:
        return float("inf")


def _sha256_file(path: str) -> str:
    """Compute SHA256 of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------


def _load_secrets() -> Dict[str, str]:
    """Load secrets from secrets.conf (KEY=VALUE format)."""
    secrets = {}
    try:
        with open(NANOBOT_SECRETS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    secrets[key.strip()] = val.strip()
    except (FileNotFoundError, PermissionError):
        pass
    return secrets


def _resolve_secrets(text: str, secrets: Dict[str, str]) -> str:
    """Replace ${SECRET_NAME} placeholders with actual values."""
    def replacer(m):
        key = m.group(1)
        return secrets.get(key, m.group(0))
    return re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}", replacer, text)


def load_sbom_config() -> Dict[str, Any]:
    """Load full SBOM module configuration from environment and config file.

    Returns a dict with all resolved paths and settings.
    Defaults work out of the box with zero config.
    """
    config: Dict[str, Any] = {
        "config_file": NANOBOT_CONFIG,
        "data_dir": NANOBOT_DATA_DIR,
        "devices_dir": NANOBOT_DEVICES_DIR,
        "networks_dir": NANOBOT_NETWORKS_DIR,
        "secrets_file": NANOBOT_SECRETS_FILE,
        "syft_path": "syft",
        "grype_path": "grype",
        "scan_interface": "eth0",
        "subnets": [],
        "gone_threshold_hours": GONE_THRESHOLD_HOURS,
        "sbom_retention_days": SBOM_RETENTION_DAYS,
        "event_retention_days": EVENT_RETENTION_DAYS,
        "notifications": [],
        "epss_csv_url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
        "epss_csv_path": "",
        "firmware_check_interval_hours": 24,
    }

    # Load main config file
    try:
        with open(NANOBOT_CONFIG, "r") as f:
            main_cfg = json.load(f)
        # Top-level path overrides (12-factor: config file overrides defaults)
        for key in ("data_dir", "devices_dir", "networks_dir", "secrets_file"):
            if key in main_cfg:
                config[key] = main_cfg[key]
        # Extract sbom-related keys
        if "sbom" in main_cfg:
            config.update(main_cfg["sbom"])
        if "scan_interface" in main_cfg:
            config["scan_interface"] = main_cfg["scan_interface"]
        if "notifications" in main_cfg:
            config["notifications"] = main_cfg["notifications"]
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        pass

    # Load network config
    networks_dir = Path(config["networks_dir"])
    if networks_dir.is_dir():
        for nf in sorted(networks_dir.glob("*.json")):
            try:
                with open(nf, "r") as f:
                    net = json.load(f)
                if "subnet" in net:
                    config["subnets"].append(net)
                if "interface" in net:
                    config["scan_interface"] = net["interface"]
            except (json.JSONDecodeError, OSError):
                pass

    # Resolve EPSS CSV path
    if not config["epss_csv_path"]:
        config["epss_csv_path"] = str(Path(config["data_dir"]) / "epss_scores.csv")

    config["secrets"] = _load_secrets()
    return config


# Global config singleton (lazy-loaded)
_cfg: Optional[Dict[str, Any]] = None


def _get_cfg() -> Dict[str, Any]:
    """Get or load the module config."""
    global _cfg
    if _cfg is None:
        _cfg = load_sbom_config()
    return _cfg


# ---------------------------------------------------------------------------
# Events Database (SQLite with WAL mode)
# ---------------------------------------------------------------------------


def _db_path() -> str:
    """Return path to the events database."""
    return str(Path(_get_cfg()["data_dir"]) / "events.db")


def init_events_db() -> sqlite3.Connection:
    """Initialize the events database with WAL mode.

    Creates tables if they don't exist:
    - scan_events: records of each scan run
    - cve_findings: CVE detections with dedup
    - alerts_sent: alert delivery log
    - device_changes: network device state changes
    """
    _ensure_dir(_get_cfg()["data_dir"])
    db = sqlite3.connect(_db_path())
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")

    db.executescript("""
        CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT DEFAULT 'running',
            summary TEXT,
            items_found INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS cve_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            package TEXT,
            version TEXT,
            severity TEXT,
            cvss_score REAL,
            epss_score REAL,
            fix_version TEXT,
            source TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            UNIQUE(cve_id, package, version)
        );

        CREATE TABLE IF NOT EXISTS alerts_sent (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            channel TEXT,
            sent_at TEXT NOT NULL,
            success INTEGER DEFAULT 1,
            error_msg TEXT
        );

        CREATE TABLE IF NOT EXISTS device_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            ip TEXT,
            change_type TEXT NOT NULL,
            details TEXT,
            detected_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_findings(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_status ON cve_findings(status);
        CREATE INDEX IF NOT EXISTS idx_device_mac ON device_changes(mac);
        CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_events(scan_type);
    """)
    db.commit()
    return db


def _prune_events_db(db: sqlite3.Connection) -> None:
    """Remove events older than retention period."""
    cfg = _get_cfg()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=cfg["event_retention_days"])).strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("DELETE FROM scan_events WHERE started_at < ?", (cutoff,))
    db.execute("DELETE FROM alerts_sent WHERE sent_at < ?", (cutoff,))
    db.execute("DELETE FROM device_changes WHERE detected_at < ?", (cutoff,))
    # Keep CVE findings longer but mark resolved ones
    db.execute(
        "UPDATE cve_findings SET status='expired' WHERE last_seen < ? AND status='open'",
        (cutoff,),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------


def send_alert(event_type: str, title: str, body: str, severity: str = "medium") -> None:
    """Send alert via configured notification channels.

    Supports:
    - ha_webhook: POST JSON to Home Assistant webhook
    - ntfy: POST to ntfy.sh topic

    Resolves ${SECRET_NAME} placeholders in URLs/tokens.
    """
    cfg = _get_cfg()
    notifications = cfg.get("notifications", [])
    secrets = cfg.get("secrets", {})

    if not notifications:
        log.info(f"Alert ({severity}): {title} - {body} [no channels configured]")
        return

    db = init_events_db()

    for channel in notifications:
        ch_type = channel.get("type", "")
        ch_events = channel.get("events", [])

        # Filter: send only if event_type matches or events list is empty (send all)
        if ch_events and event_type not in ch_events:
            continue

        success = False
        error_msg = ""

        try:
            if ch_type == "ha_webhook":
                url = _resolve_secrets(channel.get("url", ""), secrets)
                payload = json.dumps({
                    "event_type": event_type,
                    "title": title,
                    "message": body,
                    "severity": severity,
                    "timestamp": _now_iso(),
                }).encode("utf-8")
                req = urllib.request.Request(
                    url, data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    success = resp.status < 400

            elif ch_type == "ntfy":
                url = _resolve_secrets(channel.get("url", ""), secrets)
                token = _resolve_secrets(channel.get("token", ""), secrets)
                headers = {
                    "Title": title,
                    "Priority": "high" if severity == "critical" else "default",
                    "Tags": f"nanobot,{event_type},{severity}",
                }
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(
                    url, data=body.encode("utf-8"),
                    headers=headers, method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    success = resp.status < 400

            else:
                log.warning(f"Unknown notification channel type: {ch_type}")
                continue

        except Exception as e:
            error_msg = str(e)
            log.warning(f"Alert delivery failed ({ch_type}): {e}")

        # Record alert
        db.execute(
            "INSERT INTO alerts_sent (event_type, title, severity, channel, sent_at, success, error_msg) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_type, title, severity, ch_type, _now_iso(), int(success), error_msg),
        )
        db.commit()

        if success:
            log.info(f"Alert sent via {ch_type}: {title}")

    db.close()


# ---------------------------------------------------------------------------
# Network Discovery
# ---------------------------------------------------------------------------


def _load_device_registry() -> Dict[str, Dict[str, Any]]:
    """Load all registered devices from devices directory.

    Returns dict keyed by MAC address (lowercase).
    """
    devices: Dict[str, Dict[str, Any]] = {}
    devices_dir = Path(_get_cfg()["devices_dir"])
    if not devices_dir.is_dir():
        return devices

    for df in devices_dir.glob("*.json"):
        if df.name.startswith("_"):
            continue
        try:
            with open(df, "r") as f:
                dev = json.load(f)
            mac = dev.get("mac", "").lower()
            if mac:
                dev["_file"] = str(df)
                devices[mac] = dev
        except (json.JSONDecodeError, OSError):
            pass
    return devices


def _parse_arp_scan(output: str) -> List[Dict[str, str]]:
    """Parse arp-scan --plain output into device dicts."""
    results = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            results.append({
                "ip": parts[0].strip(),
                "mac": parts[1].strip().lower(),
                "vendor": parts[2].strip(),
            })
        elif len(parts) == 2:
            results.append({
                "ip": parts[0].strip(),
                "mac": parts[1].strip().lower(),
                "vendor": "",
            })
    return results


def _parse_avahi_browse(output: str) -> Dict[str, str]:
    """Parse avahi-browse -apt output, return map of IP → hostname."""
    hostnames: Dict[str, str] = {}
    for line in output.splitlines():
        # Format: +;interface;protocol;name;type;domain;hostname;address;port;txt
        parts = line.split(";")
        if len(parts) >= 8 and parts[0] == "=":
            ip = parts[7]
            hostname = parts[6].rstrip(".")
            if ip and hostname:
                hostnames[ip] = hostname
    return hostnames


def check_network_inventory() -> Dict[str, Any]:
    """Perform network inventory scan via ARP + mDNS.

    1. Load network config (subnets to scan)
    2. Run arp-scan on configured interface
    3. Enrich with mDNS hostnames via avahi-browse
    4. Compare against device registry
    5. New devices → write to _discovered/ directory
    6. Missing registered devices → alert if past threshold
    7. Update last_seen timestamps

    Returns summary dict with counts.
    """
    cfg = _get_cfg()
    iface = cfg.get("scan_interface", "eth0")
    devices_dir = Path(cfg["devices_dir"])
    discovered_dir = _ensure_dir(str(devices_dir / "_discovered"))

    result = {
        "scanned_at": _now_iso(),
        "devices_found": 0,
        "new_devices": 0,
        "missing_devices": 0,
        "errors": [],
    }

    # Check for arp-scan
    if not _which("arp-scan"):
        log.warning("arp-scan not found, skipping network inventory")
        result["errors"].append("arp-scan not installed")
        return result

    # Run ARP scan
    rc, out = run(f"arp-scan --localnet --plain -I {iface}")
    if rc != 0:
        log.warning(f"arp-scan failed (rc={rc}) on interface {iface}")
        result["errors"].append(f"arp-scan exit code {rc}")
        # Try without interface specification
        rc, out = run("arp-scan --localnet --plain")
        if rc != 0:
            return result

    found_devices = _parse_arp_scan(out)
    result["devices_found"] = len(found_devices)

    # mDNS enrichment
    hostnames: Dict[str, str] = {}
    if _which("avahi-browse"):
        rc2, mdns_out = run("avahi-browse -apt --no-db-lookup", timeout=15)
        if rc2 == 0:
            hostnames = _parse_avahi_browse(mdns_out)

    # Enrich devices with hostnames
    for dev in found_devices:
        dev["hostname"] = hostnames.get(dev["ip"], "")

    # Load registry
    registry = _load_device_registry()
    seen_macs = set()

    db = init_events_db()

    for dev in found_devices:
        mac = dev["mac"]
        seen_macs.add(mac)

        if mac in registry:
            # Known device - update last_seen
            reg_file = registry[mac].get("_file")
            if reg_file:
                try:
                    with open(reg_file, "r") as f:
                        reg_data = json.load(f)
                    reg_data["last_seen"] = _now_iso()
                    reg_data["last_ip"] = dev["ip"]
                    if dev["hostname"]:
                        reg_data["last_hostname"] = dev["hostname"]
                    with open(reg_file, "w") as f:
                        json.dump(reg_data, f, indent=2)
                except (OSError, json.JSONDecodeError):
                    pass
        else:
            # New device - write to _discovered
            result["new_devices"] += 1
            disc_file = discovered_dir / f"{mac.replace(':', '-')}.json"
            disc_data = {
                "mac": mac,
                "ip": dev["ip"],
                "vendor": dev.get("vendor", ""),
                "hostname": dev.get("hostname", ""),
                "first_seen": _now_iso(),
                "last_seen": _now_iso(),
            }
            try:
                with open(disc_file, "w") as f:
                    json.dump(disc_data, f, indent=2)
            except OSError as e:
                log.warning(f"Failed to write discovered device: {e}")

            # Record change
            db.execute(
                "INSERT INTO device_changes (mac, ip, change_type, details, detected_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (mac, dev["ip"], "new_device", json.dumps(disc_data), _now_iso()),
            )

            log.info(f"New device discovered: {mac} ({dev['ip']}) vendor={dev.get('vendor', 'unknown')}")
            send_alert(
                "new_device",
                f"New device on network: {dev.get('vendor', mac)}",
                f"MAC: {mac}\nIP: {dev['ip']}\nVendor: {dev.get('vendor', 'unknown')}\nHostname: {dev.get('hostname', '')}",
                severity="low",
            )

    # Check for missing registered devices
    gone_threshold = cfg.get("gone_threshold_hours", GONE_THRESHOLD_HOURS)
    for mac, reg in registry.items():
        if mac not in seen_macs:
            last_seen = reg.get("last_seen", "")
            if last_seen:
                try:
                    ls_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00").replace("+00:00", ""))
                    hours_gone = (datetime.now(timezone.utc) - ls_dt.replace(tzinfo=timezone.utc)).total_seconds() / 3600
                    if hours_gone > gone_threshold:
                        result["missing_devices"] += 1
                        name = reg.get("name", reg.get("hostname", mac))
                        log.warning(f"Registered device missing: {name} ({mac}) - gone {hours_gone:.1f}h")
                        send_alert(
                            "device_missing",
                            f"Device offline: {name}",
                            f"MAC: {mac}\nLast seen: {last_seen}\nGone for: {hours_gone:.1f} hours",
                            severity="medium",
                        )
                except (ValueError, TypeError):
                    pass

    db.commit()
    db.close()

    log.info(
        f"Network scan: {result['devices_found']} found, "
        f"{result['new_devices']} new, {result['missing_devices']} missing"
    )
    return result


# ---------------------------------------------------------------------------
# SBOM Generator
# ---------------------------------------------------------------------------


def _cleanup_old_sboms(sbom_dir: Path, retention_days: int) -> None:
    """Remove SBOM files older than retention period."""
    cutoff = time.time() - (retention_days * 86400)
    if not sbom_dir.is_dir():
        return
    for f in sbom_dir.iterdir():
        if f.is_file() and f.suffix == ".json":
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    log.debug(f"Removed old SBOM: {f.name}")
            except OSError:
                pass


def _get_running_containers() -> List[Dict[str, str]]:
    """Get list of running Docker containers."""
    if not _which("docker"):
        return []
    rc, out = run('docker ps --format "{{.ID}}\\t{{.Image}}\\t{{.Names}}"')
    if rc != 0:
        return []
    containers = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append({
                "id": parts[0],
                "image": parts[1],
                "name": parts[2],
            })
    return containers


def _get_image_digest(image: str) -> str:
    """Get Docker image digest for change detection."""
    rc, out = run(f'docker inspect --format="{{{{.Id}}}}" {image}')
    if rc == 0 and out:
        return out.strip()
    return ""


def _native_dpkg_scan() -> List[Dict[str, str]]:
    """Scan installed packages via dpkg."""
    rc, out = run("dpkg-query -W -f '${Package}\\t${Version}\\n'")
    if rc != 0:
        return []
    packages = []
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            packages.append({"name": parts[0], "version": parts[1], "type": "deb"})
    return packages


def _native_snap_scan() -> List[Dict[str, str]]:
    """Scan installed snaps."""
    if not _which("snap"):
        return []
    rc, out = run("snap list --all")
    if rc != 0:
        return []
    packages = []
    for line in out.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "version": parts[1], "type": "snap"})
    return packages


def _native_pip_scan() -> List[Dict[str, str]]:
    """Scan installed pip packages."""
    if not _which("pip3") and not _which("pip"):
        return []
    pip_cmd = "pip3" if _which("pip3") else "pip"
    rc, out = run(f"{pip_cmd} list --format=json")
    if rc != 0:
        return []
    try:
        pip_pkgs = json.loads(out)
        return [{"name": p["name"], "version": p["version"], "type": "pip"} for p in pip_pkgs]
    except (json.JSONDecodeError, KeyError):
        return []


def _native_kernel_modules() -> List[Dict[str, str]]:
    """Scan loaded kernel modules."""
    rc, out = run("lsmod")
    if rc != 0:
        return []
    modules = []
    for line in out.splitlines()[1:]:  # Skip header
        parts = line.split()
        if parts:
            mod_name = parts[0]
            # Get version from modinfo
            rc2, info = run(f"modinfo -F version {mod_name}")
            version = info.strip() if rc2 == 0 and info.strip() else "unknown"
            modules.append({"name": mod_name, "version": version, "type": "kernel_module"})
    return modules


def check_sbom() -> Dict[str, Any]:
    """Generate Software Bill of Materials for host and containers.

    1. Run syft for comprehensive host SBOM (if available)
    2. Scan each running Docker container
    3. Supplement with native package scans (dpkg, snap, pip, kernel modules)
    4. Write SBOMs to data directory with timestamps
    5. Enforce retention policy

    Returns summary dict.
    """
    cfg = _get_cfg()
    data_dir = Path(cfg["data_dir"])
    sbom_dir = _ensure_dir(str(data_dir / "sboms"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    result = {
        "scanned_at": _now_iso(),
        "host_sbom": False,
        "container_sboms": 0,
        "native_packages": 0,
        "errors": [],
    }

    db = init_events_db()
    db.execute(
        "INSERT INTO scan_events (scan_type, started_at, status) VALUES (?, ?, ?)",
        ("sbom", _now_iso(), "running"),
    )
    db.commit()
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    syft_path = cfg.get("syft_path", "syft")
    has_syft = _which(syft_path) is not None

    # Host SBOM via syft
    if has_syft:
        host_sbom_file = sbom_dir / f"sbom-host-{timestamp}.cdx.json"
        rc, out = run(f"{syft_path} dir:/ -o cyclonedx-json --file {host_sbom_file}")
        if rc == 0 and host_sbom_file.exists():
            result["host_sbom"] = True
            # Create a symlink for latest
            latest = sbom_dir / "sbom-host-latest.cdx.json"
            try:
                if latest.is_symlink() or latest.exists():
                    latest.unlink()
                latest.symlink_to(host_sbom_file.name)
            except OSError:
                pass
            log.info(f"Host SBOM generated: {host_sbom_file.name}")
        else:
            result["errors"].append("syft host scan failed")
            log.warning("syft host scan failed")
    else:
        log.info("syft not found, using native package scans only")

    # Container SBOMs
    containers = _get_running_containers()
    digest_cache_file = data_dir / "container_digests.json"
    digests_cache: Dict[str, str] = {}
    try:
        with open(digest_cache_file, "r") as f:
            digests_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    for container in containers:
        image = container["image"]
        name = container["name"]
        digest = _get_image_digest(image)

        # Skip if digest unchanged
        if digest and digests_cache.get(image) == digest:
            log.debug(f"Skipping container {name}: image unchanged")
            continue

        if has_syft:
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
            container_sbom = sbom_dir / f"sbom-container-{safe_name}-{timestamp}.cdx.json"
            rc, _ = run(f"{syft_path} {image} -o cyclonedx-json --file {container_sbom}")
            if rc == 0:
                result["container_sboms"] += 1
                if digest:
                    digests_cache[image] = digest
                log.info(f"Container SBOM generated: {name} ({image})")
            else:
                result["errors"].append(f"syft container scan failed: {name}")

    # Save digest cache
    try:
        with open(digest_cache_file, "w") as f:
            json.dump(digests_cache, f)
    except OSError:
        pass

    # Native package scans (always run as supplement/fallback)
    native_sbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"name": "nanobot-sbom", "version": "1.0.0"}],
        },
        "components": [],
    }

    # dpkg
    dpkg_pkgs = _native_dpkg_scan()
    for pkg in dpkg_pkgs:
        native_sbom["components"].append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:deb/ubuntu/{pkg['name']}@{pkg['version']}",
        })

    # snap
    snap_pkgs = _native_snap_scan()
    for pkg in snap_pkgs:
        native_sbom["components"].append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:snap/{pkg['name']}@{pkg['version']}",
        })

    # pip
    pip_pkgs = _native_pip_scan()
    for pkg in pip_pkgs:
        native_sbom["components"].append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
        })

    # kernel modules (limited scan - first 50 to avoid timeout)
    kmod_pkgs = _native_kernel_modules()[:50]
    for pkg in kmod_pkgs:
        native_sbom["components"].append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "properties": [{"name": "type", "value": "kernel_module"}],
        })

    result["native_packages"] = len(native_sbom["components"])

    # Write native SBOM
    native_sbom_file = sbom_dir / f"sbom-native-{timestamp}.cdx.json"
    try:
        with open(native_sbom_file, "w") as f:
            json.dump(native_sbom, f, indent=2)
        # Symlink latest
        latest_native = sbom_dir / "sbom-native-latest.cdx.json"
        try:
            if latest_native.is_symlink() or latest_native.exists():
                latest_native.unlink()
            latest_native.symlink_to(native_sbom_file.name)
        except OSError:
            pass
    except OSError as e:
        result["errors"].append(f"Failed to write native SBOM: {e}")

    # Cleanup old SBOMs
    _cleanup_old_sboms(sbom_dir, cfg.get("sbom_retention_days", SBOM_RETENTION_DAYS))

    # Update scan event
    db.execute(
        "UPDATE scan_events SET finished_at=?, status=?, items_found=? WHERE id=?",
        (_now_iso(), "completed", result["native_packages"], scan_id),
    )
    db.commit()
    db.close()

    log.info(
        f"SBOM scan complete: host={result['host_sbom']}, "
        f"containers={result['container_sboms']}, native_pkgs={result['native_packages']}"
    )
    return result


# ---------------------------------------------------------------------------
# CVE Checker
# ---------------------------------------------------------------------------


def _load_epss_scores(csv_path: str) -> Dict[str, float]:
    """Load EPSS scores from CSV file.

    Expected format: cve,epss,percentile (with header rows).
    Returns dict of CVE-ID → EPSS probability.
    """
    scores: Dict[str, float] = {}
    if not os.path.isfile(csv_path):
        return scores
    try:
        with open(csv_path, "r", newline="") as f:
            # Skip comment lines
            lines = []
            for line in f:
                if not line.startswith("#"):
                    lines.append(line)
            reader = csv.DictReader(lines)
            for row in reader:
                cve_id = row.get("cve", "").strip()
                epss_str = row.get("epss", "0")
                if cve_id.startswith("CVE-"):
                    try:
                        scores[cve_id] = float(epss_str)
                    except ValueError:
                        pass
    except (OSError, csv.Error) as e:
        log.warning(f"Failed to load EPSS scores: {e}")
    return scores


def _parse_grype_results(output: str) -> List[Dict[str, Any]]:
    """Parse Grype JSON output into findings list."""
    findings = []
    try:
        data = json.loads(output)
        matches = data.get("matches", [])
        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            cve_id = vuln.get("id", "")
            severity = vuln.get("severity", "Unknown")

            # Extract CVSS score
            cvss_score = 0.0
            for cvss in vuln.get("cvss", []):
                score = cvss.get("metrics", {}).get("baseScore", 0)
                if score > cvss_score:
                    cvss_score = score

            fix_versions = vuln.get("fix", {}).get("versions", [])
            fix_version = fix_versions[0] if fix_versions else ""

            findings.append({
                "cve_id": cve_id,
                "package": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "severity": severity,
                "cvss_score": cvss_score,
                "fix_version": fix_version,
                "source": "grype",
            })
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        log.warning(f"Failed to parse Grype output: {e}")
    return findings


def check_cve() -> Dict[str, Any]:
    """Run CVE vulnerability scan against latest SBOM.

    1. Verify grype binary exists
    2. Check grype DB freshness (warn if >48h)
    3. Run grype against host and native SBOMs
    4. Load EPSS scores and join on CVE-ID
    5. Apply significance filter (EPSS > 0.1 OR CVSS >= 7.0 OR new)
    6. Deduplicate against events DB
    7. Generate alerts for new high-priority findings

    Returns summary dict.
    """
    cfg = _get_cfg()
    data_dir = Path(cfg["data_dir"])
    sbom_dir = data_dir / "sboms"
    grype_path = cfg.get("grype_path", "grype")

    result = {
        "scanned_at": _now_iso(),
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "new_findings": 0,
        "filtered_findings": 0,
        "errors": [],
    }

    # Check for grype
    if not _which(grype_path):
        log.warning("grype not found, skipping CVE scan")
        result["errors"].append("grype not installed")
        return result

    # Check DB freshness
    grype_db_dir = Path.home() / ".cache" / "grype" / "db"
    if grype_db_dir.is_dir():
        db_files = list(grype_db_dir.rglob("metadata.json"))
        if db_files:
            age_h = _file_age_hours(str(db_files[0]))
            if age_h > GRYPE_DB_MAX_AGE_HOURS:
                log.warning(f"Grype DB is {age_h:.1f}h old (threshold: {GRYPE_DB_MAX_AGE_HOURS}h)")
                # Attempt update
                run(f"{grype_path} db update", timeout=120)

    db = init_events_db()
    db.execute(
        "INSERT INTO scan_events (scan_type, started_at, status) VALUES (?, ?, ?)",
        ("cve", _now_iso(), "running"),
    )
    db.commit()
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    all_findings: List[Dict[str, Any]] = []

    # Scan host SBOM
    host_sbom = sbom_dir / "sbom-host-latest.cdx.json"
    native_sbom = sbom_dir / "sbom-native-latest.cdx.json"

    for sbom_file in [host_sbom, native_sbom]:
        if not sbom_file.exists():
            continue
        resolved = sbom_file.resolve() if sbom_file.is_symlink() else sbom_file
        rc, out = run(f"{grype_path} sbom:{resolved} -o json")
        if rc == 0 and out:
            findings = _parse_grype_results(out)
            all_findings.extend(findings)
        elif rc != 0:
            result["errors"].append(f"grype scan failed for {sbom_file.name}")

    # Load EPSS scores
    epss_scores = _load_epss_scores(cfg.get("epss_csv_path", ""))

    # Enrich with EPSS and filter
    filtered: List[Dict[str, Any]] = []
    for finding in all_findings:
        cve_id = finding["cve_id"]
        finding["epss_score"] = epss_scores.get(cve_id, 0.0)

        # Apply significance filter
        is_significant = (
            finding["epss_score"] > EPSS_THRESHOLD
            or finding["cvss_score"] >= CVSS_THRESHOLD
            or finding["severity"] in ("Critical", "High")
        )

        if is_significant:
            filtered.append(finding)

    result["total_findings"] = len(all_findings)
    result["filtered_findings"] = len(filtered)

    # Count by severity
    for f in all_findings:
        sev = f["severity"].lower()
        if sev == "critical":
            result["critical"] += 1
        elif sev == "high":
            result["high"] += 1
        elif sev == "medium":
            result["medium"] += 1
        else:
            result["low"] += 1

    # Deduplicate against DB and insert new findings
    now = _now_iso()
    for finding in filtered:
        cursor = db.execute(
            "SELECT id, last_seen FROM cve_findings WHERE cve_id=? AND package=? AND version=?",
            (finding["cve_id"], finding["package"], finding["version"]),
        )
        existing = cursor.fetchone()

        if existing:
            # Update last_seen
            db.execute(
                "UPDATE cve_findings SET last_seen=?, epss_score=?, status='open' WHERE id=?",
                (now, finding["epss_score"], existing[0]),
            )
        else:
            # New finding
            result["new_findings"] += 1
            db.execute(
                "INSERT INTO cve_findings "
                "(cve_id, package, version, severity, cvss_score, epss_score, fix_version, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding["cve_id"], finding["package"], finding["version"],
                    finding["severity"], finding["cvss_score"], finding["epss_score"],
                    finding["fix_version"], finding["source"], now, now,
                ),
            )

    db.commit()

    # Alert on new critical/high findings
    if result["new_findings"] > 0:
        critical_new = [f for f in filtered if f["severity"] in ("Critical", "High")
                        and not db.execute(
                            "SELECT 1 FROM cve_findings WHERE cve_id=? AND first_seen < ?",
                            (f["cve_id"], now)).fetchone()]

        if critical_new:
            alert_body = "\n".join(
                f"• {f['cve_id']} ({f['severity']}): {f['package']}@{f['version']} "
                f"[EPSS:{f['epss_score']:.3f}]"
                for f in critical_new[:10]
            )
            send_alert(
                "cve_critical",
                f"{len(critical_new)} new critical/high CVEs found",
                alert_body,
                severity="critical" if any(f["severity"] == "Critical" for f in critical_new) else "high",
            )

    # Update scan event
    db.execute(
        "UPDATE scan_events SET finished_at=?, status=?, summary=?, items_found=? WHERE id=?",
        (now, "completed", json.dumps(result), result["total_findings"], scan_id),
    )
    db.commit()

    # Prune old events
    _prune_events_db(db)
    db.close()

    log.info(
        f"CVE scan: {result['total_findings']} total, {result['filtered_findings']} significant, "
        f"{result['new_findings']} new (C:{result['critical']} H:{result['high']} "
        f"M:{result['medium']} L:{result['low']})"
    )
    return result


# ---------------------------------------------------------------------------
# Firmware Version Monitor
# ---------------------------------------------------------------------------


def _check_firmware_http(device: Dict[str, Any]) -> Optional[str]:
    """Check firmware version via HTTP API."""
    fw_cfg = device.get("firmware", {})
    url = fw_cfg.get("check_url", "")
    field = fw_cfg.get("version_field", "version")

    if not url:
        return None

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        # Support nested fields via dot notation
        value = data
        for key in field.split("."):
            if isinstance(value, dict):
                value = value.get(key, "")
            else:
                return None
        return str(value) if value else None
    except Exception as e:
        log.debug(f"Firmware HTTP check failed for {device.get('name', '?')}: {e}")
        return None


def _check_firmware_fwupd() -> Dict[str, str]:
    """Get firmware versions from fwupdmgr."""
    if not _which("fwupdmgr"):
        return {}

    rc, out = run("fwupdmgr get-devices --json", timeout=30)
    if rc != 0:
        return {}

    versions: Dict[str, str] = {}
    try:
        data = json.loads(out)
        devices = data.get("Devices", [])
        for dev in devices:
            name = dev.get("Name", "")
            version = dev.get("Version", "")
            if name and version:
                versions[name.lower()] = version
    except (json.JSONDecodeError, KeyError):
        pass
    return versions


def check_firmware_versions() -> Dict[str, Any]:
    """Check firmware versions for registered devices.

    For each device with firmware.check_method:
    - http_api: GET URL, extract version from JSON
    - fwupd: Use fwupdmgr to check local hardware
    - manual: Check if reminder threshold has passed

    Compares current vs registered version and alerts on changes.

    Returns summary dict.
    """
    cfg = _get_cfg()
    registry = _load_device_registry()
    check_interval = cfg.get("firmware_check_interval_hours", 24) * 3600

    result = {
        "checked_at": _now_iso(),
        "devices_checked": 0,
        "updates_found": 0,
        "errors": [],
    }

    # Get fwupd data once (reuse for all fwupd-type devices)
    fwupd_versions = _check_firmware_fwupd()

    db = init_events_db()

    for mac, device in registry.items():
        fw_cfg = device.get("firmware", {})
        check_method = fw_cfg.get("check_method", "")
        if not check_method:
            continue

        # Respect check interval
        last_checked = fw_cfg.get("last_checked", "")
        if last_checked:
            try:
                lc_dt = datetime.fromisoformat(last_checked.replace("Z", "+00:00").replace("+00:00", ""))
                elapsed = (datetime.now(timezone.utc) - lc_dt.replace(tzinfo=timezone.utc)).total_seconds()
                if elapsed < check_interval:
                    continue
            except (ValueError, TypeError):
                pass

        current_version: Optional[str] = None
        registered_version = fw_cfg.get("version", "")
        device_name = device.get("name", mac)

        if check_method == "http_api":
            current_version = _check_firmware_http(device)
        elif check_method == "fwupd":
            fwupd_name = fw_cfg.get("fwupd_name", device_name).lower()
            current_version = fwupd_versions.get(fwupd_name)
        elif check_method == "manual":
            # For manual checks, just remind if threshold passed
            reminder_days = fw_cfg.get("reminder_days", 90)
            if last_checked:
                try:
                    lc_dt = datetime.fromisoformat(last_checked.replace("Z", "+00:00").replace("+00:00", ""))
                    days_since = (datetime.now(timezone.utc) - lc_dt.replace(tzinfo=timezone.utc)).days
                    if days_since >= reminder_days:
                        send_alert(
                            "firmware_reminder",
                            f"Firmware check reminder: {device_name}",
                            f"Last checked {days_since} days ago. Current version: {registered_version}",
                            severity="low",
                        )
                except (ValueError, TypeError):
                    pass
            result["devices_checked"] += 1
            continue
        else:
            result["errors"].append(f"Unknown check_method '{check_method}' for {device_name}")
            continue

        result["devices_checked"] += 1

        if current_version and current_version != registered_version:
            result["updates_found"] += 1
            log.info(
                f"Firmware change detected: {device_name} "
                f"{registered_version} → {current_version}"
            )
            send_alert(
                "firmware_update",
                f"Firmware update: {device_name}",
                f"Version changed: {registered_version} → {current_version}",
                severity="low",
            )

            # Record change
            db.execute(
                "INSERT INTO device_changes (mac, ip, change_type, details, detected_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (mac, device.get("last_ip", ""), "firmware_change",
                 json.dumps({"old": registered_version, "new": current_version}), _now_iso()),
            )

        # Update last_checked in device file
        reg_file = device.get("_file")
        if reg_file and os.path.isfile(reg_file):
            try:
                with open(reg_file, "r") as f:
                    reg_data = json.load(f)
                if "firmware" not in reg_data:
                    reg_data["firmware"] = {}
                reg_data["firmware"]["last_checked"] = _now_iso()
                if current_version:
                    reg_data["firmware"]["current_version"] = current_version
                with open(reg_file, "w") as f:
                    json.dump(reg_data, f, indent=2)
            except (OSError, json.JSONDecodeError):
                pass

    db.commit()
    db.close()

    log.info(
        f"Firmware check: {result['devices_checked']} checked, "
        f"{result['updates_found']} updates found"
    )
    return result


# ---------------------------------------------------------------------------
# Status / Health Check
# ---------------------------------------------------------------------------


def sbom_status() -> Dict[str, Any]:
    """Return health status dict for the SBOM module.

    Used by nanobot.py's self-monitoring to check module health.
    Returns dict with component statuses, last scan times, and findings count.
    """
    cfg = _get_cfg()
    data_dir = Path(cfg["data_dir"])
    sbom_dir = data_dir / "sboms"
    devices_dir = Path(cfg["devices_dir"])

    status: Dict[str, Any] = {
        "module": "sbom",
        "healthy": True,
        "checked_at": _now_iso(),
        "components": {},
        "issues": [],
    }

    # Check tools availability
    tools = {
        "syft": _which(cfg.get("syft_path", "syft")) is not None,
        "grype": _which(cfg.get("grype_path", "grype")) is not None,
        "arp-scan": _which("arp-scan") is not None,
        "avahi-browse": _which("avahi-browse") is not None,
        "docker": _which("docker") is not None,
        "fwupdmgr": _which("fwupdmgr") is not None,
    }
    status["tools"] = tools

    # Check data directory
    status["components"]["data_dir"] = {
        "path": str(data_dir),
        "exists": data_dir.is_dir(),
        "writable": os.access(str(data_dir), os.W_OK) if data_dir.is_dir() else False,
    }

    # Check latest SBOMs
    host_sbom = sbom_dir / "sbom-host-latest.cdx.json"
    native_sbom = sbom_dir / "sbom-native-latest.cdx.json"
    status["components"]["host_sbom"] = {
        "exists": host_sbom.exists(),
        "age_hours": round(_file_age_hours(str(host_sbom)), 1) if host_sbom.exists() else None,
    }
    status["components"]["native_sbom"] = {
        "exists": native_sbom.exists(),
        "age_hours": round(_file_age_hours(str(native_sbom)), 1) if native_sbom.exists() else None,
    }

    # Check devices
    discovered_dir = devices_dir / "_discovered"
    registered_count = len(list(devices_dir.glob("*.json"))) if devices_dir.is_dir() else 0
    discovered_count = len(list(discovered_dir.glob("*.json"))) if discovered_dir.is_dir() else 0
    status["components"]["devices"] = {
        "registered": registered_count,
        "discovered_pending": discovered_count,
    }

    # Check events DB
    db_file = data_dir / "events.db"
    if db_file.exists():
        try:
            db = sqlite3.connect(str(db_file))
            open_cves = db.execute(
                "SELECT COUNT(*) FROM cve_findings WHERE status='open'"
            ).fetchone()[0]
            recent_alerts = db.execute(
                "SELECT COUNT(*) FROM alerts_sent WHERE sent_at > ?",
                ((datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S"),),
            ).fetchone()[0]
            last_scan = db.execute(
                "SELECT scan_type, finished_at, status FROM scan_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            db.close()

            status["components"]["cve_findings"] = {"open": open_cves}
            status["components"]["alerts_24h"] = recent_alerts
            if last_scan:
                status["components"]["last_scan"] = {
                    "type": last_scan[0],
                    "finished_at": last_scan[1],
                    "status": last_scan[2],
                }
        except sqlite3.Error:
            status["issues"].append("events.db corrupt or inaccessible")
    else:
        status["components"]["events_db"] = {"exists": False}

    # Determine overall health
    if not tools.get("arp-scan"):
        status["issues"].append("arp-scan not installed (network discovery disabled)")
    if not tools.get("syft") and not tools.get("grype"):
        status["issues"].append("Neither syft nor grype installed (vulnerability scanning limited)")
    if not status["components"]["data_dir"].get("writable", False):
        status["healthy"] = False
        status["issues"].append("Data directory not writable")

    return status


# ---------------------------------------------------------------------------
# CLI Handler
# ---------------------------------------------------------------------------


def _print_devices_list() -> None:
    """Print all known devices in table format."""
    cfg = _get_cfg()
    devices_dir = Path(cfg["devices_dir"])

    print(f"\n{'='*70}")
    print(f"{'MAC':<20} {'IP':<16} {'Name':<20} {'Last Seen':<20}")
    print(f"{'='*70}")

    # Registered devices
    registry = _load_device_registry()
    if registry:
        print("\n  [Registered Devices]")
        for mac, dev in sorted(registry.items()):
            name = dev.get("name", dev.get("hostname", "—"))
            ip = dev.get("last_ip", dev.get("ip", "—"))
            last_seen = dev.get("last_seen", "never")[:19]
            print(f"  {mac:<20} {ip:<16} {name:<20} {last_seen}")

    # Discovered (unregistered) devices
    discovered_dir = devices_dir / "_discovered"
    if discovered_dir.is_dir():
        disc_files = list(discovered_dir.glob("*.json"))
        if disc_files:
            print(f"\n  [Discovered (Unregistered)]")
            for df in sorted(disc_files):
                try:
                    with open(df) as f:
                        dev = json.load(f)
                    mac = dev.get("mac", "?")
                    ip = dev.get("ip", "?")
                    vendor = dev.get("vendor", "—")
                    last_seen = dev.get("last_seen", "?")[:19]
                    print(f"  {mac:<20} {ip:<16} {vendor:<20} {last_seen}")
                except (json.JSONDecodeError, OSError):
                    pass

    if not registry and not (discovered_dir.is_dir() and list(discovered_dir.glob("*.json"))):
        print("  No devices found. Run a network scan first.")

    print()


def _print_device_show(identifier: str) -> None:
    """Show detailed info for a specific device."""
    registry = _load_device_registry()

    # Search by MAC or name
    device = None
    for mac, dev in registry.items():
        if mac == identifier.lower() or dev.get("name", "").lower() == identifier.lower():
            device = dev
            break

    if not device:
        # Check discovered
        cfg = _get_cfg()
        disc_dir = Path(cfg["devices_dir"]) / "_discovered"
        mac_file = disc_dir / f"{identifier.replace(':', '-')}.json"
        if mac_file.exists():
            try:
                with open(mac_file) as f:
                    device = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    if not device:
        print(f"Device not found: {identifier}")
        return

    print(f"\n{'='*50}")
    print(f"Device: {device.get('name', device.get('mac', '?'))}")
    print(f"{'='*50}")
    for key, val in sorted(device.items()):
        if key.startswith("_"):
            continue
        if isinstance(val, dict):
            print(f"  {key}:")
            for k2, v2 in val.items():
                print(f"    {k2}: {v2}")
        else:
            print(f"  {key}: {val}")
    print()


def _print_status() -> None:
    """Print module status in human-readable format."""
    status = sbom_status()

    print(f"\n{'='*50}")
    print(f"  SBOM Module Status")
    print(f"{'='*50}")
    print(f"  Healthy: {'✓' if status['healthy'] else '✗'}")
    print(f"  Checked: {status['checked_at']}")

    print(f"\n  Tools:")
    for tool, available in status.get("tools", {}).items():
        icon = "✓" if available else "✗"
        print(f"    {icon} {tool}")

    print(f"\n  Components:")
    for name, info in status.get("components", {}).items():
        if isinstance(info, dict):
            parts = [f"{k}={v}" for k, v in info.items()]
            print(f"    {name}: {', '.join(parts)}")
        else:
            print(f"    {name}: {info}")

    if status.get("issues"):
        print(f"\n  Issues:")
        for issue in status["issues"]:
            print(f"    ⚠ {issue}")
    print()


def _run_full_scan() -> None:
    """Run all scan functions sequentially."""
    print("Starting full SBOM scan cycle...")
    print()

    print("[1/4] Network inventory scan...")
    try:
        net_result = check_network_inventory()
        print(f"      Found {net_result['devices_found']} devices, "
              f"{net_result['new_devices']} new")
    except Exception as e:
        print(f"      Error: {e}")

    print("[2/4] SBOM generation...")
    try:
        sbom_result = check_sbom()
        print(f"      Host SBOM: {sbom_result['host_sbom']}, "
              f"Containers: {sbom_result['container_sboms']}, "
              f"Native packages: {sbom_result['native_packages']}")
    except Exception as e:
        print(f"      Error: {e}")

    print("[3/4] CVE scan...")
    try:
        cve_result = check_cve()
        print(f"      Total: {cve_result['total_findings']}, "
              f"Significant: {cve_result['filtered_findings']}, "
              f"New: {cve_result['new_findings']}")
    except Exception as e:
        print(f"      Error: {e}")

    print("[4/4] Firmware check...")
    try:
        fw_result = check_firmware_versions()
        print(f"      Checked: {fw_result['devices_checked']}, "
              f"Updates: {fw_result['updates_found']}")
    except Exception as e:
        print(f"      Error: {e}")

    print("\nScan cycle complete.")


def handle_sbom_cli(args: List[str]) -> None:
    """Handle CLI invocations for the SBOM module.

    Usage:
        devices [list]     - List all known devices
        devices show <id>  - Show device details
        scan               - Run full scan cycle
        status             - Show module health status
        cve                - Run CVE scan only
        sbom               - Generate SBOM only
        network            - Run network scan only
        firmware           - Run firmware check only
    """
    if not args:
        print("Usage: nanobot_sbom.py {devices|scan|status|cve|sbom|network|firmware}")
        print()
        print("Commands:")
        print("  devices [list]      List all known devices")
        print("  devices show <id>   Show device details (MAC or name)")
        print("  scan                Run full scan cycle")
        print("  status              Show module health status")
        print("  cve                 Run CVE vulnerability scan")
        print("  sbom                Generate SBOM")
        print("  network             Run network discovery scan")
        print("  firmware            Run firmware version check")
        return

    cmd = args[0].lower()

    if cmd == "devices":
        if len(args) >= 3 and args[1].lower() == "show":
            _print_device_show(args[2])
        else:
            _print_devices_list()

    elif cmd == "scan":
        _run_full_scan()

    elif cmd == "status":
        if "--json" in args:
            print(json.dumps(sbom_status(), indent=2))
        else:
            _print_status()

    elif cmd == "cve":
        result = check_cve()
        print(json.dumps(result, indent=2))

    elif cmd == "sbom":
        result = check_sbom()
        print(json.dumps(result, indent=2))

    elif cmd == "network":
        result = check_network_inventory()
        print(json.dumps(result, indent=2))

    elif cmd == "firmware":
        result = check_firmware_versions()
        print(json.dumps(result, indent=2))

    else:
        print(f"Unknown command: {cmd}")
        handle_sbom_cli([])


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    handle_sbom_cli(sys.argv[1:])
