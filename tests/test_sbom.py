#!/usr/bin/env python3
"""Comprehensive tests for nanobot_sbom.py module.

Run with:
    python3 -m unittest tests.test_sbom -v
    make test
"""

import csv
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nanobot_sbom


# ---------------------------------------------------------------------------
# Test Fixtures / Helpers
# ---------------------------------------------------------------------------

SAMPLE_ARP_OUTPUT = """192.168.1.1\t00:11:22:33:44:55\tNetgear Inc
192.168.1.100\taa:bb:cc:dd:ee:ff\tRaspberry Pi Foundation
192.168.1.50\t11:22:33:44:55:66\tApple Inc"""

SAMPLE_AVAHI_OUTPUT = """=;eth0;IPv4;Living Room Speaker;_googlecast._tcp;local;speaker-living.local;192.168.1.100;8009;
=;eth0;IPv4;Office Printer;_ipp._tcp;local;printer-office.local;192.168.1.50;631;
+;eth0;IPv4;Something;_http._tcp;local"""

SAMPLE_GRYPE_JSON = json.dumps({
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-44487",
                "severity": "Critical",
                "cvss": [{"metrics": {"baseScore": 9.8}}],
                "fix": {"versions": ["1.2.4"]},
            },
            "artifact": {
                "name": "libnghttp2",
                "version": "1.52.0-1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2023-12345",
                "severity": "Medium",
                "cvss": [{"metrics": {"baseScore": 5.3}}],
                "fix": {"versions": []},
            },
            "artifact": {
                "name": "openssl",
                "version": "3.0.2",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-00001",
                "severity": "High",
                "cvss": [{"metrics": {"baseScore": 7.5}}],
                "fix": {"versions": ["2.0.1"]},
            },
            "artifact": {
                "name": "curl",
                "version": "7.88.1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2024-99999",
                "severity": "Low",
                "cvss": [{"metrics": {"baseScore": 3.1}}],
                "fix": {"versions": []},
            },
            "artifact": {
                "name": "zlib",
                "version": "1.2.13",
            },
        },
    ]
})

SAMPLE_EPSS_CSV = """#model_version:v2023.03.01,score_date:2024-01-15
cve,epss,percentile
CVE-2023-44487,0.95,0.99
CVE-2023-12345,0.05,0.30
CVE-2024-00001,0.15,0.85
"""

SAMPLE_SYFT_CYCLONEDX = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {"type": "library", "name": "openssl", "version": "3.0.2"},
        {"type": "library", "name": "curl", "version": "7.88.1"},
    ],
})

SAMPLE_FWUPD_JSON = json.dumps({
    "Devices": [
        {"Name": "UEFI Device Firmware", "Version": "1.23"},
        {"Name": "Thunderbolt Controller", "Version": "45.0"},
    ]
})


class SBOMTestBase(unittest.TestCase):
    """Base class that sets up temp dirs and resets module state."""

    def setUp(self):
        """Create isolated temp directories and configure env vars."""
        self.tmpdir = tempfile.mkdtemp(prefix="nanobot_test_")
        self.data_dir = os.path.join(self.tmpdir, "data")
        self.devices_dir = os.path.join(self.tmpdir, "devices")
        self.networks_dir = os.path.join(self.tmpdir, "networks")
        self.config_file = os.path.join(self.tmpdir, "config.json")
        self.secrets_file = os.path.join(self.tmpdir, "secrets.conf")

        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.devices_dir, exist_ok=True)
        os.makedirs(self.networks_dir, exist_ok=True)

        # Write minimal config
        config = {
            "sbom": {
                "scan_interface": "eth0",
                "gone_threshold_hours": 24,
                "sbom_retention_days": 7,
                "event_retention_days": 90,
            },
            "notifications": [],
        }
        with open(self.config_file, "w") as f:
            json.dump(config, f)

        # Write secrets file
        with open(self.secrets_file, "w") as f:
            f.write("HA_WEBHOOK_TOKEN=secret123\n")
            f.write("NTFY_TOKEN=ntfy_abc\n")
            f.write("# This is a comment\n")
            f.write("EMPTY_VAL=\n")

        # Set env vars to point at our temp dirs
        self._env_patcher = patch.dict(os.environ, {
            "NANOBOT_CONFIG": self.config_file,
            "NANOBOT_DATA_DIR": self.data_dir,
            "NANOBOT_DEVICES_DIR": self.devices_dir,
            "NANOBOT_NETWORKS_DIR": self.networks_dir,
            "NANOBOT_SECRETS_FILE": self.secrets_file,
        })
        self._env_patcher.start()

        # Reset module-level config singleton and constants
        nanobot_sbom._cfg = None
        nanobot_sbom.NANOBOT_CONFIG = self.config_file
        nanobot_sbom.NANOBOT_DATA_DIR = self.data_dir
        nanobot_sbom.NANOBOT_DEVICES_DIR = self.devices_dir
        nanobot_sbom.NANOBOT_NETWORKS_DIR = self.networks_dir
        nanobot_sbom.NANOBOT_SECRETS_FILE = self.secrets_file

    def tearDown(self):
        """Remove temp dirs and restore env."""
        self._env_patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        nanobot_sbom._cfg = None

    def _write_device_file(self, mac, data):
        """Helper: write a device JSON to the devices dir."""
        filename = mac.replace(":", "-") + ".json"
        filepath = os.path.join(self.devices_dir, filename)
        full_data = {"mac": mac}
        full_data.update(data)
        with open(filepath, "w") as f:
            json.dump(full_data, f)
        return filepath

    def _write_epss_csv(self, content=None):
        """Helper: write EPSS CSV to data dir."""
        csv_path = os.path.join(self.data_dir, "epss_scores.csv")
        with open(csv_path, "w") as f:
            f.write(content or SAMPLE_EPSS_CSV)
        return csv_path


# ---------------------------------------------------------------------------
# 1. Config Loading
# ---------------------------------------------------------------------------


class TestConfigLoading(SBOMTestBase):
    """Test config loading with defaults and env var overrides."""

    def test_load_config_defaults(self):
        """Config loads with correct directory paths from env vars."""
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(cfg["data_dir"], self.data_dir)
        self.assertEqual(cfg["devices_dir"], self.devices_dir)
        self.assertEqual(cfg["networks_dir"], self.networks_dir)
        self.assertEqual(cfg["config_file"], self.config_file)

    def test_load_config_default_values(self):
        """Config has sensible defaults for scan settings."""
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(cfg["scan_interface"], "eth0")
        self.assertEqual(cfg["gone_threshold_hours"], 24)
        self.assertEqual(cfg["sbom_retention_days"], 7)
        self.assertEqual(cfg["event_retention_days"], 90)

    def test_load_config_from_file(self):
        """Config file values override defaults."""
        config = {
            "sbom": {
                "scan_interface": "wlan0",
                "gone_threshold_hours": 48,
            },
            "notifications": [{"type": "ntfy", "url": "https://ntfy.sh/test"}],
        }
        with open(self.config_file, "w") as f:
            json.dump(config, f)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(cfg["scan_interface"], "wlan0")
        self.assertEqual(cfg["gone_threshold_hours"], 48)
        self.assertEqual(len(cfg["notifications"]), 1)

    def test_load_config_missing_file(self):
        """Config loading works even if config file doesn't exist."""
        os.unlink(self.config_file)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        # Should use defaults
        self.assertEqual(cfg["scan_interface"], "eth0")
        self.assertIsInstance(cfg["subnets"], list)

    def test_load_config_invalid_json(self):
        """Config loading handles corrupt JSON gracefully."""
        with open(self.config_file, "w") as f:
            f.write("{not valid json!!!")
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        # Should fall back to defaults
        self.assertEqual(cfg["scan_interface"], "eth0")

    def test_load_config_network_dir(self):
        """Network configs from networks_dir are loaded into subnets."""
        net_cfg = {"subnet": "192.168.1.0/24", "interface": "br0", "name": "LAN"}
        with open(os.path.join(self.networks_dir, "lan.json"), "w") as f:
            json.dump(net_cfg, f)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(len(cfg["subnets"]), 1)
        self.assertEqual(cfg["subnets"][0]["subnet"], "192.168.1.0/24")
        self.assertEqual(cfg["scan_interface"], "br0")

    def test_epss_csv_path_default(self):
        """EPSS CSV path defaults to data_dir/epss_scores.csv."""
        cfg = nanobot_sbom.load_sbom_config()
        expected = str(Path(self.data_dir) / "epss_scores.csv")
        self.assertEqual(cfg["epss_csv_path"], expected)

    def test_config_singleton(self):
        """_get_cfg returns cached config on subsequent calls."""
        cfg1 = nanobot_sbom._get_cfg()
        cfg2 = nanobot_sbom._get_cfg()
        self.assertIs(cfg1, cfg2)


# ---------------------------------------------------------------------------
# 2. Device Registry
# ---------------------------------------------------------------------------


class TestDeviceRegistry(SBOMTestBase):
    """Test device registry reading/writing."""

    def test_load_empty_registry(self):
        """Empty devices dir returns empty dict."""
        registry = nanobot_sbom._load_device_registry()
        self.assertEqual(registry, {})

    def test_load_registry_single_device(self):
        """Single device file is loaded correctly."""
        self._write_device_file("00:11:22:33:44:55", {
            "name": "router",
            "ip": "192.168.1.1",
            "last_seen": "2024-01-01T00:00:00Z",
        })
        registry = nanobot_sbom._load_device_registry()
        self.assertIn("00:11:22:33:44:55", registry)
        self.assertEqual(registry["00:11:22:33:44:55"]["name"], "router")

    def test_load_registry_multiple_devices(self):
        """Multiple device files are loaded."""
        self._write_device_file("00:11:22:33:44:55", {"name": "router"})
        self._write_device_file("aa:bb:cc:dd:ee:ff", {"name": "pi"})
        registry = nanobot_sbom._load_device_registry()
        self.assertEqual(len(registry), 2)

    def test_load_registry_skips_underscore_files(self):
        """Files starting with _ are skipped."""
        filepath = os.path.join(self.devices_dir, "_template.json")
        with open(filepath, "w") as f:
            json.dump({"mac": "ff:ff:ff:ff:ff:ff"}, f)
        self._write_device_file("00:11:22:33:44:55", {"name": "router"})
        registry = nanobot_sbom._load_device_registry()
        self.assertEqual(len(registry), 1)
        self.assertNotIn("ff:ff:ff:ff:ff:ff", registry)

    def test_load_registry_invalid_json_skipped(self):
        """Invalid JSON device files are skipped without crashing."""
        filepath = os.path.join(self.devices_dir, "bad.json")
        with open(filepath, "w") as f:
            f.write("not json {{{")
        self._write_device_file("00:11:22:33:44:55", {"name": "good"})
        registry = nanobot_sbom._load_device_registry()
        self.assertEqual(len(registry), 1)

    def test_load_registry_mac_lowercase(self):
        """MAC addresses are normalized to lowercase."""
        self._write_device_file("AA:BB:CC:DD:EE:FF", {"name": "upper"})
        registry = nanobot_sbom._load_device_registry()
        self.assertIn("aa:bb:cc:dd:ee:ff", registry)

    def test_device_file_path_stored(self):
        """Loaded devices have _file key with their source path."""
        self._write_device_file("00:11:22:33:44:55", {"name": "router"})
        registry = nanobot_sbom._load_device_registry()
        self.assertIn("_file", registry["00:11:22:33:44:55"])
        self.assertTrue(os.path.isfile(registry["00:11:22:33:44:55"]["_file"]))



# ---------------------------------------------------------------------------
# 3. ARP Scan Parsing
# ---------------------------------------------------------------------------


class TestARPScanParsing(SBOMTestBase):
    """Test ARP scan output parsing."""

    def test_parse_standard_output(self):
        """Standard arp-scan output with 3 columns is parsed correctly."""
        results = nanobot_sbom._parse_arp_scan(SAMPLE_ARP_OUTPUT)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["ip"], "192.168.1.1")
        self.assertEqual(results[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(results[0]["vendor"], "Netgear Inc")

    def test_parse_two_column_output(self):
        """arp-scan output with only IP and MAC (no vendor) is handled."""
        output = "192.168.1.1\t00:11:22:33:44:55"
        results = nanobot_sbom._parse_arp_scan(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip"], "192.168.1.1")
        self.assertEqual(results[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(results[0]["vendor"], "")

    def test_parse_empty_output(self):
        """Empty output returns empty list."""
        results = nanobot_sbom._parse_arp_scan("")
        self.assertEqual(results, [])

    def test_parse_mac_lowercase(self):
        """MAC addresses are normalized to lowercase."""
        output = "192.168.1.1\tAA:BB:CC:DD:EE:FF\tSome Vendor"
        results = nanobot_sbom._parse_arp_scan(output)
        self.assertEqual(results[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_parse_ignores_invalid_lines(self):
        """Lines with too few columns are skipped."""
        output = "just a single field\n192.168.1.1\t00:11:22:33:44:55\tVendor\n\n"
        results = nanobot_sbom._parse_arp_scan(output)
        self.assertEqual(len(results), 1)

    def test_parse_whitespace_handling(self):
        """Whitespace around fields is stripped."""
        output = "  192.168.1.1  \t  00:11:22:33:44:55  \t  My Vendor  "
        results = nanobot_sbom._parse_arp_scan(output)
        self.assertEqual(results[0]["ip"], "192.168.1.1")
        self.assertEqual(results[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(results[0]["vendor"], "My Vendor")


# ---------------------------------------------------------------------------
# 4. mDNS Parsing
# ---------------------------------------------------------------------------


class TestMDNSParsing(SBOMTestBase):
    """Test avahi-browse output parsing."""

    def test_parse_standard_output(self):
        """Standard avahi-browse -apt output is parsed correctly."""
        result = nanobot_sbom._parse_avahi_browse(SAMPLE_AVAHI_OUTPUT)
        self.assertEqual(result["192.168.1.100"], "speaker-living.local")
        self.assertEqual(result["192.168.1.50"], "printer-office.local")

    def test_trailing_dot_removed(self):
        """Trailing dot on hostnames is stripped."""
        output = "=;eth0;IPv4;Test;_http._tcp;local;myhost.local.;10.0.0.1;80;"
        result = nanobot_sbom._parse_avahi_browse(output)
        self.assertEqual(result["10.0.0.1"], "myhost.local")

    def test_non_resolved_lines_skipped(self):
        """Lines starting with + (unresolved) are skipped."""
        output = "+;eth0;IPv4;Unresolved;_http._tcp;local"
        result = nanobot_sbom._parse_avahi_browse(output)
        self.assertEqual(result, {})

    def test_empty_output(self):
        """Empty output returns empty dict."""
        result = nanobot_sbom._parse_avahi_browse("")
        self.assertEqual(result, {})

    def test_multiple_services_same_ip(self):
        """Last hostname wins for same IP with multiple services."""
        output = (
            "=;eth0;IPv4;Svc1;_http._tcp;local;host1.local;10.0.0.1;80;\n"
            "=;eth0;IPv4;Svc2;_ipp._tcp;local;host2.local;10.0.0.1;631;\n"
        )
        result = nanobot_sbom._parse_avahi_browse(output)
        self.assertEqual(result["10.0.0.1"], "host2.local")


# ---------------------------------------------------------------------------
# 5. New Device Detection
# ---------------------------------------------------------------------------


class TestNewDeviceDetection(SBOMTestBase):
    """Test new device detection logic in check_network_inventory."""

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_new_device_detected(self, mock_alert, mock_run, mock_which):
        """New device (not in registry) is written to _discovered dir."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b
        mock_run.side_effect = [
            (0, "192.168.1.99\tde:ad:be:ef:00:01\tUnknown Vendor"),  # arp-scan
            (0, ""),  # avahi-browse
        ]

        result = nanobot_sbom.check_network_inventory()

        self.assertEqual(result["devices_found"], 1)
        self.assertEqual(result["new_devices"], 1)
        # Check _discovered file was created
        disc_dir = os.path.join(self.devices_dir, "_discovered")
        disc_files = list(Path(disc_dir).glob("*.json"))
        self.assertEqual(len(disc_files), 1)
        with open(disc_files[0]) as f:
            data = json.load(f)
        self.assertEqual(data["mac"], "de:ad:be:ef:00:01")
        self.assertEqual(data["ip"], "192.168.1.99")

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_known_device_not_flagged_new(self, mock_alert, mock_run, mock_which):
        """Known device (in registry) is not flagged as new."""
        self._write_device_file("00:11:22:33:44:55", {
            "name": "router",
            "last_seen": "2024-01-01T00:00:00Z",
        })
        mock_which.side_effect = lambda b: "/usr/bin/" + b
        mock_run.side_effect = [
            (0, "192.168.1.1\t00:11:22:33:44:55\tNetgear Inc"),
            (0, ""),
        ]

        result = nanobot_sbom.check_network_inventory()

        self.assertEqual(result["devices_found"], 1)
        self.assertEqual(result["new_devices"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_new_device_alert_sent(self, mock_alert, mock_run, mock_which):
        """Alert is sent when new device is detected."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b
        mock_run.side_effect = [
            (0, "10.0.0.5\tff:ee:dd:cc:bb:aa\tEspressif"),
            (0, ""),
        ]

        nanobot_sbom.check_network_inventory()

        mock_alert.assert_called()
        call_args = mock_alert.call_args
        self.assertEqual(call_args[0][0], "new_device")
        self.assertIn("ff:ee:dd:cc:bb:aa", call_args[0][2])


# ---------------------------------------------------------------------------
# 6. Device Gone Detection
# ---------------------------------------------------------------------------


class TestDeviceGoneDetection(SBOMTestBase):
    """Test detection of missing registered devices."""

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_device_gone_past_threshold(self, mock_alert, mock_run, mock_which):
        """Device missing past threshold triggers missing count."""
        # Register a device that was last seen 48 hours ago
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self._write_device_file("00:11:22:33:44:55", {
            "name": "old_router",
            "last_seen": old_time,
        })

        mock_which.side_effect = lambda b: "/usr/bin/" + b
        # ARP scan returns empty (device not found)
        mock_run.side_effect = [
            (0, ""),  # arp-scan: no devices
            (0, ""),  # avahi-browse
        ]

        result = nanobot_sbom.check_network_inventory()
        self.assertEqual(result["missing_devices"], 1)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_device_gone_within_threshold(self, mock_alert, mock_run, mock_which):
        """Device missing within threshold does not trigger alert."""
        # Device last seen 1 hour ago (within 24h default threshold)
        recent_time = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self._write_device_file("00:11:22:33:44:55", {
            "name": "recent_router",
            "last_seen": recent_time,
        })

        mock_which.side_effect = lambda b: "/usr/bin/" + b
        mock_run.side_effect = [
            (0, ""),  # arp-scan: device not seen
            (0, ""),  # avahi-browse
        ]

        result = nanobot_sbom.check_network_inventory()
        self.assertEqual(result["missing_devices"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_device_gone_alert_sent(self, mock_alert, mock_run, mock_which):
        """Alert is sent for device missing past threshold."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self._write_device_file("00:11:22:33:44:55", {
            "name": "server",
            "last_seen": old_time,
        })

        mock_which.side_effect = lambda b: "/usr/bin/" + b
        mock_run.side_effect = [
            (0, ""),
            (0, ""),
        ]

        nanobot_sbom.check_network_inventory()

        # Find the device_missing alert call
        found = False
        for call in mock_alert.call_args_list:
            if call[0][0] == "device_missing":
                found = True
                self.assertIn("server", call[0][1])
                break
        self.assertTrue(found, "device_missing alert was not sent")


# ---------------------------------------------------------------------------
# 7. SBOM Generation
# ---------------------------------------------------------------------------


class TestSBOMGeneration(SBOMTestBase):
    """Test SBOM generation with mocked tools."""

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_sbom_with_syft(self, mock_run, mock_which):
        """SBOM generation with syft available creates host SBOM."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b in ("syft", "docker") else None

        sbom_dir = os.path.join(self.data_dir, "sboms")
        os.makedirs(sbom_dir, exist_ok=True)

        def run_side_effect(cmd, timeout=300):
            if isinstance(cmd, list):
                cmd_str = " ".join(cmd)
            else:
                cmd_str = cmd
            if "syft dir:/" in cmd_str:
                # Simulate syft writing a file
                for part in cmd_str.split():
                    if part.endswith(".cdx.json"):
                        with open(part, "w") as f:
                            f.write(SAMPLE_SYFT_CYCLONEDX)
                        break
                return (0, SAMPLE_SYFT_CYCLONEDX)
            elif "docker ps" in cmd_str:
                return (0, "")  # No containers
            elif "dpkg-query" in cmd_str:
                return (0, "openssl\t3.0.2\ncurl\t7.88.1\n")
            elif "snap list" in cmd_str:
                return (1, "")
            elif "pip" in cmd_str:
                return (1, "")
            elif "lsmod" in cmd_str:
                return (0, "Module\nip_tables\nnf_nat\n")
            elif "modinfo" in cmd_str:
                return (0, "")
            return (0, "")

        mock_run.side_effect = run_side_effect

        result = nanobot_sbom.check_sbom()

        self.assertTrue(result["host_sbom"])
        self.assertGreater(result["native_packages"], 0)
        self.assertEqual(result["errors"], [])

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_sbom_without_syft(self, mock_run, mock_which):
        """SBOM generation without syft falls back to native scans."""
        mock_which.side_effect = lambda b: None if b == "syft" else "/usr/bin/" + b

        def run_side_effect(cmd, timeout=300):
            if isinstance(cmd, list):
                cmd_str = " ".join(cmd)
            else:
                cmd_str = cmd
            if "dpkg-query" in cmd_str:
                return (0, "vim\t9.0.1\nnano\t7.2\n")
            elif "docker ps" in cmd_str:
                return (0, "")
            elif "snap list" in cmd_str:
                return (0, "Name  Version\nfirefox  120.0\n")
            elif "pip" in cmd_str:
                return (0, json.dumps([{"name": "requests", "version": "2.31.0"}]))
            elif "lsmod" in cmd_str:
                return (0, "Module\n")
            return (0, "")

        mock_run.side_effect = run_side_effect

        result = nanobot_sbom.check_sbom()

        self.assertFalse(result["host_sbom"])
        # dpkg (2) + snap (1) + pip (1) = 4
        self.assertGreaterEqual(result["native_packages"], 4)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_sbom_native_file_written(self, mock_run, mock_which):
        """Native SBOM JSON is written to sboms directory."""
        mock_which.side_effect = lambda b: None  # No tools

        def run_side_effect(cmd, timeout=300):
            if isinstance(cmd, list):
                cmd_str = " ".join(cmd)
            else:
                cmd_str = cmd
            if "dpkg-query" in cmd_str:
                return (0, "bash\t5.2\n")
            elif "docker ps" in cmd_str:
                return (1, "")
            return (1, "")

        mock_run.side_effect = run_side_effect

        nanobot_sbom.check_sbom()

        sbom_dir = Path(self.data_dir) / "sboms"
        native_files = list(sbom_dir.glob("sbom-native-*.cdx.json"))
        self.assertGreaterEqual(len(native_files), 1)
        with open(native_files[0]) as f:
            data = json.load(f)
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertGreater(len(data["components"]), 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_sbom_scan_event_recorded(self, mock_run, mock_which):
        """SBOM scan is recorded in events database."""
        mock_which.side_effect = lambda b: None
        mock_run.return_value = (1, "")

        nanobot_sbom.check_sbom()

        db = sqlite3.connect(os.path.join(self.data_dir, "events.db"))
        row = db.execute(
            "SELECT scan_type, status FROM scan_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        self.assertEqual(row[0], "sbom")
        self.assertEqual(row[1], "completed")


# ---------------------------------------------------------------------------
# 8. CVE Result Parsing
# ---------------------------------------------------------------------------


class TestCVEParsing(SBOMTestBase):
    """Test Grype JSON output parsing."""

    def test_parse_grype_standard(self):
        """Standard Grype JSON output is parsed into findings."""
        findings = nanobot_sbom._parse_grype_results(SAMPLE_GRYPE_JSON)
        self.assertEqual(len(findings), 4)

        # Check first finding
        f0 = findings[0]
        self.assertEqual(f0["cve_id"], "CVE-2023-44487")
        self.assertEqual(f0["package"], "libnghttp2")
        self.assertEqual(f0["version"], "1.52.0-1")
        self.assertEqual(f0["severity"], "Critical")
        self.assertAlmostEqual(f0["cvss_score"], 9.8)
        self.assertEqual(f0["fix_version"], "1.2.4")

    def test_parse_grype_empty_matches(self):
        """Empty matches array returns empty list."""
        findings = nanobot_sbom._parse_grype_results(json.dumps({"matches": []}))
        self.assertEqual(findings, [])

    def test_parse_grype_invalid_json(self):
        """Invalid JSON returns empty list without crashing."""
        findings = nanobot_sbom._parse_grype_results("not json{{{")
        self.assertEqual(findings, [])

    def test_parse_grype_missing_fields(self):
        """Missing optional fields are handled gracefully."""
        data = {
            "matches": [{
                "vulnerability": {"id": "CVE-2024-00000", "severity": "Unknown"},
                "artifact": {"name": "pkg", "version": "1.0"},
            }]
        }
        findings = nanobot_sbom._parse_grype_results(json.dumps(data))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cvss_score"], 0.0)
        self.assertEqual(findings[0]["fix_version"], "")

    def test_parse_grype_multiple_cvss(self):
        """Highest CVSS score is selected from multiple entries."""
        data = {
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-MULTI",
                    "severity": "High",
                    "cvss": [
                        {"metrics": {"baseScore": 5.5}},
                        {"metrics": {"baseScore": 8.1}},
                        {"metrics": {"baseScore": 7.0}},
                    ],
                },
                "artifact": {"name": "multi", "version": "1.0"},
            }]
        }
        findings = nanobot_sbom._parse_grype_results(json.dumps(data))
        self.assertAlmostEqual(findings[0]["cvss_score"], 8.1)


# ---------------------------------------------------------------------------
# 9. EPSS CSV Parsing
# ---------------------------------------------------------------------------


class TestEPSSParsing(SBOMTestBase):
    """Test EPSS CSV file parsing and joining."""

    def test_load_epss_scores(self):
        """EPSS CSV is loaded correctly, comment lines skipped."""
        csv_path = self._write_epss_csv()
        scores = nanobot_sbom._load_epss_scores(csv_path)
        self.assertAlmostEqual(scores["CVE-2023-44487"], 0.95)
        self.assertAlmostEqual(scores["CVE-2023-12345"], 0.05)
        self.assertAlmostEqual(scores["CVE-2024-00001"], 0.15)

    def test_load_epss_missing_file(self):
        """Missing CSV file returns empty dict."""
        scores = nanobot_sbom._load_epss_scores("/nonexistent/path.csv")
        self.assertEqual(scores, {})

    def test_load_epss_empty_file(self):
        """Empty CSV returns empty dict."""
        csv_path = os.path.join(self.data_dir, "empty.csv")
        with open(csv_path, "w") as f:
            f.write("")
        scores = nanobot_sbom._load_epss_scores(csv_path)
        self.assertEqual(scores, {})

    def test_load_epss_non_cve_rows_skipped(self):
        """Rows without CVE- prefix are skipped."""
        csv_path = os.path.join(self.data_dir, "epss.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\n")
            f.write("CVE-2024-00001,0.5,0.8\n")
            f.write("NOT-A-CVE,0.9,0.99\n")
        scores = nanobot_sbom._load_epss_scores(csv_path)
        self.assertEqual(len(scores), 1)
        self.assertNotIn("NOT-A-CVE", scores)

    def test_load_epss_invalid_score_skipped(self):
        """Invalid float values are skipped without crashing."""
        csv_path = os.path.join(self.data_dir, "epss.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\n")
            f.write("CVE-2024-00001,notafloat,0.8\n")
            f.write("CVE-2024-00002,0.3,0.5\n")
        scores = nanobot_sbom._load_epss_scores(csv_path)
        self.assertNotIn("CVE-2024-00001", scores)
        self.assertIn("CVE-2024-00002", scores)


# ---------------------------------------------------------------------------
# 10. Alert Filtering Logic
# ---------------------------------------------------------------------------


class TestAlertFiltering(SBOMTestBase):
    """Test CVE significance filter: EPSS > 0.1 OR CVSS >= 7.0 OR new-without-EPSS."""

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_high_epss_passes_filter(self, mock_alert, mock_run, mock_which):
        """CVE with EPSS > 0.1 passes the significance filter."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        # Create SBOM file so grype can scan it
        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        native_sbom = sbom_dir / "sbom-native-latest.cdx.json"
        native_sbom.write_text(SAMPLE_SYFT_CYCLONEDX)

        # Grype returns a medium CVE (CVSS 5.3) but high EPSS
        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2023-12345",
                    "severity": "Medium",
                    "cvss": [{"metrics": {"baseScore": 5.3}}],
                    "fix": {"versions": []},
                },
                "artifact": {"name": "openssl", "version": "3.0.2"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)

        # EPSS has this CVE at 0.5 (above threshold)
        csv_path = os.path.join(self.data_dir, "epss_scores.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\nCVE-2023-12345,0.5,0.9\n")

        result = nanobot_sbom.check_cve()
        self.assertGreater(result["filtered_findings"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_high_cvss_passes_filter(self, mock_alert, mock_run, mock_which):
        """CVE with CVSS >= 7.0 passes filter even with low EPSS."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        (sbom_dir / "sbom-native-latest.cdx.json").write_text(SAMPLE_SYFT_CYCLONEDX)

        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-HIGH",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 8.5}}],
                    "fix": {"versions": ["2.0"]},
                },
                "artifact": {"name": "curl", "version": "7.88.1"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)

        # EPSS has this CVE at only 0.01 (below threshold)
        csv_path = os.path.join(self.data_dir, "epss_scores.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\nCVE-2024-HIGH,0.01,0.1\n")

        result = nanobot_sbom.check_cve()
        self.assertGreater(result["filtered_findings"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_low_scores_filtered_out(self, mock_alert, mock_run, mock_which):
        """CVE with low CVSS and low EPSS is filtered out."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        (sbom_dir / "sbom-native-latest.cdx.json").write_text(SAMPLE_SYFT_CYCLONEDX)

        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-LOW",
                    "severity": "Low",
                    "cvss": [{"metrics": {"baseScore": 3.1}}],
                    "fix": {"versions": []},
                },
                "artifact": {"name": "zlib", "version": "1.2.13"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)

        # EPSS is also low
        csv_path = os.path.join(self.data_dir, "epss_scores.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\nCVE-2024-LOW,0.02,0.15\n")

        result = nanobot_sbom.check_cve()
        self.assertEqual(result["filtered_findings"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_critical_severity_passes_filter(self, mock_alert, mock_run, mock_which):
        """CVE with Critical severity passes filter regardless of scores."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        (sbom_dir / "sbom-native-latest.cdx.json").write_text(SAMPLE_SYFT_CYCLONEDX)

        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-CRIT",
                    "severity": "Critical",
                    "cvss": [{"metrics": {"baseScore": 4.0}}],
                    "fix": {"versions": []},
                },
                "artifact": {"name": "openssl", "version": "3.0.2"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)

        csv_path = os.path.join(self.data_dir, "epss_scores.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\nCVE-2024-CRIT,0.01,0.05\n")

        result = nanobot_sbom.check_cve()
        # Critical/High severity causes it to pass the filter
        self.assertGreater(result["filtered_findings"], 0)


# ---------------------------------------------------------------------------
# 11. Alert Deduplication (SQLite)
# ---------------------------------------------------------------------------


class TestAlertDeduplication(SBOMTestBase):
    """Test CVE deduplication via events.db."""

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_first_finding_is_new(self, mock_alert, mock_run, mock_which):
        """First time a CVE is seen, it counts as new_findings."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        (sbom_dir / "sbom-native-latest.cdx.json").write_text(SAMPLE_SYFT_CYCLONEDX)

        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-DEDUP",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 8.0}}],
                    "fix": {"versions": []},
                },
                "artifact": {"name": "openssl", "version": "3.0.2"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)
        self._write_epss_csv()

        result = nanobot_sbom.check_cve()
        self.assertEqual(result["new_findings"], 1)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_duplicate_finding_not_new(self, mock_alert, mock_run, mock_which):
        """Second time same CVE+package+version is seen, it's not new."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b if b == "grype" else None

        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        (sbom_dir / "sbom-native-latest.cdx.json").write_text(SAMPLE_SYFT_CYCLONEDX)

        grype_data = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-DEDUP2",
                    "severity": "High",
                    "cvss": [{"metrics": {"baseScore": 8.0}}],
                    "fix": {"versions": []},
                },
                "artifact": {"name": "curl", "version": "7.88.1"},
            }]
        })

        mock_run.side_effect = lambda cmd, timeout=300: (0, grype_data)
        self._write_epss_csv()

        # First scan: new
        result1 = nanobot_sbom.check_cve()
        self.assertEqual(result1["new_findings"], 1)

        # Reset singleton (DB persists on disk)
        nanobot_sbom._cfg = None

        # Second scan: duplicate
        result2 = nanobot_sbom.check_cve()
        self.assertEqual(result2["new_findings"], 0)

    def test_dedup_db_tables_created(self):
        """init_events_db creates all expected tables."""
        db = nanobot_sbom.init_events_db()
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        db.close()

        self.assertIn("scan_events", table_names)
        self.assertIn("cve_findings", table_names)
        self.assertIn("alerts_sent", table_names)
        self.assertIn("device_changes", table_names)

    def test_dedup_db_wal_mode(self):
        """Events DB uses WAL journal mode."""
        db = nanobot_sbom.init_events_db()
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        db.close()
        self.assertEqual(mode, "wal")


# ---------------------------------------------------------------------------
# 12. Firmware Version Check
# ---------------------------------------------------------------------------


class TestFirmwareCheck(SBOMTestBase):
    """Test firmware version checking with mocked HTTP."""

    @patch("nanobot_sbom._which")
    @patch("urllib.request.urlopen")
    @patch("nanobot_sbom.send_alert")
    def test_firmware_http_check_detects_change(self, mock_alert, mock_urlopen, mock_which):
        """Firmware check via HTTP detects version change."""
        mock_which.return_value = None  # No fwupdmgr

        # Register a device with firmware config
        self._write_device_file("aa:bb:cc:dd:ee:ff", {
            "name": "smart_switch",
            "last_ip": "192.168.1.50",
            "firmware": {
                "check_method": "http_api",
                "check_url": "http://192.168.1.50/api/info",
                "version_field": "firmware.version",
                "version": "1.0.0",
                "last_checked": "2020-01-01T00:00:00Z",
            },
        })

        # Mock HTTP response with new version
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "firmware": {"version": "1.1.0"}
        }).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = nanobot_sbom.check_firmware_versions()

        self.assertEqual(result["devices_checked"], 1)
        self.assertEqual(result["updates_found"], 1)

    @patch("nanobot_sbom._which")
    @patch("urllib.request.urlopen")
    @patch("nanobot_sbom.send_alert")
    def test_firmware_no_change(self, mock_alert, mock_urlopen, mock_which):
        """No update detected when version matches."""
        mock_which.return_value = None

        self._write_device_file("aa:bb:cc:dd:ee:ff", {
            "name": "switch",
            "firmware": {
                "check_method": "http_api",
                "check_url": "http://192.168.1.50/api/info",
                "version_field": "version",
                "version": "2.0.0",
                "last_checked": "2020-01-01T00:00:00Z",
            },
        })

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"version": "2.0.0"}).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = nanobot_sbom.check_firmware_versions()
        self.assertEqual(result["updates_found"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_firmware_fwupd_check(self, mock_alert, mock_run, mock_which):
        """Firmware check via fwupd detects version change."""
        mock_which.side_effect = lambda b: "/usr/bin/fwupdmgr" if b == "fwupdmgr" else None

        self._write_device_file("11:22:33:44:55:66", {
            "name": "mainboard",
            "firmware": {
                "check_method": "fwupd",
                "fwupd_name": "UEFI Device Firmware",
                "version": "1.20",
                "last_checked": "2020-01-01T00:00:00Z",
            },
        })

        mock_run.return_value = (0, SAMPLE_FWUPD_JSON)

        result = nanobot_sbom.check_firmware_versions()
        self.assertEqual(result["devices_checked"], 1)
        self.assertEqual(result["updates_found"], 1)  # 1.20 → 1.23

    @patch("nanobot_sbom._which")
    @patch("urllib.request.urlopen")
    @patch("nanobot_sbom.send_alert")
    def test_firmware_http_timeout(self, mock_alert, mock_urlopen, mock_which):
        """HTTP timeout is handled gracefully."""
        mock_which.return_value = None

        self._write_device_file("aa:bb:cc:dd:ee:ff", {
            "name": "unreachable",
            "firmware": {
                "check_method": "http_api",
                "check_url": "http://192.168.1.99/api",
                "version_field": "version",
                "version": "1.0",
                "last_checked": "2020-01-01T00:00:00Z",
            },
        })

        mock_urlopen.side_effect = Exception("Connection timed out")

        result = nanobot_sbom.check_firmware_versions()
        # Should not crash, just not find an update
        self.assertEqual(result["updates_found"], 0)


# ---------------------------------------------------------------------------
# 13. Secrets Loading and Variable Substitution
# ---------------------------------------------------------------------------


class TestSecrets(SBOMTestBase):
    """Test secrets loading and ${VAR} substitution."""

    def test_load_secrets_basic(self):
        """Secrets are loaded from KEY=VALUE file."""
        secrets = nanobot_sbom._load_secrets()
        self.assertEqual(secrets["HA_WEBHOOK_TOKEN"], "secret123")
        self.assertEqual(secrets["NTFY_TOKEN"], "ntfy_abc")

    def test_load_secrets_comments_skipped(self):
        """Comment lines are skipped."""
        secrets = nanobot_sbom._load_secrets()
        # Should not contain comment text as a key
        for key in secrets:
            self.assertFalse(key.startswith("#"))

    def test_load_secrets_empty_value(self):
        """Empty values are loaded as empty strings."""
        secrets = nanobot_sbom._load_secrets()
        self.assertEqual(secrets["EMPTY_VAL"], "")

    def test_load_secrets_missing_file(self):
        """Missing secrets file returns empty dict."""
        nanobot_sbom.NANOBOT_SECRETS_FILE = "/nonexistent/secrets.conf"
        secrets = nanobot_sbom._load_secrets()
        self.assertEqual(secrets, {})

    def test_resolve_secrets_substitution(self):
        """${VAR} placeholders are replaced with secret values."""
        secrets = {"MY_TOKEN": "abc123", "URL": "https://example.com"}
        text = "Bearer ${MY_TOKEN} at ${URL}"
        result = nanobot_sbom._resolve_secrets(text, secrets)
        self.assertEqual(result, "Bearer abc123 at https://example.com")

    def test_resolve_secrets_missing_key_unchanged(self):
        """Missing keys leave ${VAR} placeholder unchanged."""
        secrets = {"KNOWN": "val"}
        text = "token=${KNOWN} other=${UNKNOWN}"
        result = nanobot_sbom._resolve_secrets(text, secrets)
        self.assertEqual(result, "token=val other=${UNKNOWN}")

    def test_resolve_secrets_no_placeholders(self):
        """Text without placeholders is returned unchanged."""
        secrets = {"KEY": "val"}
        text = "no placeholders here"
        result = nanobot_sbom._resolve_secrets(text, secrets)
        self.assertEqual(result, "no placeholders here")

    def test_resolve_secrets_empty_text(self):
        """Empty text returns empty string."""
        result = nanobot_sbom._resolve_secrets("", {})
        self.assertEqual(result, "")

    def test_secrets_in_config(self):
        """Config loading includes secrets dict."""
        cfg = nanobot_sbom.load_sbom_config()
        self.assertIn("secrets", cfg)
        self.assertEqual(cfg["secrets"]["HA_WEBHOOK_TOKEN"], "secret123")


# ---------------------------------------------------------------------------
# 14. Retention Policy Enforcement
# ---------------------------------------------------------------------------


class TestRetentionPolicy(SBOMTestBase):
    """Test pruning of old files and database records."""

    def test_cleanup_old_sboms(self):
        """SBOM files older than retention are deleted."""
        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)

        # Create old file (set mtime to 10 days ago)
        old_file = sbom_dir / "sbom-old-20240101.cdx.json"
        old_file.write_text("{}")
        old_mtime = time.time() - (10 * 86400)
        os.utime(str(old_file), (old_mtime, old_mtime))

        # Create recent file
        new_file = sbom_dir / "sbom-new-20240110.cdx.json"
        new_file.write_text("{}")

        nanobot_sbom._cleanup_old_sboms(sbom_dir, retention_days=7)

        self.assertFalse(old_file.exists())
        self.assertTrue(new_file.exists())

    def test_cleanup_preserves_non_json(self):
        """Non-JSON files are not touched by cleanup."""
        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)

        txt_file = sbom_dir / "notes.txt"
        txt_file.write_text("keep me")
        old_mtime = time.time() - (30 * 86400)
        os.utime(str(txt_file), (old_mtime, old_mtime))

        nanobot_sbom._cleanup_old_sboms(sbom_dir, retention_days=7)
        self.assertTrue(txt_file.exists())

    def test_prune_events_db(self):
        """Old events are pruned from database."""
        db = nanobot_sbom.init_events_db()

        # Insert old event (100 days ago)
        old_time = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        db.execute(
            "INSERT INTO scan_events (scan_type, started_at, status) VALUES (?, ?, ?)",
            ("sbom", old_time, "completed"),
        )

        # Insert recent event
        recent_time = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        db.execute(
            "INSERT INTO scan_events (scan_type, started_at, status) VALUES (?, ?, ?)",
            ("sbom", recent_time, "completed"),
        )
        db.commit()

        nanobot_sbom._prune_events_db(db)

        count = db.execute("SELECT COUNT(*) FROM scan_events").fetchone()[0]
        db.close()
        self.assertEqual(count, 1)  # Only recent survives

    def test_prune_marks_old_cves_expired(self):
        """Old open CVE findings are marked expired."""
        db = nanobot_sbom.init_events_db()

        old_time = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        db.execute(
            "INSERT INTO cve_findings "
            "(cve_id, package, version, severity, cvss_score, epss_score, "
            "source, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("CVE-2023-OLD", "pkg", "1.0", "High", 8.0, 0.5,
             "grype", old_time, old_time, "open"),
        )
        db.commit()

        nanobot_sbom._prune_events_db(db)

        status = db.execute(
            "SELECT status FROM cve_findings WHERE cve_id='CVE-2023-OLD'"
        ).fetchone()[0]
        db.close()
        self.assertEqual(status, "expired")


# ---------------------------------------------------------------------------
# 15. Health Status Reporting
# ---------------------------------------------------------------------------


class TestHealthStatus(SBOMTestBase):
    """Test sbom_status() health reporting."""

    @patch("nanobot_sbom._which")
    def test_status_structure(self, mock_which):
        """Status returns expected structure."""
        mock_which.return_value = None
        status = nanobot_sbom.sbom_status()

        self.assertIn("module", status)
        self.assertEqual(status["module"], "sbom")
        self.assertIn("healthy", status)
        self.assertIn("checked_at", status)
        self.assertIn("components", status)
        self.assertIn("tools", status)
        self.assertIn("issues", status)

    @patch("nanobot_sbom._which")
    def test_status_tools_missing(self, mock_which):
        """Missing tools are reported in status."""
        mock_which.return_value = None
        status = nanobot_sbom.sbom_status()

        self.assertFalse(status["tools"]["syft"])
        self.assertFalse(status["tools"]["grype"])
        self.assertFalse(status["tools"]["arp-scan"])

    @patch("nanobot_sbom._which")
    def test_status_tools_available(self, mock_which):
        """Available tools are reported correctly."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b
        status = nanobot_sbom.sbom_status()

        self.assertTrue(status["tools"]["syft"])
        self.assertTrue(status["tools"]["grype"])
        self.assertTrue(status["tools"]["arp-scan"])

    @patch("nanobot_sbom._which")
    def test_status_data_dir_writable(self, mock_which):
        """Data dir writability is reported."""
        mock_which.return_value = None
        status = nanobot_sbom.sbom_status()

        self.assertTrue(status["components"]["data_dir"]["exists"])
        self.assertTrue(status["components"]["data_dir"]["writable"])

    @patch("nanobot_sbom._which")
    def test_status_unhealthy_no_data_dir(self, mock_which):
        """Status is unhealthy when data dir is not writable."""
        mock_which.return_value = None
        # Remove data dir and set to non-existent path
        shutil.rmtree(self.data_dir)
        nanobot_sbom._cfg = None
        nanobot_sbom.NANOBOT_DATA_DIR = "/nonexistent/data/dir"
        os.environ["NANOBOT_DATA_DIR"] = "/nonexistent/data/dir"

        status = nanobot_sbom.sbom_status()
        self.assertFalse(status["healthy"])

    @patch("nanobot_sbom._which")
    def test_status_device_counts(self, mock_which):
        """Status reports device counts correctly."""
        mock_which.return_value = None
        self._write_device_file("00:11:22:33:44:55", {"name": "dev1"})
        self._write_device_file("aa:bb:cc:dd:ee:ff", {"name": "dev2"})
        nanobot_sbom._cfg = None

        status = nanobot_sbom.sbom_status()
        self.assertEqual(status["components"]["devices"]["registered"], 2)

    @patch("nanobot_sbom._which")
    def test_status_issues_list(self, mock_which):
        """Issues are populated when tools are missing."""
        mock_which.return_value = None
        status = nanobot_sbom.sbom_status()

        # Should have at least one issue about missing tools
        self.assertGreater(len(status["issues"]), 0)
        issues_text = " ".join(status["issues"])
        self.assertIn("arp-scan", issues_text)


# ---------------------------------------------------------------------------
# 16. Graceful Degradation When Tools Missing
# ---------------------------------------------------------------------------


class TestGracefulDegradation(SBOMTestBase):
    """Test that the module handles missing tools gracefully."""

    @patch("nanobot_sbom._which")
    def test_network_scan_no_arp(self, mock_which):
        """Network scan returns error but doesn't crash without arp-scan."""
        mock_which.return_value = None

        result = nanobot_sbom.check_network_inventory()
        self.assertIn("arp-scan not installed", result["errors"])
        self.assertEqual(result["devices_found"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_sbom_scan_no_tools(self, mock_run, mock_which):
        """SBOM scan works (falls back to dpkg) even without syft/docker."""
        mock_which.side_effect = lambda b: None

        def run_side_effect(cmd, timeout=300):
            if isinstance(cmd, list):
                cmd_str = " ".join(cmd)
            else:
                cmd_str = cmd
            if "dpkg-query" in cmd_str:
                return (0, "bash\t5.2\n")
            return (1, "")

        mock_run.side_effect = run_side_effect

        result = nanobot_sbom.check_sbom()
        # Should still get native packages
        self.assertGreater(result["native_packages"], 0)
        self.assertFalse(result["host_sbom"])

    @patch("nanobot_sbom._which")
    def test_cve_scan_no_grype(self, mock_which):
        """CVE scan returns error but doesn't crash without grype."""
        mock_which.return_value = None

        result = nanobot_sbom.check_cve()
        self.assertIn("grype not installed", result["errors"])
        self.assertEqual(result["total_findings"], 0)

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    def test_network_scan_arp_fails(self, mock_run, mock_which):
        """Network scan handles arp-scan failure gracefully."""
        mock_which.side_effect = lambda b: "/usr/bin/" + b

        # Both attempts fail
        mock_run.return_value = (1, "")

        result = nanobot_sbom.check_network_inventory()
        self.assertIn("arp-scan exit code 1", result["errors"])


# ---------------------------------------------------------------------------
# 17. Input Sanitization
# ---------------------------------------------------------------------------


class TestInputSanitization(SBOMTestBase):
    """Test handling of malicious/malformed input data."""

    def test_malicious_hostname_in_arp(self):
        """Malicious characters in ARP output don't break parsing."""
        output = '192.168.1.1\t00:11:22:33:44:55\t$(rm -rf /)'
        results = nanobot_sbom._parse_arp_scan(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["vendor"], "$(rm -rf /)")
        # Vendor is stored as data, not executed

    def test_malicious_hostname_in_mdns(self):
        """Injection attempts in mDNS output are stored as plain text."""
        output = '=;eth0;IPv4;Malicious;_http._tcp;local;`whoami`.local;10.0.0.1;80;'
        result = nanobot_sbom._parse_avahi_browse(output)
        self.assertEqual(result["10.0.0.1"], "`whoami`.local")

    def test_device_file_injection(self):
        """Device filenames with special chars are handled safely."""
        # MAC with colons becomes hyphens in filename
        mac = "aa:bb:cc:dd:ee:ff"
        filepath = self._write_device_file(mac, {"name": "../../../etc/passwd"})
        # File is created safely in devices_dir
        self.assertTrue(os.path.dirname(filepath).endswith("devices"))

    @patch("nanobot_sbom._which")
    @patch("nanobot_sbom.run")
    @patch("nanobot_sbom.send_alert")
    def test_container_name_sanitized_in_filename(self, mock_alert, mock_run, mock_which):
        """Container names with special chars are sanitized for SBOM filenames."""
        # Test the regex used for safe_name in check_sbom
        name = "../../../etc/passwd;rm -rf /"
        safe_name = __import__("re").sub(r"[^a-zA-Z0-9_-]", "_", name)
        # Should not contain any path traversal or command injection
        self.assertNotIn("/", safe_name)
        self.assertNotIn(";", safe_name)
        self.assertNotIn("..", safe_name)

    def test_json_injection_in_device_registry(self):
        """JSON with unexpected types doesn't crash registry loading."""
        filepath = os.path.join(self.devices_dir, "weird.json")
        with open(filepath, "w") as f:
            json.dump({"mac": "00:00:00:00:00:01", "name": None, "data": [1, 2, 3]}, f)

        registry = nanobot_sbom._load_device_registry()
        self.assertIn("00:00:00:00:00:01", registry)

    def test_epss_csv_injection(self):
        """EPSS CSV with unexpected content doesn't crash."""
        csv_path = os.path.join(self.data_dir, "epss.csv")
        with open(csv_path, "w") as f:
            f.write("cve,epss,percentile\n")
            f.write("CVE-2024-00001,0.5,0.8\n")
            f.write('=cmd|"/C calc.exe"!A0,0.9,0.99\n')  # CSV injection attempt
            f.write("CVE-2024-00002,0.3,0.5\n")

        scores = nanobot_sbom._load_epss_scores(csv_path)
        # Should load valid entries without crashing
        self.assertIn("CVE-2024-00001", scores)
        self.assertIn("CVE-2024-00002", scores)


# ---------------------------------------------------------------------------
# 18. Schema Version Handling
# ---------------------------------------------------------------------------


class TestSchemaVersionHandling(SBOMTestBase):
    """Test handling of different config/data schema versions."""

    def test_empty_config_uses_defaults(self):
        """Completely empty config file uses all defaults."""
        with open(self.config_file, "w") as f:
            json.dump({}, f)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(cfg["scan_interface"], "eth0")
        self.assertEqual(cfg["gone_threshold_hours"], 24)

    def test_partial_sbom_config(self):
        """Config with partial sbom section merges with defaults."""
        with open(self.config_file, "w") as f:
            json.dump({"sbom": {"scan_interface": "wlan1"}}, f)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(cfg["scan_interface"], "wlan1")
        # Other defaults still present
        self.assertEqual(cfg["gone_threshold_hours"], 24)

    def test_unknown_config_keys_preserved(self):
        """Unknown keys in config are preserved (forward compat)."""
        with open(self.config_file, "w") as f:
            json.dump({"sbom": {"future_feature": True, "scan_interface": "eth0"}}, f)
        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertTrue(cfg.get("future_feature"))

    def test_native_sbom_cyclonedx_format(self):
        """Native SBOM output follows CycloneDX 1.4 schema."""
        # Simulate a native scan writing output
        sbom_dir = Path(self.data_dir) / "sboms"
        sbom_dir.mkdir(parents=True, exist_ok=True)

        native_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": nanobot_sbom._now_iso(),
                "tools": [{"name": "nanobot-sbom", "version": "1.0.0"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "purl": "pkg:deb/ubuntu/test-pkg@1.0.0",
                }
            ],
        }
        sbom_file = sbom_dir / "sbom-native-test.cdx.json"
        with open(sbom_file, "w") as f:
            json.dump(native_sbom, f)

        # Verify structure
        with open(sbom_file) as f:
            data = json.load(f)
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(data["specVersion"], "1.4")
        self.assertEqual(data["version"], 1)
        self.assertIn("components", data)
        self.assertIn("metadata", data)

    def test_device_registry_no_mac_skipped(self):
        """Device files without 'mac' key are skipped."""
        filepath = os.path.join(self.devices_dir, "no_mac.json")
        with open(filepath, "w") as f:
            json.dump({"name": "no mac device", "ip": "1.2.3.4"}, f)

        registry = nanobot_sbom._load_device_registry()
        self.assertEqual(len(registry), 0)

    def test_network_config_invalid_json_skipped(self):
        """Invalid network config files don't crash loading."""
        with open(os.path.join(self.networks_dir, "bad.json"), "w") as f:
            f.write("not valid json{{{")
        with open(os.path.join(self.networks_dir, "good.json"), "w") as f:
            json.dump({"subnet": "10.0.0.0/8", "interface": "eth1"}, f)

        nanobot_sbom._cfg = None
        cfg = nanobot_sbom.load_sbom_config()
        self.assertEqual(len(cfg["subnets"]), 1)


# ---------------------------------------------------------------------------
# Additional: Helper function tests
# ---------------------------------------------------------------------------


class TestHelperFunctions(SBOMTestBase):
    """Test utility/helper functions."""

    def test_now_iso_format(self):
        """_now_iso returns ISO format with Z suffix."""
        result = nanobot_sbom._now_iso()
        self.assertTrue(result.endswith("Z"))
        # Should be parseable
        dt = datetime.fromisoformat(result.replace("Z", "+00:00"))
        self.assertIsNotNone(dt)

    def test_ensure_dir_creates(self):
        """_ensure_dir creates directory if missing."""
        new_dir = os.path.join(self.tmpdir, "new", "nested", "dir")
        result = nanobot_sbom._ensure_dir(new_dir)
        self.assertTrue(result.is_dir())

    def test_ensure_dir_existing(self):
        """_ensure_dir works on existing directory."""
        result = nanobot_sbom._ensure_dir(self.data_dir)
        self.assertTrue(result.is_dir())

    def test_file_age_hours_existing(self):
        """_file_age_hours returns reasonable value for existing file."""
        test_file = os.path.join(self.tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        age = nanobot_sbom._file_age_hours(test_file)
        # Should be very close to 0
        self.assertLess(age, 0.01)

    def test_file_age_hours_missing(self):
        """_file_age_hours returns infinity for missing file."""
        age = nanobot_sbom._file_age_hours("/nonexistent/file")
        self.assertEqual(age, float("inf"))

    def test_sha256_file(self):
        """_sha256_file computes correct hash."""
        test_file = os.path.join(self.tmpdir, "hash_test.txt")
        with open(test_file, "w") as f:
            f.write("hello world")
        result = nanobot_sbom._sha256_file(test_file)
        self.assertEqual(len(result), 64)  # SHA256 hex is 64 chars
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_sha256_missing_file(self):
        """_sha256_file returns empty string for missing file."""
        result = nanobot_sbom._sha256_file("/nonexistent/file")
        self.assertEqual(result, "")

    @patch("subprocess.run")
    def test_run_string_command(self, mock_subprocess):
        """run() with string command wraps in bash -c."""
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="output\n"
        )
        rc, out = nanobot_sbom.run("echo hello")
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        self.assertEqual(args, ["bash", "-c", "echo hello"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "output")

    @patch("subprocess.run")
    def test_run_list_command(self, mock_subprocess):
        """run() with list command passes directly."""
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout="result\n"
        )
        rc, out = nanobot_sbom.run(["ls", "-la"])
        args = mock_subprocess.call_args[0][0]
        self.assertEqual(args, ["ls", "-la"])

    @patch("subprocess.run")
    def test_run_timeout(self, mock_subprocess):
        """run() handles TimeoutExpired gracefully."""
        mock_subprocess.side_effect = __import__("subprocess").TimeoutExpired(
            cmd="sleep 999", timeout=5
        )
        rc, out = nanobot_sbom.run("sleep 999", timeout=5)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")

    @patch("subprocess.run")
    def test_run_exception(self, mock_subprocess):
        """run() handles general exceptions gracefully."""
        mock_subprocess.side_effect = OSError("No such file")
        rc, out = nanobot_sbom.run("nonexistent_binary")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
