"""Unit tests for ROZ NanoBots."""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

# Add project root to path so we can import nanobot
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patch config file before import to avoid reading system config
with patch("builtins.open", side_effect=FileNotFoundError):
    import nanobot


# =============================================================================
# Test Config Loading
# =============================================================================


class TestLoadConfig:
    """Tests for the config loading system."""

    def test_default_config_loads(self):
        """Default config should have all expected keys."""
        assert "interval" in nanobot.DEFAULT_CONFIG
        assert "realtime_interval" in nanobot.DEFAULT_CONFIG
        assert "quiet_mode" in nanobot.DEFAULT_CONFIG
        assert "allowed_ports" in nanobot.DEFAULT_CONFIG
        assert "allowed_root_processes" in nanobot.DEFAULT_CONFIG

    def test_load_config_missing_file(self):
        """load_config should return defaults when file doesn't exist."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            cfg = nanobot.load_config()
        assert cfg["interval"] == 3600
        assert cfg["quiet_mode"] is False

    def test_load_config_invalid_json(self):
        """load_config should return defaults on invalid JSON."""
        with patch("builtins.open", mock_open(read_data="not json {")):
            cfg = nanobot.load_config()
        assert cfg["interval"] == 3600

    def test_load_config_overrides(self):
        """User config should override defaults."""
        user_cfg = json.dumps({"interval": 7200, "quiet_mode": True})
        with patch("builtins.open", mock_open(read_data=user_cfg)):
            cfg = nanobot.load_config()
        assert cfg["interval"] == 7200
        assert cfg["quiet_mode"] is True
        # Non-overridden defaults still present
        assert cfg["realtime_interval"] == 30


# =============================================================================
# Test Quiet Mode (#10)
# =============================================================================


class TestQuietMode:
    """Tests for the quiet/silent mode feature."""

    def test_log_ok_logs_when_not_quiet(self):
        """log_ok should log when quiet_mode is False."""
        nanobot.cfg["quiet_mode"] = False
        with patch.object(nanobot.log, "info") as mock_info:
            nanobot.log_ok("test message")
            mock_info.assert_called_once_with("test message")

    def test_log_ok_silent_when_quiet(self):
        """log_ok should not log when quiet_mode is True."""
        nanobot.cfg["quiet_mode"] = True
        with patch.object(nanobot.log, "info") as mock_info:
            nanobot.log_ok("test message")
            mock_info.assert_not_called()
        # Reset
        nanobot.cfg["quiet_mode"] = False


# =============================================================================
# Test Journal Summary (#9)
# =============================================================================


class TestLogJournalSummary:
    """Tests for the journal error grouping feature."""

    def test_groups_by_source(self):
        """Should group journal lines by source unit."""
        output = (
            "Jul 04 10:00:00 myhost NetworkManager[123]: connection failed\n"
            "Jul 04 10:00:01 myhost NetworkManager[123]: retrying\n"
            "Jul 04 10:00:02 myhost sshd[456]: auth failure\n"
            "Jul 04 10:00:03 myhost NetworkManager[123]: still failing\n"
        )
        with patch.object(nanobot.log, "warning") as mock_warn:
            nanobot.log_journal_summary(output, top_n=5)
        # NetworkManager should appear first (3 occurrences)
        calls = [str(c) for c in mock_warn.call_args_list]
        assert any("3x" in c and "NetworkManager" in c for c in calls)
        assert any("1x" in c and "sshd" in c for c in calls)

    def test_top_n_limits_output(self):
        """Should only show top_n sources."""
        lines = []
        for i in range(10):
            lines.append(f"Jul 04 10:00:00 host source{i}[1]: msg")
        output = "\n".join(lines)
        with patch.object(nanobot.log, "warning") as mock_warn:
            nanobot.log_journal_summary(output, top_n=3)
        assert mock_warn.call_count == 3

    def test_empty_output(self):
        """Should handle empty output gracefully."""
        with patch.object(nanobot.log, "warning") as mock_warn:
            nanobot.log_journal_summary("", top_n=5)
        mock_warn.assert_not_called()


# =============================================================================
# Test Open Ports Check (#7)
# =============================================================================


class TestCheckOpenPorts:
    """Tests for the open port allowlist feature."""

    def test_flags_unexpected_port(self):
        """Should warn about ports not in allowlist."""
        nanobot.cfg["allowed_ports"] = [22, 53, 631]
        ss_output = "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"nginx\",pid=1234,fd=6))"
        with patch("nanobot.run", return_value=(0, ss_output)):
            with patch.object(nanobot.log, "warning") as mock_warn:
                with patch("nanobot.track"):
                    nanobot.check_open_ports()
        assert mock_warn.called
        assert any("8080" in str(c) for c in mock_warn.call_args_list)

    def test_allows_expected_port(self):
        """Should not warn about ports in allowlist."""
        nanobot.cfg["allowed_ports"] = [22, 53, 631]
        ss_output = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1234,fd=3))"
        with patch("nanobot.run", return_value=(0, ss_output)):
            with patch.object(nanobot.log, "warning") as mock_warn:
                nanobot.check_open_ports()
        # Should NOT have warned about port 22
        for call in mock_warn.call_args_list:
            assert "Unexpected open port: 22" not in str(call)

    def test_skips_on_empty_output(self):
        """Should not crash on empty ss output."""
        with patch("nanobot.run", return_value=(0, "")):
            nanobot.check_open_ports()  # Should not raise


# =============================================================================
# Test Root Process Check
# =============================================================================


class TestCheckRootProcesses:
    """Tests for the root process allowlist feature."""

    def test_flags_unexpected_root_process(self):
        """Should warn about processes not in allowlist."""
        nanobot.cfg["allowed_root_processes"] = ["systemd", "sshd", "cron"]
        ps_output = (
            "root      1 systemd\n"
            "root    100 sshd\n"
            "root    200 malware_bot\n"
            "zani    300 firefox\n"
        )
        with patch("nanobot.run", return_value=(0, ps_output)):
            with patch.object(nanobot.log, "warning") as mock_warn:
                with patch("nanobot.track"):
                    nanobot.check_root_processes()
        assert any("malware_bot" in str(c) for c in mock_warn.call_args_list)

    def test_ignores_kernel_threads(self):
        """Should skip kernel threads in brackets."""
        nanobot.cfg["allowed_root_processes"] = ["systemd"]
        ps_output = (
            "root      1 systemd\n"
            "root      2 [kthreadd]\n"
            "root      3 [rcu_gp]\n"
        )
        with patch("nanobot.run", return_value=(0, ps_output)):
            with patch.object(nanobot.log, "warning") as mock_warn:
                with patch("nanobot.track"):
                    nanobot.check_root_processes()
        # Should not warn about kernel threads
        for call in mock_warn.call_args_list:
            assert "kthreadd" not in str(call)
            assert "rcu_gp" not in str(call)

    def test_ignores_non_root(self):
        """Should not check processes not running as root."""
        nanobot.cfg["allowed_root_processes"] = ["systemd"]
        ps_output = "zani    500 suspicious_app\n"
        with patch("nanobot.run", return_value=(0, ps_output)):
            with patch.object(nanobot.log, "warning") as mock_warn:
                nanobot.check_root_processes()
        mock_warn.assert_not_called()


# =============================================================================
# Test Pre-commit Hook (#5)
# =============================================================================


class TestPreCommitHook:
    """Tests for the branch protection pre-commit hook."""

    def test_hook_exists(self):
        """Pre-commit hook file should exist."""
        hook_path = Path(__file__).parent.parent / "hooks" / "pre-commit"
        assert hook_path.exists()

    def test_hook_blocks_main(self):
        """Hook should contain logic to block commits on main."""
        hook_path = Path(__file__).parent.parent / "hooks" / "pre-commit"
        content = hook_path.read_text()
        assert "main" in content
        assert "exit 1" in content

    def test_hook_is_executable(self):
        """Hook should be executable."""
        hook_path = Path(__file__).parent.parent / "hooks" / "pre-commit"
        assert os.access(hook_path, os.X_OK)


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestHelpers:
    """Tests for utility functions."""

    def test_load_stats_creates_defaults(self):
        """load_stats should return a valid stats dict."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            stats = nanobot.load_stats()
        assert "cycles" in stats
        assert "first_run" in stats

    def test_track_increments_counter(self):
        """track() should increment the named counter in stats."""
        nanobot.stats = {"test_counter": 5}
        nanobot.track("test_counter")
        assert nanobot.stats["test_counter"] == 6

    def test_track_creates_counter(self):
        """track() should create counter if it doesn't exist."""
        nanobot.stats = {}
        nanobot.track("new_counter")
        assert nanobot.stats["new_counter"] == 1
