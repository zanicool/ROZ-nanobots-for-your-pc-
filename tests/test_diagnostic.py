"""Unit tests for the diagnostic toolkit.

Tests cover:
- Model instantiation and serialization
- Collector base class helpers
- Analysis engine orchestration
- Report generator dispatch
- CLI argument parsing
- Suitability profiles completeness
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from diagnostic.analyzers.base import BaseAnalyzer
from diagnostic.analyzers.engine import AnalysisEngine
from diagnostic.analyzers.suitability import (
    USE_CASE_PROFILES,
    CpuPreference,
    StoragePreference,
)
from diagnostic.collectors.base import BaseCollector
from diagnostic.models import Finding, Severity, SystemSnapshot
from diagnostic.reports.generator import ReportGenerator

# =============================================================================
# Model Tests
# =============================================================================


class TestSeverity:
    """Tests for the Severity enum."""

    def test_ordering(self):
        """CRITICAL < WARNING < INFO (for sorting purposes)."""
        assert Severity.CRITICAL < Severity.WARNING
        assert Severity.WARNING < Severity.INFO

    def test_values(self):
        """Severity values are lowercase strings."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"


class TestFinding:
    """Tests for the Finding dataclass."""

    def _make_finding(self, **kwargs):
        """Helper to create a Finding with defaults."""
        defaults = {
            "cause": "Test cause",
            "severity": Severity.WARNING,
            "evidence": "Test evidence",
            "explanation": "Test explanation",
            "suggestion": "Test suggestion",
            "category": "test",
            "confidence": 0.85,
        }
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_creation(self):
        """Finding can be created with all required fields."""
        f = self._make_finding()
        assert f.cause == "Test cause"
        assert f.confidence == 0.85

    def test_immutable(self):
        """Finding is frozen — attributes cannot be changed."""
        f = self._make_finding()
        try:
            f.cause = "changed"  # type: ignore
            assert False, "Should have raised FrozenInstanceError"
        except (AttributeError, TypeError):
            pass

    def test_to_dict(self):
        """Finding serializes to dict correctly."""
        f = self._make_finding()
        d = f.to_dict()
        assert d["cause"] == "Test cause"
        assert d["severity"] == "warning"
        assert d["confidence"] == 0.85
        assert isinstance(d, dict)

    def test_to_dict_json_serializable(self):
        """to_dict() output is JSON-serializable."""
        f = self._make_finding()
        # Should not raise
        json.dumps(f.to_dict())


class TestSystemSnapshot:
    """Tests for the SystemSnapshot dataclass."""

    def test_default_creation(self):
        """Snapshot can be created with no arguments."""
        s = SystemSnapshot()
        assert s.hardware == {}
        assert s.monitor == {}
        assert s.benchmark == {}
        assert s.network == {}
        assert s.timestamp == ""

    def test_to_dict(self):
        """Snapshot serializes all fields."""
        s = SystemSnapshot(
            hardware={"cpu": "test"},
            timestamp="2024-01-01T00:00:00Z",
        )
        d = s.to_dict()
        assert d["hardware"]["cpu"] == "test"
        assert d["timestamp"] == "2024-01-01T00:00:00Z"

    def test_to_dict_json_serializable(self):
        """to_dict() output is JSON-serializable."""
        s = SystemSnapshot(hardware={"nested": {"deep": [1, 2, 3]}})
        json.dumps(s.to_dict())


# =============================================================================
# Collector Base Tests
# =============================================================================


class ConcreteCollector(BaseCollector):
    """Test implementation of BaseCollector."""

    def collect(self):
        return {"test": True}


class TestBaseCollector:
    """Tests for BaseCollector helper methods."""

    def test_has_tool_existing(self):
        """_has_tool returns True for a tool that exists."""
        c = ConcreteCollector()
        # 'python3' should exist on any system running these tests
        assert c._has_tool("python3") is True

    def test_has_tool_missing(self):
        """_has_tool returns False for a nonexistent tool."""
        c = ConcreteCollector()
        assert c._has_tool("nonexistent_tool_xyz_12345") is False

    def test_run_cmd_success(self):
        """_run_cmd returns stdout for successful commands."""
        c = ConcreteCollector()
        result = c._run_cmd(["echo", "hello"])
        assert result == "hello"

    def test_run_cmd_failure(self):
        """_run_cmd returns None for failed commands."""
        c = ConcreteCollector()
        result = c._run_cmd(["false"])
        assert result is None

    def test_run_cmd_nonexistent(self):
        """_run_cmd returns None for missing executables."""
        c = ConcreteCollector()
        result = c._run_cmd(["nonexistent_binary_xyz"])
        assert result is None

    def test_run_cmd_timeout(self):
        """_run_cmd returns None on timeout."""
        c = ConcreteCollector()
        result = c._run_cmd(["sleep", "10"], timeout=1)
        assert result is None

    def test_read_file_success(self):
        """_read_file reads existing files."""
        c = ConcreteCollector()
        result = c._read_file("/proc/loadavg")
        assert result is not None
        assert len(result) > 0

    def test_read_file_missing(self):
        """_read_file returns None for missing files."""
        c = ConcreteCollector()
        result = c._read_file("/nonexistent/file/path")
        assert result is None

    def test_read_int_success(self):
        """_read_int parses integer files."""
        c = ConcreteCollector()
        # /proc/self/loginuid should be readable
        # Use a file we know contains an int-like value
        with patch("builtins.open", MagicMock(
            return_value=MagicMock(
                __enter__=lambda s: s,
                __exit__=lambda *a: None,
                read=lambda: "42\n",
            )
        )):
            result = c._read_int("/fake/int/file")
            assert result == 42

    def test_read_int_non_numeric(self):
        """_read_int returns None for non-numeric content."""
        c = ConcreteCollector()
        result = c._read_int("/proc/loadavg")  # Contains floats, not int
        assert result is None


# =============================================================================
# Analysis Engine Tests
# =============================================================================


class TestAnalysisEngine:
    """Tests for the AnalysisEngine orchestrator."""

    def test_creation(self):
        """Engine creates with all analyzers registered."""
        engine = AnalysisEngine()
        assert engine.analyzer_count >= 20  # At least 20 causes

    def test_analyzer_names(self):
        """All analyzers have unique names."""
        engine = AnalysisEngine()
        names = engine.analyzer_names
        assert len(names) == len(set(names)), "Duplicate analyzer names"

    def test_analyze_empty_snapshot(self):
        """Analyzing an empty snapshot returns 0 findings (all stubs)."""
        engine = AnalysisEngine()
        snapshot = SystemSnapshot()
        findings = engine.analyze(snapshot)
        assert findings == []

    def test_analyze_returns_list(self):
        """analyze() always returns a list, never None."""
        engine = AnalysisEngine()
        result = engine.analyze(SystemSnapshot())
        assert isinstance(result, list)

    def test_findings_sorted_by_severity(self):
        """Findings should be sorted: critical first, then warning, then info."""
        engine = AnalysisEngine()

        # Create a mock analyzer that returns mixed-severity findings
        class MockAnalyzer(BaseAnalyzer):
            @property
            def name(self):
                return "Mock"

            @property
            def category(self):
                return "test"

            def analyze(self, snapshot):
                return [
                    Finding(
                        cause="Info thing",
                        severity=Severity.INFO,
                        evidence="e", explanation="x",
                        suggestion="s", category="test",
                        confidence=0.9,
                    ),
                    Finding(
                        cause="Critical thing",
                        severity=Severity.CRITICAL,
                        evidence="e", explanation="x",
                        suggestion="s", category="test",
                        confidence=0.5,
                    ),
                    Finding(
                        cause="Warning thing",
                        severity=Severity.WARNING,
                        evidence="e", explanation="x",
                        suggestion="s", category="test",
                        confidence=0.7,
                    ),
                ]

        # Inject mock analyzer
        engine._analyzers = [MockAnalyzer()]
        findings = engine.analyze(SystemSnapshot())

        assert len(findings) == 3
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.WARNING
        assert findings[2].severity == Severity.INFO

    def test_analyzer_crash_does_not_kill_engine(self):
        """If one analyzer throws, the others still run."""
        engine = AnalysisEngine()

        class CrashAnalyzer(BaseAnalyzer):
            @property
            def name(self):
                return "Crash"

            @property
            def category(self):
                return "test"

            def analyze(self, snapshot):
                raise RuntimeError("boom")

        class GoodAnalyzer(BaseAnalyzer):
            @property
            def name(self):
                return "Good"

            @property
            def category(self):
                return "test"

            def analyze(self, snapshot):
                return [Finding(
                    cause="Found it",
                    severity=Severity.INFO,
                    evidence="e", explanation="x",
                    suggestion="s", category="test",
                    confidence=0.5,
                )]

        engine._analyzers = [CrashAnalyzer(), GoodAnalyzer()]
        findings = engine.analyze(SystemSnapshot())
        assert len(findings) == 1
        assert findings[0].cause == "Found it"


# =============================================================================
# Report Generator Tests
# =============================================================================


class TestReportGenerator:
    """Tests for the ReportGenerator facade."""

    def test_available_formats(self):
        """All expected formats are registered."""
        gen = ReportGenerator()
        formats = gen.available_formats
        assert "terminal" in formats
        assert "markdown" in formats
        assert "json" in formats
        assert "ai" in formats

    def test_unknown_format_raises(self):
        """Requesting an unknown format raises ValueError."""
        gen = ReportGenerator()
        try:
            gen.generate(
                collected={},
                findings=[],
                output_format="nonexistent",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "nonexistent" in str(e)

    def test_generate_with_stubs_raises_not_implemented(self):
        """Unimplemented formatters raise NotImplementedError (markdown, json, ai)."""
        gen = ReportGenerator()
        # Terminal formatter is now implemented, but others are still stubs
        for fmt in ["markdown", "json", "ai"]:
            try:
                gen.generate(
                    collected={"hardware": {}, "monitor": {}, "benchmark": {}, "network": {}},
                    findings=[],
                    output_format=fmt,
                )
                assert False, f"Format '{fmt}' should have raised NotImplementedError"
            except NotImplementedError:
                pass  # Expected — formatter is still a stub

    def test_terminal_format_works(self):
        """Terminal formatter produces output without crashing."""
        gen = ReportGenerator()
        report = gen.generate(
            collected={"hardware": {}, "monitor": {}, "benchmark": {}, "network": {}},
            findings=[],
            output_format="terminal",
        )
        assert isinstance(report, str)
        assert "No issues detected" in report


# =============================================================================
# Suitability Profiles Tests
# =============================================================================


class TestUseCaseProfiles:
    """Tests for the use-case profile registry."""

    def test_has_20_profiles(self):
        """Registry should contain exactly 20 use-case profiles."""
        assert len(USE_CASE_PROFILES) == 20

    def test_all_profiles_have_names(self):
        """Every profile has a non-empty name."""
        for p in USE_CASE_PROFILES:
            assert len(p.name) > 0, f"Profile missing name: {p}"

    def test_all_profiles_have_descriptions(self):
        """Every profile has a non-empty description."""
        for p in USE_CASE_PROFILES:
            assert len(p.description) > 0, f"Profile missing description: {p.name}"

    def test_unique_names(self):
        """All profile names are unique."""
        names = [p.name for p in USE_CASE_PROFILES]
        assert len(names) == len(set(names)), "Duplicate profile names"

    def test_ram_thresholds_logical(self):
        """ideal_ram >= min_ram for all profiles."""
        for p in USE_CASE_PROFILES:
            assert p.ideal_ram_gb >= p.min_ram_gb, (
                f"{p.name}: ideal_ram ({p.ideal_ram_gb}) < min_ram ({p.min_ram_gb})"
            )

    def test_core_thresholds_logical(self):
        """ideal_cores >= min_cores for all profiles."""
        for p in USE_CASE_PROFILES:
            assert p.ideal_cores >= p.min_cores, (
                f"{p.name}: ideal_cores ({p.ideal_cores}) < min_cores ({p.min_cores})"
            )

    def test_gpu_vram_thresholds_logical(self):
        """ideal_gpu_vram >= min_gpu_vram for all profiles."""
        for p in USE_CASE_PROFILES:
            assert p.ideal_gpu_vram_gb >= p.min_gpu_vram_gb, (
                f"{p.name}: ideal_vram ({p.ideal_gpu_vram_gb}) < min_vram ({p.min_gpu_vram_gb})"
            )

    def test_profiles_are_frozen(self):
        """Profiles are immutable (frozen dataclass)."""
        p = USE_CASE_PROFILES[0]
        try:
            p.name = "changed"  # type: ignore
            assert False, "Should have raised FrozenInstanceError"
        except (AttributeError, TypeError):
            pass

    def test_cpu_preference_values(self):
        """All profiles have valid CpuPreference."""
        for p in USE_CASE_PROFILES:
            assert isinstance(p.cpu_preference, CpuPreference)

    def test_storage_preference_values(self):
        """All profiles have valid StoragePreference."""
        for p in USE_CASE_PROFILES:
            assert isinstance(p.storage_preference, StoragePreference)


# =============================================================================
# CLI Tests (argument parsing only, no execution)
# =============================================================================


class TestCliArgs:
    """Tests for CLI argument parsing."""

    def test_default_args(self):
        """Default arguments are correct."""
        from diagnostic.cli import _parse_args

        with patch("sys.argv", ["diagnostic"]):
            args = _parse_args()
            assert args.quick is False
            assert args.format == "terminal"
            assert args.output is None
            assert args.compare is None
            assert args.verbose is False

    def test_quick_flag(self):
        """--quick flag is parsed."""
        from diagnostic.cli import _parse_args

        with patch("sys.argv", ["diagnostic", "--quick"]):
            args = _parse_args()
            assert args.quick is True

    def test_format_options(self):
        """All format options are accepted."""
        from diagnostic.cli import _parse_args

        for fmt in ["json", "markdown", "ai", "terminal"]:
            with patch("sys.argv", ["diagnostic", "--format", fmt]):
                args = _parse_args()
                assert args.format == fmt

    def test_output_path(self):
        """-o flag captures the output path."""
        from diagnostic.cli import _parse_args

        with patch("sys.argv", ["diagnostic", "-o", "/tmp/report.json"]):
            args = _parse_args()
            assert args.output == "/tmp/report.json"

    def test_compare_path(self):
        """--compare captures the path."""
        from diagnostic.cli import _parse_args

        with patch("sys.argv", ["diagnostic", "--compare", "old.json"]):
            args = _parse_args()
            assert args.compare == "old.json"


# =============================================================================
# Integration Test — full pipeline with stubs
# =============================================================================


class TestIntegration:
    """End-to-end tests that exercise the full pipeline."""

    def test_full_pipeline_with_stubs(self):
        """The full pipeline runs without crashing with real collectors."""
        from diagnostic.cli import _analyze, _collect

        # Suppress print output
        with patch("builtins.print"):
            collected = _collect(quick=True)

        assert "hardware" in collected
        assert "monitor" in collected
        assert "network" in collected
        assert "benchmark" in collected
        assert "timestamp" in collected

        with patch("builtins.print"):
            findings = _analyze(collected)

        assert isinstance(findings, list)
        # Real analyzers may produce findings on any machine
        for f in findings:
            assert isinstance(f, Finding)
