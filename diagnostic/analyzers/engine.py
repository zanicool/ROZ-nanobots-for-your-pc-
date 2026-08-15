"""Analysis engine — orchestrates all analyzers.

The engine discovers and runs all registered analyzers against a
SystemSnapshot, then collects and sorts findings by severity and
confidence. It is the single entry point for the analysis phase.
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseAnalyzer
from .cpu import CpuFrequencyAnalyzer, CpuHogAnalyzer
from .drivers import DisplayLinkAnalyzer, DriverAnalyzer
from .gpu import CompositorAnalyzer, GpuAccelerationAnalyzer
from .memory import MemoryLeakAnalyzer, MemoryPressureAnalyzer
from .network import NetworkLatencyAnalyzer
from .power import PowerProfileAnalyzer
from .processes import BackgroundLoadAnalyzer, MalwareAnalyzer, ZombieProcessAnalyzer
from .storage import IoPressureAnalyzer, StorageCapacityAnalyzer, StorageHealthAnalyzer
from .suitability import SuitabilityAnalyzer
from .system import FilesystemAnalyzer, FirmwareAnalyzer, VirtualizationAnalyzer
from .thermal import ThermalAnalyzer
from .usb import UsbLoadAnalyzer


class AnalysisEngine:
    """Runs all analyzers and produces a sorted list of findings.

    The engine owns the analyzer registry. To add a new cause of
    slowness, create a new BaseAnalyzer subclass and register it here.
    """

    def __init__(self) -> None:
        """Initialize with all known analyzers."""
        self._analyzers: list[BaseAnalyzer] = self._build_registry()

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Run all analyzers and return findings sorted by impact.

        Findings are sorted by: severity (critical first), then
        confidence (highest first within same severity).

        Args:
            snapshot: Complete system state from collectors.

        Returns:
            Sorted list of all findings across all analyzers.
        """
        findings: list[Finding] = []

        for analyzer in self._analyzers:
            try:
                results = analyzer.analyze(snapshot)
                findings.extend(results)
            except NotImplementedError:
                # Analyzer stub not yet implemented — skip silently
                pass
            except Exception as exc:  # noqa: BLE001
                # Analyzer crashed — don't let one failure kill the run.
                # TODO: replace with proper logging
                _ = exc

        return self._sort_findings(findings)

    @property
    def analyzer_count(self) -> int:
        """Number of registered analyzers."""
        return len(self._analyzers)

    @property
    def analyzer_names(self) -> list[str]:
        """Names of all registered analyzers (for --verbose output)."""
        return [a.name for a in self._analyzers]

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _build_registry(self) -> list[BaseAnalyzer]:
        """Instantiate all analyzers in priority order.

        Order here determines evaluation order but NOT output order
        (findings are sorted by severity/confidence after the fact).
        """
        return [
            # High-impact causes first (more likely to be "the answer")
            CpuHogAnalyzer(),
            IoPressureAnalyzer(),
            ThermalAnalyzer(),
            MemoryPressureAnalyzer(),
            GpuAccelerationAnalyzer(),
            CpuFrequencyAnalyzer(),
            PowerProfileAnalyzer(),
            StorageCapacityAnalyzer(),
            StorageHealthAnalyzer(),
            BackgroundLoadAnalyzer(),
            MemoryLeakAnalyzer(),
            DriverAnalyzer(),
            DisplayLinkAnalyzer(),
            CompositorAnalyzer(),
            NetworkLatencyAnalyzer(),
            FilesystemAnalyzer(),
            VirtualizationAnalyzer(),
            ZombieProcessAnalyzer(),
            MalwareAnalyzer(),
            FirmwareAnalyzer(),
            UsbLoadAnalyzer(),
            # Positive guidance — "what is this system good for?"
            SuitabilityAnalyzer(),
        ]

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings: critical first, then by confidence descending."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.WARNING: 1,
            Severity.INFO: 2,
        }
        return sorted(
            findings,
            key=lambda f: (severity_order[f.severity], -f.confidence),
        )
