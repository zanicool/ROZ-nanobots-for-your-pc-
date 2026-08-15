"""Shared data models for the diagnostic toolkit.

All modules communicate through these types. Collectors produce a
SystemSnapshot; analyzers consume it and produce Findings; reporters
format Findings for output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """How likely a finding is to be causing perceived slowness.

    CRITICAL — almost certainly the cause, user will notice immediately.
    WARNING  — contributing factor, may compound with other issues.
    INFO     — worth noting, unlikely to be the sole cause.
    """

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.CRITICAL, Severity.WARNING, Severity.INFO]
        return order.index(self) < order.index(other)


@dataclass(frozen=True)
class Finding:
    """A single diagnostic finding — one probable cause of slowness.

    Attributes:
        cause:       Short title, e.g. "Thermal throttling detected".
        severity:    How impactful this finding is.
        evidence:    Raw data supporting the conclusion.
        explanation: Human-readable story of what is happening and why
                     it causes slowness.
        suggestion:  Actionable fix the user can apply.
        category:    Grouping key (e.g. "thermal", "gpu", "memory").
        confidence:  0.0–1.0 indicating certainty of the diagnosis.
    """

    cause: str
    severity: Severity
    evidence: str
    explanation: str
    suggestion: str
    category: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON export."""
        return {
            "cause": self.cause,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "suggestion": self.suggestion,
            "category": self.category,
            "confidence": self.confidence,
        }


@dataclass
class SystemSnapshot:
    """Complete system state captured by all collectors.

    This is the single data structure that flows from the collection
    phase into the analysis phase.  Analyzers must not call collectors
    directly — they operate solely on this snapshot.

    Attributes:
        hardware:   Static hardware information (CPU model, GPU, disks, RAM).
        monitor:    Live monitoring data (temps, top processes, memory state).
        benchmark:  Benchmark results or {"skipped": True} in quick mode.
        network:    Network diagnostics (latency, DNS, packet loss).
        timestamp:  ISO-8601 timestamp of when the snapshot was taken.
    """

    hardware: dict[str, Any] = field(default_factory=dict)
    monitor: dict[str, Any] = field(default_factory=dict)
    benchmark: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire snapshot for JSON export."""
        return {
            "hardware": self.hardware,
            "monitor": self.monitor,
            "benchmark": self.benchmark,
            "network": self.network,
            "timestamp": self.timestamp,
        }
