"""Memory-related analyzers.

Detects:
- System under memory pressure (heavy swap usage, low available RAM)
- Memory leaks in individual applications (disproportionate RSS)
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseAnalyzer


class MemoryPressureAnalyzer(BaseAnalyzer):
    """Detect system-wide memory pressure."""

    _CRITICAL_AVAILABLE_MB = 500
    _WARNING_SWAP_USED_PCT = 50.0

    @property
    def name(self) -> str:
        return "Memory Pressure"

    @property
    def category(self) -> str:
        return "memory"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check available RAM, swap usage, and PSI memory metrics."""
        memory = snapshot.monitor.get("memory", {})
        if not memory:
            return []

        available_mb = memory.get("available_mb", 9999)
        swap_used_pct = memory.get("swap_used_pct", 0)
        swap_used_mb = memory.get("swap_used_mb", 0)
        total_mb = memory.get("total_mb", 1)
        used_pct = memory.get("used_pct", 0)

        findings: list[Finding] = []

        # Critical: very low available RAM
        if available_mb < self._CRITICAL_AVAILABLE_MB:
            findings.append(Finding(
                cause=f"Critically low RAM: only {available_mb} MB available",
                severity=Severity.CRITICAL,
                evidence=(
                    f"Available: {available_mb} MB out of {total_mb} MB total "
                    f"({used_pct:.0f}% used). Swap used: {swap_used_mb} MB."
                ),
                explanation=(
                    "Your system is almost out of RAM. The kernel is aggressively "
                    "swapping memory pages to disk, which causes multi-second "
                    "freezes every time a process touches swapped data. "
                    "This is the #1 cause of 'my PC completely freezes for "
                    "seconds then comes back'."
                ),
                suggestion=(
                    "Close some applications (especially browser tabs). "
                    "Check top memory consumers: ps aux --sort=-%mem | head -10"
                ),
                category=self.category,
                confidence=0.95,
            ))

        # Warning: heavy swap usage
        elif swap_used_pct >= self._WARNING_SWAP_USED_PCT:
            findings.append(Finding(
                cause=f"Heavy swap usage: {swap_used_pct:.0f}% of swap in use",
                severity=Severity.WARNING,
                evidence=(
                    f"Swap: {swap_used_mb} MB used ({swap_used_pct:.0f}%). "
                    f"RAM: {available_mb} MB available of {total_mb} MB."
                ),
                explanation=(
                    "A significant amount of memory has been pushed to swap. "
                    "Applications accessing swapped pages will experience "
                    "noticeable delays as data is read back from disk."
                ),
                suggestion=(
                    "Reduce memory usage or add more RAM. "
                    "Check what's using memory: ps aux --sort=-%mem | head -10"
                ),
                category=self.category,
                confidence=0.7,
            ))

        return findings


class MemoryLeakAnalyzer(BaseAnalyzer):
    """Detect individual processes with suspiciously high memory usage."""

    _LEAK_THRESHOLD_FRACTION = 0.25

    @property
    def name(self) -> str:
        return "Memory Leak Detection"

    @property
    def category(self) -> str:
        return "memory"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Identify processes with RSS exceeding threshold of total RAM."""
        processes = snapshot.monitor.get("processes", {})
        by_memory = processes.get("by_memory", [])
        total_mb = snapshot.hardware.get("memory", {}).get("total_mb", 0)

        if not by_memory or total_mb == 0:
            return []

        findings: list[Finding] = []
        for proc in by_memory[:5]:  # Check top 5
            rss_mb = proc.get("rss_kb", 0) / 1024
            fraction = rss_mb / total_mb
            if fraction >= self._LEAK_THRESHOLD_FRACTION:
                cmd = proc.get("command", "unknown")[:40]
                findings.append(Finding(
                    cause=f"High memory usage: {cmd} ({rss_mb:.0f} MB)",
                    severity=Severity.WARNING,
                    evidence=(
                        f"Process '{cmd}' using {rss_mb:.0f} MB "
                        f"({fraction:.0%} of total RAM)."
                    ),
                    explanation=(
                        f"The process '{cmd}' is consuming {fraction:.0%} of your "
                        "total RAM. This could be a memory leak or simply a "
                        "demanding application. If this keeps growing over time, "
                        "it will eventually push the system into swap."
                    ),
                    suggestion=(
                        f"Monitor if it keeps growing: watch -n5 'ps -p {proc.get('pid', '?')} -o rss='. "
                        "If it grows unbounded, restart the application."
                    ),
                    category=self.category,
                    confidence=0.5,
                ))

        return findings
