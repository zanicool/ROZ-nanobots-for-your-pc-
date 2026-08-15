"""CPU-related analyzers.

Detects:
- CPU frequency stuck low (power saving / governor issue)
- Single process monopolizing CPU (the "ffmpeg eating a core" problem)
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseAnalyzer


class CpuFrequencyAnalyzer(BaseAnalyzer):
    """Detect CPU running below expected frequency."""

    _LOW_FREQ_RATIO = 0.5

    @property
    def name(self) -> str:
        return "CPU Frequency"

    @property
    def category(self) -> str:
        return "cpu"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check if CPU cores are running significantly below max clock."""
        frequencies = snapshot.monitor.get("frequencies", [])
        if not frequencies:
            return []

        # Calculate average ratio of current/max
        ratios: list[float] = []
        for core in frequencies:
            cur = core.get("current_mhz")
            max_freq = core.get("max_mhz")
            if cur and max_freq and max_freq > 0:
                ratios.append(cur / max_freq)

        if not ratios:
            return []

        avg_ratio = sum(ratios) / len(ratios)
        if avg_ratio >= self._LOW_FREQ_RATIO:
            return []

        avg_cur = sum(c.get("current_mhz", 0) for c in frequencies) / len(frequencies)
        avg_max = sum(c.get("max_mhz", 0) for c in frequencies) / len(frequencies)
        governor = frequencies[0].get("governor", "unknown")

        return [Finding(
            cause="CPU frequency significantly below maximum",
            severity=Severity.WARNING,
            evidence=(
                f"Average clock: {avg_cur:.0f} MHz vs max {avg_max:.0f} MHz "
                f"(ratio: {avg_ratio:.0%}). Governor: {governor}"
            ),
            explanation=(
                "Your CPU cores are running well below their maximum speed. "
                "This could be due to a power-saving governor, thermal limits, "
                "or a missing CPU frequency driver. Applications feel sluggish "
                "because every operation takes longer than it should."
            ),
            suggestion=(
                f"Check governor: current is '{governor}'. For performance, try: "
                "sudo cpupower frequency-set -g performance"
            ),
            category=self.category,
            confidence=min(0.9, 1.0 - avg_ratio),
        )]


class CpuHogAnalyzer(BaseAnalyzer):
    """Detect a single process monopolizing CPU time."""

    # A process using more than this % is considered a hog
    _HOG_THRESHOLD_PCT = 80.0
    # Load average above this per-core is high
    _HIGH_LOAD_PER_CORE = 1.0

    @property
    def name(self) -> str:
        return "CPU Hog Detection"

    @property
    def category(self) -> str:
        return "cpu"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Identify processes consuming disproportionate CPU."""
        processes = snapshot.monitor.get("processes", {})
        by_cpu = processes.get("by_cpu", [])
        load = snapshot.monitor.get("load_average", {})

        if not by_cpu:
            return []

        findings: list[Finding] = []

        # Check load average relative to core count
        load_1min = load.get("1min", 0)
        num_cores = len(snapshot.monitor.get("frequencies", [])) or 4

        # Find processes hogging CPU (filter out our own measurement commands)
        _SELF_COMMANDS = {"ps", "top", "htop", "diagnostic"}
        hogs = [
            p for p in by_cpu
            if p.get("cpu_pct", 0) >= self._HOG_THRESHOLD_PCT
            and not any(sc in p.get("command", "").split()[0] for sc in _SELF_COMMANDS)
        ]

        for proc in hogs:
            cmd = proc.get("command", "unknown")
            cpu_pct = proc.get("cpu_pct", 0)
            pid = proc.get("pid", "?")

            # Determine if this is impactful (system is actually loaded)
            is_system_loaded = load_1min > num_cores * 0.7

            severity = Severity.CRITICAL if is_system_loaded else Severity.WARNING
            confidence = min(0.95, cpu_pct / 100 * 0.8 + (0.2 if is_system_loaded else 0))

            findings.append(Finding(
                cause=f"Process consuming {cpu_pct:.0f}% CPU: {cmd[:40]}",
                severity=severity,
                evidence=(
                    f"PID {pid} ({cmd[:60]}) using {cpu_pct:.1f}% CPU. "
                    f"System load: {load_1min:.1f} on {num_cores} cores."
                ),
                explanation=(
                    f"The process '{cmd[:30]}' is consuming an entire CPU core "
                    f"(or more). With a load average of {load_1min:.1f} on "
                    f"{num_cores} cores, this leaves less headroom for your "
                    "desktop, input handling, and other applications. "
                    "This directly causes UI lag and typing delay."
                ),
                suggestion=(
                    f"To lower its priority without stopping it: "
                    f"renice +15 -p {pid} && ionice -c 3 -p {pid}\n"
                    f"To stop it: kill {pid}"
                ),
                category=self.category,
                confidence=confidence,
            ))

        # Also flag high overall load even without a single hog
        if not hogs and load_1min > num_cores * 1.2:
            # Sum top CPU consumers
            top_3 = by_cpu[:3]
            top_summary = ", ".join(
                f"{p.get('command', '?')[:20]} ({p.get('cpu_pct', 0):.0f}%)"
                for p in top_3
            )
            findings.append(Finding(
                cause="System overloaded (high CPU load across multiple processes)",
                severity=Severity.WARNING,
                evidence=(
                    f"Load average: {load_1min:.1f} on {num_cores} cores. "
                    f"Top consumers: {top_summary}"
                ),
                explanation=(
                    f"Your system load ({load_1min:.1f}) exceeds the available "
                    f"cores ({num_cores}). Multiple processes are competing for "
                    "CPU time, which causes context-switch overhead and makes "
                    "everything feel slower."
                ),
                suggestion=(
                    "Close some applications, or reduce background tasks. "
                    "Consider running heavy tasks one at a time."
                ),
                category=self.category,
                confidence=min(0.85, load_1min / num_cores * 0.5),
            ))

        return findings
