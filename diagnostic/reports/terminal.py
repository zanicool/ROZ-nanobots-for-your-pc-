"""Terminal formatter — colored, human-readable output.

Produces output designed for direct terminal viewing with ANSI colors,
emoji severity indicators, and concise formatting.
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseFormatter

# Severity to emoji mapping
_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.WARNING: "🟡",
    Severity.INFO: "🔵",
}

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}


class TerminalFormatter(BaseFormatter):
    """Renders findings as colored terminal output."""

    @property
    def name(self) -> str:
        return "terminal"

    def format(
        self,
        findings: list[Finding],
        snapshot: SystemSnapshot,
        *,
        verbose: bool = False,
        comparison: dict | None = None,
    ) -> str:
        """Render findings for terminal display."""
        lines: list[str] = []

        # System summary
        lines.append(self._format_system_summary(snapshot))
        lines.append("")

        if not findings:
            lines.append("✅ No issues detected — your system looks healthy!")
            return "\n".join(lines)

        # Count by severity
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        lines.append(f"Found {len(findings)} issue(s): "
                     f"🔴 {critical} critical, 🟡 {warnings} warning, 🔵 {info} info")
        lines.append("─" * 60)
        lines.append("")

        # Findings
        for i, finding in enumerate(findings, 1):
            icon = _SEVERITY_ICON[finding.severity]
            label = _SEVERITY_LABEL[finding.severity]
            lines.append(f"{icon} #{i} [{label}] {finding.cause}")
            lines.append(f"   Confidence: {finding.confidence:.0%}")
            lines.append(f"   Evidence: {finding.evidence}")
            lines.append(f"   Why: {finding.explanation}")
            lines.append(f"   Fix: {finding.suggestion}")
            lines.append("")

        # Verbose: raw data dump
        if verbose:
            lines.append("─" * 60)
            lines.append("RAW DATA (--verbose)")
            lines.append("─" * 60)
            lines.append(self._format_raw_data(snapshot))

        return "\n".join(lines)

    def _format_system_summary(self, snapshot: SystemSnapshot) -> str:
        """Build a one-line system identification."""
        hw = snapshot.hardware
        cpu_model = hw.get("cpu", {}).get("model", "Unknown CPU")
        ram_gb = hw.get("memory", {}).get("total_gb", "?")
        kernel = hw.get("kernel", {}).get("release", "?")
        gpu = hw.get("gpu", {}).get("renderer") or hw.get("gpu", {}).get("device", "Unknown GPU")

        # Trim GPU string
        if gpu and len(gpu) > 50:
            gpu = gpu[:50] + "..."

        load = snapshot.monitor.get("load_average", {})
        load_str = f"{load.get('1min', '?')}/{load.get('5min', '?')}/{load.get('15min', '?')}"

        return (
            f"System: {cpu_model}, {ram_gb} GB RAM, {kernel}\n"
            f"GPU: {gpu}\n"
            f"Load: {load_str} | Uptime: {self._format_uptime(snapshot)}"
        )

    def _format_uptime(self, snapshot: SystemSnapshot) -> str:
        """Format uptime as human-readable string."""
        uptime = snapshot.monitor.get("uptime")
        if uptime is None:
            return "?"
        hours = int(uptime // 3600)
        mins = int((uptime % 3600) // 60)
        if hours > 24:
            days = hours // 24
            hours = hours % 24
            return f"{days}d {hours}h {mins}m"
        return f"{hours}h {mins}m"

    def _format_raw_data(self, snapshot: SystemSnapshot) -> str:
        """Dump key metrics for debugging."""
        lines: list[str] = []

        # Memory
        mem = snapshot.monitor.get("memory", {})
        lines.append(f"  Memory: {mem.get('available_mb', '?')} MB available / "
                     f"{mem.get('total_mb', '?')} MB total "
                     f"(swap: {mem.get('swap_used_mb', 0)} MB used)")

        # Temps
        temps = snapshot.monitor.get("temperatures", [])
        if temps:
            temp_strs = [f"{t.get('label', '?')}={t.get('temp_c', '?')}°C" for t in temps[:6]]
            lines.append(f"  Temps: {', '.join(temp_strs)}")

        # CPU frequencies
        freqs = snapshot.monitor.get("frequencies", [])
        if freqs:
            freq_strs = [f"{f.get('current_mhz', 0):.0f}" for f in freqs]
            lines.append(f"  CPU MHz: [{', '.join(freq_strs)}] (max: {freqs[0].get('max_mhz', '?')})")

        # Top processes
        procs = snapshot.monitor.get("processes", {}).get("by_cpu", [])[:5]
        if procs:
            lines.append("  Top CPU:")
            for p in procs:
                lines.append(f"    {p.get('cpu_pct', 0):5.1f}% {p.get('command', '?')[:50]}")

        return "\n".join(lines)
