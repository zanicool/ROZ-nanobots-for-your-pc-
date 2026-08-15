"""Storage-related analyzers.

Detects:
- Disk nearly full (performance degrades significantly past 90%)
- Failing disk with I/O errors (SMART warnings, dmesg errors)
- High I/O pressure blocking the UI
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseAnalyzer


class StorageCapacityAnalyzer(BaseAnalyzer):
    """Detect storage that is nearly full."""

    _WARNING_USAGE_PCT = 85.0
    _CRITICAL_USAGE_PCT = 95.0

    @property
    def name(self) -> str:
        return "Storage Capacity"

    @property
    def category(self) -> str:
        return "storage"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check disk usage percentages for all mounted filesystems."""
        storage = snapshot.hardware.get("storage", [])
        if not storage:
            return []

        findings: list[Finding] = []
        for disk in storage:
            used_pct = disk.get("used_pct", 0)
            mount = disk.get("mount", "?")
            device = disk.get("device", "?")

            if used_pct >= self._CRITICAL_USAGE_PCT:
                findings.append(Finding(
                    cause=f"Disk critically full: {mount} at {used_pct}%",
                    severity=Severity.CRITICAL,
                    evidence=(
                        f"{device} mounted at {mount}: {used_pct}% used, "
                        f"{disk.get('avail_mb', 0)} MB free"
                    ),
                    explanation=(
                        f"The filesystem at {mount} is almost completely full. "
                        "SSDs lose performance dramatically when nearly full "
                        "(no space for wear-leveling). Applications may fail to "
                        "write temp files, causing freezes and crashes."
                    ),
                    suggestion=(
                        f"Free up space on {mount}. Check large files: "
                        f"du -sh {mount}/* | sort -rh | head -20"
                    ),
                    category=self.category,
                    confidence=0.9,
                ))
            elif used_pct >= self._WARNING_USAGE_PCT:
                findings.append(Finding(
                    cause=f"Disk filling up: {mount} at {used_pct}%",
                    severity=Severity.WARNING,
                    evidence=(
                        f"{device} mounted at {mount}: {used_pct}% used, "
                        f"{disk.get('avail_mb', 0)} MB free"
                    ),
                    explanation=(
                        f"The filesystem at {mount} is getting full. "
                        "Performance may start to degrade, especially on SSDs."
                    ),
                    suggestion=f"Consider cleaning up {mount} before it hits 90%+.",
                    category=self.category,
                    confidence=0.6,
                ))

        return findings


class StorageHealthAnalyzer(BaseAnalyzer):
    """Detect failing or degraded storage devices."""

    @property
    def name(self) -> str:
        return "Storage Health"

    @property
    def category(self) -> str:
        return "storage"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check SMART data and dmesg for I/O errors."""
        # TODO: implement SMART checking via smartctl
        return []


class IoPressureAnalyzer(BaseAnalyzer):
    """Detect high I/O pressure stalling the system."""

    _WARNING_PSI_SOME_AVG10 = 5.0
    _CRITICAL_PSI_SOME_AVG10 = 20.0

    @property
    def name(self) -> str:
        return "I/O Pressure"

    @property
    def category(self) -> str:
        return "storage"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check /proc/pressure/io metrics for stall time."""
        io_pressure = snapshot.monitor.get("io_pressure", {})
        if not io_pressure:
            return []

        some = io_pressure.get("some", {})
        full = io_pressure.get("full", {})
        avg10 = some.get("avg10", 0)
        avg60 = some.get("avg60", 0)
        full_avg10 = full.get("avg10", 0)

        if avg10 < self._WARNING_PSI_SOME_AVG10:
            return []

        # Try to identify I/O-heavy processes
        processes = snapshot.monitor.get("processes", {}).get("by_cpu", [])
        io_suspects = [
            p.get("command", "?")[:30]
            for p in processes[:5]
            if p.get("state") == "D" or "ffmpeg" in p.get("command", "").lower()
            or "cp" in p.get("command", "").lower()
            or "rsync" in p.get("command", "").lower()
            or "fio" in p.get("command", "").lower()
            or "dd" in p.get("command", "").lower()
            or "yt-dlp" in p.get("command", "").lower()
        ]

        severity = Severity.CRITICAL if avg10 >= self._CRITICAL_PSI_SOME_AVG10 else Severity.WARNING
        confidence = min(0.95, avg10 / 30)

        suspect_text = ""
        if io_suspects:
            suspect_text = f" Likely culprits: {', '.join(io_suspects)}."

        return [Finding(
            cause="High I/O pressure — disk operations blocking the system",
            severity=severity,
            evidence=(
                f"I/O pressure: some avg10={avg10:.1f}% avg60={avg60:.1f}%, "
                f"full avg10={full_avg10:.1f}%.{suspect_text}"
            ),
            explanation=(
                "Processes are waiting for disk I/O to complete, which blocks "
                "everything else including your window manager and keyboard input. "
                "This typically happens during large file copies, video encoding "
                "to external drives, or when a process is writing heavily. "
                "Even fast CPUs can't help when the disk is the bottleneck."
            ),
            suggestion=(
                "Reduce I/O-intensive operations, or lower their priority: "
                "ionice -c 3 -p <PID> (for specific process). "
                "If writing to USB storage, that's often the bottleneck."
            ),
            category=self.category,
            confidence=confidence,
        )]
