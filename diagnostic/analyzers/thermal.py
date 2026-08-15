"""Thermal analyzer.

Detects:
- CPU/GPU thermal throttling (temps exceeding throttle threshold)
"""

from __future__ import annotations

from diagnostic.models import Finding, Severity, SystemSnapshot

from .base import BaseAnalyzer


class ThermalAnalyzer(BaseAnalyzer):
    """Detect thermal throttling."""

    _WARNING_TEMP_C = 80
    _CRITICAL_TEMP_C = 95

    @property
    def name(self) -> str:
        return "Thermal"

    @property
    def category(self) -> str:
        return "thermal"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Compare sensor temperatures against throttle thresholds."""
        temps = snapshot.monitor.get("temperatures", [])
        if not temps:
            return []

        findings: list[Finding] = []
        max_temp = 0.0
        max_label = ""
        critical_threshold = None

        for sensor in temps:
            temp_c = sensor.get("temp_c", 0)
            label = sensor.get("label", "unknown")
            crit = sensor.get("critical_c")

            if temp_c > max_temp:
                max_temp = temp_c
                max_label = label
                critical_threshold = crit

        if max_temp >= self._CRITICAL_TEMP_C:
            findings.append(Finding(
                cause=f"Critical temperature: {max_label} at {max_temp:.0f}°C",
                severity=Severity.CRITICAL,
                evidence=(
                    f"{max_label}: {max_temp:.0f}°C "
                    f"(critical threshold: {critical_threshold or '~100'}°C). "
                    "CPU is almost certainly thermal throttling."
                ),
                explanation=(
                    f"Your CPU temperature ({max_temp:.0f}°C) is dangerously high. "
                    "The CPU is reducing its clock speed to avoid damage. This "
                    "causes severe performance drops — everything feels slow "
                    "because the CPU literally cannot run at full speed."
                ),
                suggestion=(
                    "Immediate: check for dust in vents, ensure fans are spinning. "
                    "Long-term: repaste thermal compound, use a cooling pad, "
                    "reduce workload until resolved."
                ),
                category=self.category,
                confidence=0.95,
            ))
        elif max_temp >= self._WARNING_TEMP_C:
            # Check if frequency is also reduced (confirms throttling)
            freqs = snapshot.monitor.get("frequencies", [])
            is_throttled = False
            if freqs:
                ratios = []
                for core in freqs:
                    cur = core.get("current_mhz", 0)
                    mx = core.get("max_mhz", 1)
                    if mx > 0:
                        ratios.append(cur / mx)
                if ratios and (sum(ratios) / len(ratios)) < 0.7:
                    is_throttled = True

            severity = Severity.WARNING
            confidence = 0.6
            throttle_note = ""
            if is_throttled:
                severity = Severity.CRITICAL
                confidence = 0.9
                throttle_note = " CPU frequency is reduced — throttling confirmed."

            findings.append(Finding(
                cause=f"High temperature: {max_label} at {max_temp:.0f}°C",
                severity=severity,
                evidence=(
                    f"{max_label}: {max_temp:.0f}°C.{throttle_note}"
                ),
                explanation=(
                    f"Your CPU is running hot ({max_temp:.0f}°C). "
                    "While not yet at critical levels, prolonged high temps "
                    "can trigger thermal throttling under sustained load. "
                    + ("The CPU is already slowing down to manage heat. " if is_throttled else "")
                    + "This affects performance during heavy workloads."
                ),
                suggestion=(
                    "Ensure good airflow. Check if fans are blocked or dusty. "
                    "Consider a laptop cooling stand if on a flat surface."
                ),
                category=self.category,
                confidence=confidence,
            ))

        return findings
