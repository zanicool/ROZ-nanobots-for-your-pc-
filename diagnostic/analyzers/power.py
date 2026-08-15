"""Power profile analyzer.

Detects:
- CPU governor set to powersave when performance is needed
- TLP or power-profiles-daemon limiting performance
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer


class PowerProfileAnalyzer(BaseAnalyzer):
    """Detect power settings that limit performance.

    Laptops often default to "power-saver" governor which caps CPU
    frequency. Combined with TLP or ppd in battery mode, this can
    make the system feel sluggish even under light load.
    """

    @property
    def name(self) -> str:
        return "Power Profile"

    @property
    def category(self) -> str:
        return "power"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check CPU governor, TLP mode, and power-profiles-daemon state.

        Uses hardware.cpu.governor, hardware.cpu.energy_performance_preference
        to determine if the system is artificially power-limited.
        """
        raise NotImplementedError  # TODO: implement
