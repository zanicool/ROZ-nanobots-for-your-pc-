"""Driver and display-link analyzers.

Detects:
- Missing or wrong GPU/hardware drivers
- External monitor via USB dock saturating bandwidth
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer


class DriverAnalyzer(BaseAnalyzer):
    """Detect missing or fallback drivers.

    Using generic kernel drivers instead of proper hardware-specific
    ones (e.g. nouveau vs nvidia, or missing firmware) can cause
    significant performance loss and missing features like HW decode.
    """

    @property
    def name(self) -> str:
        return "Driver Check"

    @property
    def category(self) -> str:
        return "drivers"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check GPU driver, firmware status, and kernel module bindings.

        Looks at hardware.gpu.driver_in_use and compares against known
        optimal drivers for the detected GPU model.
        """
        raise NotImplementedError  # TODO: implement


class DisplayLinkAnalyzer(BaseAnalyzer):
    """Detect external monitor/dock bandwidth issues.

    USB-C docks with DisplayLink compress the video stream over USB,
    which uses CPU and adds latency. Running a high-res monitor through
    a dock can also saturate USB bandwidth, affecting all USB devices.
    """

    @property
    def name(self) -> str:
        return "Display/Dock Bandwidth"

    @property
    def category(self) -> str:
        return "drivers"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check for DisplayLink devices and USB bandwidth saturation.

        Looks for evdi/displaylink kernel modules, USB3 hubs with many
        devices, and high CPU usage from display-related processes.
        """
        raise NotImplementedError  # TODO: implement
