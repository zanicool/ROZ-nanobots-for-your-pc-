"""System-level analyzers.

Detects:
- Outdated BIOS/kernel missing performance fixes
- Filesystem errors causing I/O retries
- Virtualization overhead (running inside a VM unknowingly)
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer


class FirmwareAnalyzer(BaseAnalyzer):
    """Detect outdated firmware or kernel.

    Old BIOS versions may lack CPU microcode fixes (Spectre mitigations
    that don't murder performance), and old kernels miss scheduler and
    driver improvements that directly affect responsiveness.
    """

    # Kernel older than this many days triggers a warning
    _KERNEL_AGE_WARNING_DAYS = 365

    @property
    def name(self) -> str:
        return "Firmware/Kernel Age"

    @property
    def category(self) -> str:
        return "system"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check kernel release date and BIOS age.

        Uses hardware.kernel.version_date and hardware.bios.date.
        """
        raise NotImplementedError  # TODO: implement


class FilesystemAnalyzer(BaseAnalyzer):
    """Detect filesystem errors causing performance issues.

    Ext4 errors, read-only remounts, or journaling issues cause the
    kernel to retry I/O operations, leading to sudden multi-second
    stalls.
    """

    @property
    def name(self) -> str:
        return "Filesystem Health"

    @property
    def category(self) -> str:
        return "system"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check dmesg for filesystem errors and read-only mounts.

        Uses hardware.storage[].filesystem_errors and mount state.
        """
        raise NotImplementedError  # TODO: implement


class VirtualizationAnalyzer(BaseAnalyzer):
    """Detect virtualization overhead.

    If the system is running inside a VM (or heavy VM workloads are
    running alongside desktop use), the hypervisor overhead and
    resource contention can cause unpredictable latency.
    """

    @property
    def name(self) -> str:
        return "Virtualization"

    @property
    def category(self) -> str:
        return "system"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Detect if running in a VM or if VMs are consuming resources.

        Checks hardware.cpu for hypervisor flag, and monitor.processes
        for qemu/vbox/vmware processes.
        """
        raise NotImplementedError  # TODO: implement
