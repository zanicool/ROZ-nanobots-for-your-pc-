"""Process-related analyzers.

Detects:
- Background tasks eating resources (tracker-miner, snapd, updates)
- Zombie/duplicate processes accumulating
- Suspicious processes (cryptominers, malware patterns)
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer

# Well-known background resource hogs on Linux desktops
_KNOWN_BACKGROUND_HOGS = frozenset({
    "tracker-miner-fs",
    "tracker-miner-fs-3",
    "tracker-extract",
    "packagekitd",
    "snapd",
    "unattended-upgr",
    "apt-get",
    "dpkg",
    "baloo_file",
    "zeitgeist-datah",
    "fwupd",
})

# Process names that are suspicious if found using high CPU
_SUSPICIOUS_NAMES = frozenset({
    "xmrig",
    "minerd",
    "cpuminer",
    "cryptonight",
    "kworker-crypto",
    "kdevtmpfsi",
})


class BackgroundLoadAnalyzer(BaseAnalyzer):
    """Detect background tasks consuming significant resources.

    Desktop Linux systems often have hidden background services
    (file indexers, package managers, firmware updaters) that run
    at inopportune times and compete for CPU/I/O.
    """

    _HOG_CPU_THRESHOLD = 10.0  # % of one core

    @property
    def name(self) -> str:
        return "Background Load"

    @property
    def category(self) -> str:
        return "processes"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Look for known background hogs in the process list.

        Checks monitor.processes.by_cpu for any process whose name
        matches _KNOWN_BACKGROUND_HOGS and is above threshold.
        """
        raise NotImplementedError  # TODO: implement


class ZombieProcessAnalyzer(BaseAnalyzer):
    """Detect zombie and duplicate processes.

    Zombies don't use CPU but indicate broken parent processes.
    Duplicate instances of singleton services suggest something is
    respawning uncontrollably.
    """

    @property
    def name(self) -> str:
        return "Zombie/Duplicate Processes"

    @property
    def category(self) -> str:
        return "processes"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Count zombie-state processes and duplicate service instances.

        Uses monitor.processes for state information.
        """
        raise NotImplementedError  # TODO: implement


class MalwareAnalyzer(BaseAnalyzer):
    """Detect suspicious processes that may be malware.

    Cryptominers are the most common malware on Linux — they consume
    100% CPU silently. This analyzer checks for known miner process
    names and suspicious patterns (unnamed processes using high CPU).
    """

    @property
    def name(self) -> str:
        return "Suspicious Process Detection"

    @property
    def category(self) -> str:
        return "processes"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check for known malware process names and suspicious patterns.

        Compares monitor.processes against _SUSPICIOUS_NAMES and flags
        high-CPU processes with no identifiable binary path.
        """
        raise NotImplementedError  # TODO: implement
