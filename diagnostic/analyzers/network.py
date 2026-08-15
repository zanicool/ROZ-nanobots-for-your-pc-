"""Network latency analyzer.

Detects:
- Slow DNS resolution causing app hangs
- Packet loss to gateway
- High latency making web apps feel unresponsive
"""

from __future__ import annotations

from diagnostic.models import Finding, SystemSnapshot

from .base import BaseAnalyzer


class NetworkLatencyAnalyzer(BaseAnalyzer):
    """Detect network issues that make applications feel slow.

    Many desktop apps (browsers, Electron apps, package managers) block
    on network I/O. If DNS is slow or the connection is lossy, these
    apps appear frozen even though the CPU and disk are fine.
    """

    _WARNING_DNS_MS = 100.0
    _CRITICAL_DNS_MS = 500.0
    _WARNING_LOSS_PCT = 5.0

    @property
    def name(self) -> str:
        return "Network Latency"

    @property
    def category(self) -> str:
        return "network"

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Check DNS resolution time, gateway RTT, and packet loss.

        Uses network.dns, network.gateway for measurements.
        """
        raise NotImplementedError  # TODO: implement
