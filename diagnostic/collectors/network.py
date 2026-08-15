"""Network collector — connectivity and performance diagnostics.

Measures network health because many applications hang or feel slow
when DNS resolution is slow, packet loss is high, or the default
gateway is unreachable.
"""

from __future__ import annotations

from typing import Any

from .base import BaseCollector


class NetworkCollector(BaseCollector):
    """Collects network connectivity and performance data.

    Sources:
        - ping (gateway RTT, packet loss)
        - DNS resolution timing
        - ip link / ip addr (interface state)
        - /proc/net/dev (error counters)
        - ss / netstat (connection counts)
    """

    def collect(self) -> dict[str, Any]:
        """Measure network health indicators.

        Keys:
            interfaces:     List of interfaces with state and addresses.
            gateway:        Default gateway RTT and packet loss.
            dns:            DNS resolution time for well-known domains.
            errors:         RX/TX error and drop counts per interface.
            connections:    Summary of open connections by state.
        """
        return {
            "interfaces": self._collect_interfaces(),
            "gateway": self._collect_gateway_latency(),
            "dns": self._collect_dns_latency(),
            "errors": self._collect_interface_errors(),
            "connections": self._collect_connections(),
        }

    def _collect_interfaces(self) -> list[dict[str, Any]]:
        """List network interfaces with their state and addresses."""
        raise NotImplementedError  # TODO: implement

    def _collect_gateway_latency(self) -> dict[str, Any]:
        """Ping the default gateway and measure RTT + loss."""
        raise NotImplementedError  # TODO: implement

    def _collect_dns_latency(self) -> dict[str, Any]:
        """Time DNS resolution for common domains."""
        raise NotImplementedError  # TODO: implement

    def _collect_interface_errors(self) -> list[dict[str, Any]]:
        """Read RX/TX error and drop counters from /proc/net/dev."""
        raise NotImplementedError  # TODO: implement

    def _collect_connections(self) -> dict[str, int]:
        """Count open connections by state (ESTABLISHED, TIME_WAIT, etc)."""
        raise NotImplementedError  # TODO: implement
