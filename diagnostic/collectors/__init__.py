"""Data collectors — gather raw system information.

Each collector is a subclass of BaseCollector and implements collect()
to return a structured dict of system data. Collectors perform no
analysis; they only gather and normalize raw information.
"""

from .benchmark import BenchmarkCollector
from .hardware import HardwareCollector
from .monitor import MonitorCollector
from .network import NetworkCollector

__all__ = [
    "BenchmarkCollector",
    "HardwareCollector",
    "MonitorCollector",
    "NetworkCollector",
]
