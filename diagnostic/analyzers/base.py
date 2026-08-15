"""Abstract base class for all analyzers.

Analyzers receive a SystemSnapshot and look for specific patterns that
indicate a known cause of perceived slowness. They produce zero or more
Finding objects but never collect data themselves.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from diagnostic.models import Finding, SystemSnapshot


class BaseAnalyzer(ABC):
    """Interface that all analyzers must implement.

    Each analyzer is responsible for detecting one or more related
    causes of slowness. It inspects the SystemSnapshot and returns
    findings with severity, evidence, and suggestions.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this analyzer (e.g. 'Thermal')."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """Category tag for findings produced by this analyzer."""
        ...

    @abstractmethod
    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Inspect snapshot and return any findings.

        Args:
            snapshot: Complete system state from the collection phase.

        Returns:
            List of findings, empty list if nothing detected. Never None.
        """
        ...
