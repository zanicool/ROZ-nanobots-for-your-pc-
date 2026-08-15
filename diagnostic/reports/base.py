"""Abstract base class for report formatters.

Formatters turn a list of Findings (plus the raw SystemSnapshot for
context) into a human- or machine-readable output string. They contain
no analysis logic — only presentation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from diagnostic.models import Finding, SystemSnapshot


class BaseFormatter(ABC):
    """Interface for all report output formatters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this format (e.g. 'terminal', 'json')."""
        ...

    @abstractmethod
    def format(
        self,
        findings: list[Finding],
        snapshot: SystemSnapshot,
        *,
        verbose: bool = False,
        comparison: dict | None = None,
    ) -> str:
        """Render findings into a formatted string.

        Args:
            findings:   Sorted list of diagnostic findings.
            snapshot:   Raw system data (for context/detail sections).
            verbose:    If True, include raw data in output.
            comparison: Optional previous run data for diff reporting.

        Returns:
            Formatted report as a single string.
        """
        ...
